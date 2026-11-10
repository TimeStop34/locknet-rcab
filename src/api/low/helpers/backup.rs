//! Encrypted key backup: wire methods and export/import flows.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use crypto_secretbox::aead::{generic_array::GenericArray, Aead};
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};

use crate::api::low::command::{dispatch, dispatch_unit, CmdSender};
use crate::api::low::helpers::megolm::LockNetMegolmHelper;
use crate::api::low::models::*;
use crate::core::crypto::CryptoStore;
use crate::core::errors::{LockNetError, Result};

const BACKUP_ALGORITHM: &str = "ln.encryption.backup.v1";
const BACKUP_HKDF_INFO: &[u8] = b"LOCKNET_ENCRYPTION_BACKUP_V1";

/// 32-byte secret used to encrypt the key backup.
///
/// The user must save this key out-of-band (password manager, paper, etc.).
/// **Losing it means losing access to all backed-up Megolm history.**
///
/// # Examples
///
/// ```rust
/// use locknet_rcab::RecoveryKey;
///
/// let key = RecoveryKey::generate();
/// let encoded = key.to_base64();
/// let decoded = RecoveryKey::from_base64(&encoded).unwrap();
/// assert_eq!(key.as_bytes(), decoded.as_bytes());
/// ```
#[derive(Clone)]
pub struct RecoveryKey([u8; 32]);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret bytes.
        write!(f, "RecoveryKey(<redacted 32 bytes>)")
    }
}

impl RecoveryKey {
    /// Generate a new random recovery key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom");
        Self(bytes)
    }

    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as base64 (unpadded).
    pub fn to_base64(&self) -> String {
        b64_no_pad(&self.0)
    }

    /// Decode from base64.
    ///
    /// # Errors
    ///
    /// Returns [`LockNetError::InvalidArgument`] if the input is not valid
    /// base64 or does not decode to exactly 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = decode_b64(s).map_err(|_| {
            LockNetError::InvalidArgument("recovery key: invalid base64".into())
        })?;
        if bytes.len() != 32 {
            return Err(LockNetError::InvalidArgument(format!(
                "recovery key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Result of [`LockNetBackupHelper::export`].
#[derive(Debug, Clone)]
pub struct BackupExportResult {
    /// Server-side version created for this backup.
    pub version: i32,
    /// Number of Megolm sessions uploaded.
    pub items_uploaded: u32,
}

/// Result of [`LockNetBackupHelper::import`].
#[derive(Debug, Clone)]
pub struct BackupImportResult {
    /// Backup version that was imported.
    pub version: i32,
    /// Number of Megolm sessions restored into the local store.
    pub sessions_imported: u32,
}

/// Wraps the `/api/v1/backup` WebSocket methods and implements the
/// encrypt/decrypt flow.
///
/// Obtained via [`crate::LockNetLowAgent::backup`].
pub struct LockNetBackupHelper {
    pub(crate) cmd_tx: CmdSender,
    pub(crate) store: Arc<dyn CryptoStore>,
    pub(crate) megolm: Arc<LockNetMegolmHelper>,
}

impl LockNetBackupHelper {
    /// List existing backup versions for the current user.
    pub async fn versions(&self) -> Result<Vec<BackupVersion>> {
        #[derive(serde::Deserialize)]
        struct W {
            versions: Vec<BackupVersion>,
        }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "backup_versions", "data": {} })).await?;
        Ok(w.versions)
    }

    /// Create a new (empty) backup version.
    ///
    /// `auth_data` must include a `public_key` field derived from the
    /// recovery key (see [`Self::export`]). Returns the new version number.
    pub async fn new_version(
        &self,
        algorithm: impl Into<String>,
        auth_data: serde_json::Value,
    ) -> Result<i32> {
        #[derive(serde::Deserialize)]
        struct W {
            version: i32,
        }
        let w: W = dispatch(
            &self.cmd_tx,
            json!({ "type": "backup_new", "data": { "algorithm": algorithm.into(), "auth_data": auth_data } }),
        )
        .await?;
        Ok(w.version)
    }

    /// Upload encrypted backup items.
    ///
    /// `items` maps `"<chat_id>:<megolm_session_id>"` to an opaque encrypted
    /// blob. Existing items with the same ID are overwritten.
    pub async fn put(
        &self,
        version: i32,
        items: HashMap<String, serde_json::Value>,
    ) -> Result<u32> {
        #[derive(serde::Deserialize)]
        struct W {
            count: u32,
        }
        let w: W = dispatch(
            &self.cmd_tx,
            json!({ "type": "backup_put", "data": { "version": version, "items": items } }),
        )
        .await?;
        Ok(w.count)
    }

    /// Fetch a backup version with all its items.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `backup_version_not_found`.
    pub async fn get(&self, version: i32) -> Result<BackupVersionData> {
        dispatch(&self.cmd_tx, json!({ "type": "backup_get", "data": { "version": version } })).await
    }

    /// Delete a backup version and all its items.
    pub async fn delete(&self, version: i32) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "backup_delete", "data": { "version": version } })).await
    }

    /// Export every known Megolm inbound session to a new backup version.
    ///
    /// Each session is encrypted with XSalsa20-Poly1305 using a key derived
    /// from `recovery_key`. The `auth_data.public_key` field stores a SHA-256
    /// fingerprint of the derived key, allowing import to detect wrong
    /// recovery keys before attempting decryption.
    ///
    /// Returns the new version number and the count of uploaded sessions.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Timeout`] on transport timeout.
    /// - [`crate::LockNetError::InvalidResponse`] on malformed server response.
    pub async fn export(&self, recovery_key: &RecoveryKey) -> Result<BackupExportResult> {
        let secret = derive_backup_secret(recovery_key)?;
        let public_key = b64_no_pad(&sha256_bytes(&secret));

        let auth_data = json!({
            "algorithm": BACKUP_ALGORITHM,
            "public_key": public_key,
        });

        let version = self.new_version(BACKUP_ALGORITHM, auth_data).await?;

        let mut items: HashMap<String, Value> = HashMap::new();
        for (chat_id, megolm_session_id) in self.store.megolm_inbound_all().await {
            let session = match self.store.megolm_inbound(chat_id, &megolm_session_id).await {
                Some(s) => s,
                None => continue,
            };

            let (session_key_b64, first_known_index) = {
                let mut s = session.lock().await;
                let first = s.first_known_index();
                match s.export_at(first) {
                    Some(key) => (key.to_base64(), first),
                    None => continue,
                }
            };

            let plaintext = json!({
                "session_key": session_key_b64,
                "first_known_index": first_known_index,
            })
            .to_string();

            let encrypted = encrypt_item(&secret, plaintext.as_bytes())?;
            let item_id = format!("{}:{}", chat_id, megolm_session_id);
            items.insert(item_id, encrypted);
        }

        let uploaded = self.put(version, items).await?;
        Ok(BackupExportResult { version, items_uploaded: uploaded })
    }

    /// Import all Megolm sessions from a backup version.
    ///
    /// Verifies that `recovery_key` matches the fingerprint stored in
    /// `auth_data.public_key` before decrypting any item.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `backup_version_not_found`.
    /// - [`LockNetError::InvalidArgument`] if `recovery_key` does not match
    ///   the backup's `auth_data.public_key`.
    pub async fn import(
        &self,
        version: i32,
        recovery_key: &RecoveryKey,
    ) -> Result<BackupImportResult> {
        let secret = derive_backup_secret(recovery_key)?;
        let data = self.get(version).await?;

        let expected_pk = b64_no_pad(&sha256_bytes(&secret));
        let claimed_pk = data
            .auth_data
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                LockNetError::InvalidResponse("backup auth_data.public_key missing".into())
            })?;
        if normalize_b64(claimed_pk) != expected_pk {
            return Err(LockNetError::InvalidArgument(
                "recovery key does not match backup auth_data".into(),
            ));
        }

        let mut imported = 0u32;
        for (item_id, enc) in &data.items {
            let (chat_id_str, megolm_session_id) = item_id.split_once(':').ok_or_else(|| {
                LockNetError::InvalidResponse(format!("bad item_id: {item_id}"))
            })?;
            let chat_id: i64 = chat_id_str.parse().map_err(|_| {
                LockNetError::InvalidResponse(format!("bad chat_id in item_id: {chat_id_str}"))
            })?;

            let plaintext = decrypt_item(&secret, enc)?;
            let parsed: Value = serde_json::from_slice(&plaintext)?;
            let session_key = parsed
                .get("session_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    LockNetError::InvalidResponse("backup item missing session_key".into())
                })?;

            self.megolm
                .import(
                    chat_id,
                    megolm_session_id.to_string(),
                    session_key.to_string(),
                )
                .await?;
            imported += 1;
        }

        Ok(BackupImportResult { version, sessions_imported: imported })
    }
}

// ---- crypto helpers ----

fn derive_backup_secret(rk: &RecoveryKey) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), rk.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(BACKUP_HKDF_INFO, &mut okm)
        .map_err(|e| LockNetError::InvalidResponse(format!("hkdf backup_secret: {e}")))?;
    Ok(okm)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encrypt_item(secret: &[u8; 32], plaintext: &[u8]) -> Result<Value> {
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(secret));
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).expect("getrandom");
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LockNetError::InvalidResponse(format!("secretbox encrypt: {e:?}")))?;

    Ok(json!({
        "nonce": b64_no_pad(&nonce_bytes),
        "ciphertext": b64_no_pad(&ciphertext),
    }))
}

fn decrypt_item(secret: &[u8; 32], enc: &Value) -> Result<Vec<u8>> {
    let nonce_b64 = enc
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LockNetError::InvalidResponse("item nonce missing".into()))?;
    let ct_b64 = enc
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LockNetError::InvalidResponse("item ciphertext missing".into()))?;

    let nonce_bytes = decode_b64(nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(LockNetError::InvalidResponse(format!(
            "item nonce must be 24 bytes, got {}",
            nonce_bytes.len()
        )));
    }
    let ciphertext = decode_b64(ct_b64)?;

    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(secret));
    let nonce = GenericArray::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| LockNetError::InvalidArgument("backup item decrypt failed".into()))
}

fn b64_no_pad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| LockNetError::InvalidResponse(format!("b64: {e}")))
}

fn normalize_b64(s: &str) -> String {
    s.trim_end_matches('=').to_string()
}