//! Encryption of the group policy blob (`encrypted_group_data`).

use base64::Engine;
use crypto_secretbox::aead::{generic_array::GenericArray, Aead};
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};
use serde_json;

use crate::core::errors::{LockNetError, Result};
use crate::core::policies::GroupData;

const GROUP_DATA_HKDF_INFO: &[u8] = b"LOCKNET_ENCRYPTED_GROUP_DATA_V1";
const NONCE_LEN: usize = 24;

/// Derive the 32-byte encryption key for [`GroupData`] from the
/// `group_data_key` delivered in `ln.encryption.group_key`.
///
/// HKDF-SHA256, salt = 32 zero bytes, info = `LOCKNET_ENCRYPTED_GROUP_DATA_V1`.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if HKDF expansion fails (should
/// never happen with 32-byte output).
pub fn derive_group_data_encryption_key(group_data_key: &[u8; 32]) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), group_data_key);
    let mut okm = [0u8; 32];
    hk.expand(GROUP_DATA_HKDF_INFO, &mut okm)
        .map_err(|e| LockNetError::InvalidResponse(format!("hkdf group_data: {e}")))?;
    Ok(okm)
}

/// Encrypt [`GroupData`] with `group_data_key` using XSalsa20-Poly1305
/// (NaCl `SecretBox`).
///
/// Output format: `base64(nonce (24 bytes) || ciphertext)`.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if JSON serialization or
/// encryption fails (should never happen with a valid key).
pub fn encrypt_group_data(data: &GroupData, group_data_key: &[u8; 32]) -> Result<String> {
    let key = derive_group_data_encryption_key(group_data_key)?;
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key));

    let plaintext = serde_json::to_vec(data)?;
    let nonce_bytes = super::random::random_bytes::<NONCE_LEN>()?;
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| LockNetError::InvalidResponse(format!("group_data encrypt: {e:?}")))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);

    Ok(base64::engine::general_purpose::STANDARD_NO_PAD.encode(&blob))
}

/// Decrypt a blob produced by [`encrypt_group_data`].
///
/// # Errors
///
/// Returns [`LockNetError::InvalidArgument`] if the base64 or JSON is
/// malformed, or if the AEAD tag fails (wrong key, tampered ciphertext, or
/// truncated blob).
pub fn decrypt_group_data(blob_b64: &str, group_data_key: &[u8; 32]) -> Result<GroupData> {
    let key = derive_group_data_encryption_key(group_data_key)?;
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key));

    let blob = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(blob_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(blob_b64))
        .map_err(|e| LockNetError::InvalidArgument(format!("group_data blob b64: {e}")))?;

    if blob.len() < NONCE_LEN {
        return Err(LockNetError::InvalidArgument(
            "group_data blob too short".into(),
        ));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ct).map_err(|_| {
        LockNetError::InvalidArgument("group_data decrypt failed (wrong key or tampered)".into())
    })?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| LockNetError::InvalidArgument(format!("group_data json: {e}")))
}
