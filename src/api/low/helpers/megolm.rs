//! Megolm (group) sessions, rotation, and `group_key` payload handling.

use crate::api::low::command::CmdSender;
use crate::api::low::helpers::olm::LockNetOlmHelper;
use crate::api::low::models::Encrypted;
use crate::core::crypto::megolm::{
    create_outbound, decrypt_inbound, encrypt, import_inbound, session_id, MEGOLM_ALGORITHM,
};
use crate::core::crypto::CryptoStore;
use crate::core::errors::{LockNetError, Result};
use crate::core::policies::MegolmOutboundMeta;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Snapshot of the current outbound Megolm session for a chat.
pub struct MegolmSessionInfo {
    /// Chat ID.
    pub chat_id: i64,
    /// Megolm session ID.
    pub megolm_session_id: String,
    /// Base64-encoded session key, for sharing with other members.
    pub session_key: String,
}

/// Wraps Megolm session lifecycle and encryption.
///
/// Obtained via [`crate::LockNetLowAgent::megolm`]. Most callers use
/// [`crate::Chat`] instead, which adds fan-out and policy handling.
pub struct LockNetMegolmHelper {
    #[allow(dead_code)]
    pub(crate) cmd_tx: CmdSender,
    pub(crate) store: Arc<dyn CryptoStore>,
    pub(crate) olm: Arc<LockNetOlmHelper>,
    pub(crate) session_id: i64,
    pub(crate) default_history_visibility: crate::core::policies::HistoryVisibility,
    pub(crate) default_megolm_rotation_visibility: crate::core::policies::MegolmRotationVisibility,
    pub(crate) rotation_message_count: u64,
    pub(crate) rotation_ttl_secs: u64,
}

impl LockNetMegolmHelper {
    /// Create a fresh outbound session for `chat_id`.
    ///
    /// If a session already exists, the new one replaces it and its
    /// `GroupData.version` is incremented. A fresh `group_data_key` is
    /// generated as well, so previously shared peers cannot read the new
    /// policy until the new `group_key` is distributed.
    ///
    /// The inbound half is also stored locally, so the sender can decrypt
    /// their own messages.
    ///
    /// # Errors
    ///
    /// Returns [`LockNetError::InvalidResponse`] on internal encryption errors
    /// (should never happen with valid keys).
    pub async fn create(&self, chat_id: i64) -> Result<MegolmSessionInfo> {
        use crate::core::crypto::group_data::encrypt_group_data;
        use crate::core::policies::{GroupData, GroupDataState};

        let (session, key) = create_outbound();
        let sid = session_id(&session);

        let (new_version, history_vis, megolm_vis) =
            match self.store.group_data_state(chat_id).await {
                Some(prev) => (
                    prev.data.version.saturating_add(1),
                    prev.data.history_visibility,
                    prev.data.megolm_rotation_visibility,
                ),
                None => (
                    1,
                    self.default_history_visibility,
                    self.default_megolm_rotation_visibility,
                ),
            };

        let gd_key = crate::core::crypto::random::random_bytes::<32>()?;

        let gd_data = GroupData {
            version: new_version,
            history_visibility: history_vis,
            megolm_rotation_visibility: megolm_vis,
            rotated_at: chrono::Utc::now(),
        };
        let gd_blob = encrypt_group_data(&gd_data, &gd_key)?;

        self.store
            .group_data_state_put(
                chat_id,
                GroupDataState {
                    key: gd_key,
                    data: gd_data,
                    blob: gd_blob,
                },
            )
            .await;

        self.store
            .megolm_outbound_put(chat_id, Arc::new(Mutex::new(session)), key.clone())
            .await;
        let inbound = import_inbound(&key)?;
        self.store
            .megolm_inbound_put(chat_id, sid.clone(), Arc::new(Mutex::new(inbound)))
            .await;

        self.store
            .megolm_outbound_meta_put(
                chat_id,
                MegolmOutboundMeta {
                    session_id: sid.clone(),
                    created_at: chrono::Utc::now(),
                    messages_sent: 0,
                },
            )
            .await;

        Ok(MegolmSessionInfo {
            chat_id,
            megolm_session_id: sid,
            session_key: key,
        })
    }

    /// Return the current outbound session, creating one if needed, and
    /// rotate it if the configured message-count or TTL threshold is reached.
    ///
    /// Returns `(info, was_rotated)`. `was_rotated = true` means the caller
    /// must fan out the new key (see [`crate::Chat::send`]).
    pub async fn ensure_session(&self, chat_id: i64) -> Result<(MegolmSessionInfo, bool)> {
        let existing = self.store.megolm_outbound(chat_id).await;
        let existing_key = self.store.megolm_outbound_key(chat_id).await;
        let meta = self.store.megolm_outbound_meta(chat_id).await;

        if let (Some(session), Some(key), Some(meta)) = (existing, existing_key, meta) {
            let sid = {
                let s = session.lock().await;
                session_id(&s)
            };

            let now = chrono::Utc::now();
            let age = now.signed_duration_since(meta.created_at);
            let ttl_expired =
                self.rotation_ttl_secs > 0 && age.num_seconds() as u64 >= self.rotation_ttl_secs;
            let count_exceeded = self.rotation_message_count > 0
                && meta.messages_sent >= self.rotation_message_count;

            if ttl_expired || count_exceeded {
                tracing::info!(
                    chat_id,
                    age_secs = age.num_seconds(),
                    messages_sent = meta.messages_sent,
                    ttl_expired,
                    count_exceeded,
                    "megolm auto-rotation triggered"
                );
                let info = self.create(chat_id).await?;
                return Ok((info, true));
            }

            return Ok((
                MegolmSessionInfo {
                    chat_id,
                    megolm_session_id: sid,
                    session_key: key,
                },
                false,
            ));
        }

        let info = self.create(chat_id).await?;
        Ok((info, true))
    }

    /// Force a rotation regardless of thresholds.
    pub async fn rotate(&self, chat_id: i64) -> Result<MegolmSessionInfo> {
        self.create(chat_id).await
    }

    /// Encrypt `plaintext` with the current outbound session for `chat_id`.
    ///
    /// Increments the message counter used by auto-rotation. If the counter
    /// crosses the threshold, the next call to [`Self::ensure_session`] will
    /// rotate.
    pub async fn encrypt(&self, chat_id: i64, plaintext: impl Into<String>) -> Result<Encrypted> {
        let session =
            self.store.megolm_outbound(chat_id).await.ok_or_else(|| {
                LockNetError::InvalidResponse("no megolm session for chat".into())
            })?;
        let (sid, ct) = {
            let mut s = session.lock().await;
            let sid = session_id(&s);
            let ct = encrypt(&mut s, &plaintext.into());
            (sid, ct)
        };

        if let Some(mut meta) = self.store.megolm_outbound_meta(chat_id).await {
            meta.messages_sent = meta.messages_sent.saturating_add(1);
            self.store.megolm_outbound_meta_put(chat_id, meta).await;
        }

        Ok(Encrypted {
            algorithm: MEGOLM_ALGORITHM.into(),
            sender_key: "WILL_BE_OVERWRITTEN".into(),
            sender_session_id: self.session_id,
            megolm_session_id: sid,
            ciphertext: ct,
        })
    }

    /// Decrypt a Megolm ciphertext with a known inbound session.
    ///
    /// Returns `Ok(None)` if no inbound session is known for
    /// `encrypted.megolm_session_id`, or if `encrypted.algorithm` is not
    /// [`MEGOLM_ALGORITHM`].
    pub async fn decrypt(&self, chat_id: i64, encrypted: &Encrypted) -> Result<Option<String>> {
        if encrypted.algorithm != MEGOLM_ALGORITHM {
            return Ok(None);
        }
        let session = match self
            .store
            .megolm_inbound(chat_id, &encrypted.megolm_session_id)
            .await
        {
            Some(s) => s,
            None => return Ok(None),
        };
        let mut s = session.lock().await;
        match decrypt_inbound(&mut s, &encrypted.ciphertext) {
            Ok(pt) => Ok(Some(pt)),
            Err(_) => Ok(None),
        }
    }

    /// Import an inbound session from a base64-encoded key.
    ///
    /// # Errors
    ///
    /// Returns [`LockNetError::InvalidResponse`] if the key is malformed.
    pub async fn import(
        &self,
        chat_id: i64,
        megolm_session_id: String,
        session_key: String,
    ) -> Result<()> {
        let session = import_inbound(&session_key)?;
        self.store
            .megolm_inbound_put(chat_id, megolm_session_id, Arc::new(Mutex::new(session)))
            .await;
        Ok(())
    }

    /// Share the current `group_key` with a specific peer session via Olm.
    ///
    /// Loads (or creates) the outbound session, then sends an
    /// `ln.encryption.group_key` payload with the key and the current
    /// `encrypted_group_data` blob.
    pub async fn share_group_key(&self, chat_id: i64, to_user: i64, to_session: i64) -> Result<()> {
        let (info, _) = self.ensure_session(chat_id).await?;
        self.share_group_key_with_session_key(
            chat_id,
            to_user,
            to_session,
            info.megolm_session_id,
            info.session_key,
        )
        .await
    }

    /// Share a **specific** Megolm session (and its policy blob) via Olm.
    ///
    /// Used when the caller already has the info and does not want
    /// [`Self::ensure_session`] to rotate the session under their feet.
    pub async fn share_group_key_with_session_key(
        &self,
        chat_id: i64,
        to_user: i64,
        to_session: i64,
        megolm_session_id: String,
        session_key: String,
    ) -> Result<()> {
        let content =
            build_group_key_content(&self.store, chat_id, megolm_session_id, session_key, None)
                .await;
        let pt = json!({
            "type": "ln.encryption.group_key",
            "content": content,
        })
        .to_string();
        self.olm.send(to_user, to_session, pt).wait().await
    }

    /// Parse and apply an `ln.encryption.group_key` payload.
    ///
    /// - Imports the Megolm inbound session.
    /// - Decrypts and caches the `group_data` policy blob (with anti-replay
    ///   by version).
    ///
    /// Returns `Ok(true)` if the payload was a valid `group_key`,
    /// `Ok(false)` for other message types.
    pub async fn decrypt_group_key(&self, plaintext: &str) -> Result<bool> {
        let val: serde_json::Value = match serde_json::from_str(plaintext) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if val.get("type").and_then(|v| v.as_str()) != Some("ln.encryption.group_key") {
            return Ok(false);
        }
        let content = val
            .get("content")
            .ok_or_else(|| LockNetError::InvalidResponse("no content".into()))?;
        let chat_id = content
            .get("chat_id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| LockNetError::InvalidResponse("no chat_id".into()))?;
        let megolm_session_id = content
            .get("megolm_session_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LockNetError::InvalidResponse("no megolm_session_id".into()))?
            .to_string();
        let session_key = content
            .get("session_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LockNetError::InvalidResponse("no session_key".into()))?
            .to_string();

        self.import(chat_id, megolm_session_id, session_key).await?;
        apply_group_data_to_store(&self.store, chat_id, content).await?;

        Ok(true)
    }
}

// ---- shared helpers ----

/// Build the `content` object of an `ln.encryption.group_key` payload.
///
/// Includes the Megolm session key and, if available, the current
/// `group_data` blob plus its key.
pub(crate) async fn build_group_key_content(
    store: &Arc<dyn CryptoStore>,
    chat_id: i64,
    megolm_session_id: String,
    session_key: String,
    transaction_id: Option<String>,
) -> serde_json::Value {
    let mut content = json!({
        "algorithm": MEGOLM_ALGORITHM,
        "chat_id": chat_id,
        "megolm_session_id": megolm_session_id,
        "session_key": session_key,
    });

    if let Some(txid) = transaction_id {
        if let Some(obj) = content.as_object_mut() {
            obj.insert("transaction_id".into(), serde_json::Value::String(txid));
        }
    }

    if let Some(state) = store.group_data_state(chat_id).await {
        use base64::Engine;
        let key_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(state.key);
        if let Some(obj) = content.as_object_mut() {
            obj.insert("group_data".into(), serde_json::Value::String(state.blob));
            obj.insert("group_data_key".into(), serde_json::Value::String(key_b64));
        }
    }

    content
}

/// Decrypt and persist a `group_data` blob from a `group_key` content object.
///
/// Rejects blobs with a version lower than the locally cached one.
pub(crate) async fn apply_group_data_to_store(
    store: &Arc<dyn CryptoStore>,
    chat_id: i64,
    content: &serde_json::Value,
) -> Result<()> {
    use crate::core::crypto::group_data::decrypt_group_data;

    let Some(blob) = content.get("group_data").and_then(|v| v.as_str()) else {
        return Ok(());
    };
    let Some(key_b64) = content.get("group_data_key").and_then(|v| v.as_str()) else {
        return Ok(());
    };

    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(key_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key_b64))
        .map_err(|e| LockNetError::InvalidResponse(format!("group_data_key b64: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(LockNetError::InvalidResponse(format!(
            "group_data_key must be 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let data = match decrypt_group_data(blob, &key) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(chat_id, ?e, "group_data decrypt failed, ignoring");
            return Ok(());
        }
    };

    let existing = store.group_data_state(chat_id).await;
    if let Some(prev) = &existing {
        if data.version < prev.data.version {
            tracing::warn!(
                chat_id,
                incoming = data.version,
                current = prev.data.version,
                "group_data version downgrade, ignoring"
            );
            return Ok(());
        }
    }

    store
        .group_data_state_put(
            chat_id,
            crate::core::policies::GroupDataState {
                key,
                data,
                blob: blob.to_string(),
            },
        )
        .await;

    Ok(())
}
