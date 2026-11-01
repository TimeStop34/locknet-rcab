use std::sync::Arc;
use serde_json::json;
use tokio::sync::{mpsc, Mutex};
use crate::api::low::command::Cmd;
use crate::api::low::models::Encrypted;
use crate::core::crypto::megolm::{create_outbound, decrypt_inbound, encrypt, import_inbound, session_id, MEGOLM_ALGORITHM};
use crate::core::crypto::CryptoStore;
use crate::core::errors::{LockNetError, Result};
use crate::api::low::helpers::olm::LockNetOlmHelper;

pub struct MegolmSessionInfo { pub chat_id: i64, pub megolm_session_id: String, pub session_key: String }

pub struct LockNetMegolmHelper {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
    pub(crate) store: Arc<dyn CryptoStore>,
    pub(crate) olm: Arc<LockNetOlmHelper>,
    pub(crate) session_id: i64,
}

impl LockNetMegolmHelper {
    pub async fn create(&self, chat_id: i64) -> Result<MegolmSessionInfo> {
        let (session, key) = create_outbound();
        let sid = session_id(&session);
        self.store.megolm_outbound_put(chat_id, Arc::new(Mutex::new(session)), key.clone());
        let inbound = import_inbound(&key)?;
        self.store.megolm_inbound_put(chat_id, sid.clone(), Arc::new(Mutex::new(inbound)));
        Ok(MegolmSessionInfo { chat_id, megolm_session_id: sid, session_key: key })
    }

    pub async fn ensure_session(&self, chat_id: i64) -> Result<MegolmSessionInfo> {
        if let (Some(session), Some(key)) = (self.store.megolm_outbound(chat_id), self.store.megolm_outbound_key(chat_id)) {
            let sid = { let s = session.lock().await; session_id(&s) };
            return Ok(MegolmSessionInfo { chat_id, megolm_session_id: sid, session_key: key });
        }
        self.create(chat_id).await
    }

    pub async fn rotate(&self, chat_id: i64) -> Result<MegolmSessionInfo> { self.create(chat_id).await }

    pub async fn encrypt(&self, chat_id: i64, plaintext: impl Into<String>) -> Result<Encrypted> {
        let session = self.store.megolm_outbound(chat_id)
            .ok_or_else(|| LockNetError::InvalidResponse("no megolm session for chat".into()))?;
        let (sid, ct) = {
            let mut s = session.lock().await;
            let sid = session_id(&s);
            let ct = encrypt(&mut s, &plaintext.into());
            (sid, ct)
        };
        Ok(Encrypted { algorithm: MEGOLM_ALGORITHM.into(), sender_key: "WILL_BE_OVERWRITTEN".into(), sender_session_id: self.session_id, megolm_session_id: sid, ciphertext: ct })
    }

    pub async fn decrypt(&self, chat_id: i64, encrypted: &Encrypted) -> Result<Option<String>> {
        if encrypted.algorithm != MEGOLM_ALGORITHM { return Ok(None); }
        let session = match self.store.megolm_inbound(chat_id, &encrypted.megolm_session_id) { Some(s) => s, None => return Ok(None) };
        let mut s = session.lock().await;
        match decrypt_inbound(&mut s, &encrypted.ciphertext) { Ok(pt) => Ok(Some(pt)), Err(_) => Ok(None) }
    }

    pub async fn import(&self, chat_id: i64, megolm_session_id: String, session_key: String) -> Result<()> {
        let session = import_inbound(&session_key)?;
        self.store.megolm_inbound_put(chat_id, megolm_session_id, Arc::new(Mutex::new(session)));
        Ok(())
    }

    pub async fn share_group_key(&self, chat_id: i64, to_user: i64, to_session: i64) -> Result<()> {
        let info = self.ensure_session(chat_id).await?;
        let content = json!({
            "type": "ln.encryption.group_key",
            "content": { "algorithm": MEGOLM_ALGORITHM, "chat_id": chat_id, "megolm_session_id": info.megolm_session_id, "session_key": info.session_key }
        });
        self.olm.send(to_user, to_session, content.to_string()).wait().await
    }

    pub async fn decrypt_group_key(&self, plaintext: &str) -> Result<bool> {
        let val: serde_json::Value = match serde_json::from_str(plaintext) { Ok(v) => v, Err(_) => return Ok(false) };
        if val.get("type").and_then(|v| v.as_str()) != Some("ln.encryption.group_key") { return Ok(false); }
        let content = val.get("content").ok_or_else(|| LockNetError::InvalidResponse("no content".into()))?;
        let chat_id = content.get("chat_id").and_then(|v| v.as_i64()).ok_or_else(|| LockNetError::InvalidResponse("no chat_id".into()))?;
        let megolm_session_id = content.get("megolm_session_id").and_then(|v| v.as_str()).ok_or_else(|| LockNetError::InvalidResponse("no megolm_session_id".into()))?.to_string();
        let session_key = content.get("session_key").and_then(|v| v.as_str()).ok_or_else(|| LockNetError::InvalidResponse("no session_key".into()))?.to_string();
        self.import(chat_id, megolm_session_id, session_key).await?;
        Ok(true)
    }
}