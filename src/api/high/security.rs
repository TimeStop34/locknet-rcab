use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::helpers::verification::sas::{SasFlow, SasStep};
use crate::api::low::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use crate::core::crypto::signature::{sign_b64, verify_b64, CrossSigningKeysPrivate};
use crate::core::errors::{LockNetError, Result};
use super::event::HighEvent;
use super::models::User;
use super::state::ClientState;

pub struct SecurityHelper {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) state: Arc<RwLock<ClientState>>,
    pub(crate) event_tx: broadcast::Sender<HighEvent>,
}

impl SecurityHelper {
    pub async fn is_user_verified(&self, user_id: i64) -> bool {
        { let state = self.state.read().await; if state.verified_users.contains(&user_id) { return true; } }
        let query = match self.low.crypto().query_cross_signing_keys(vec![user_id]).await { Ok(q) => q, Err(_) => return false };
        let entry = match query.get(&user_id) { Some(e) => e, None => return false };
        let our_id = self.low.user_id();
        let our_sig = match entry.master_key.signatures.get(&our_id).and_then(|m| m.get("user_signing")) { Some(s) => s.clone(), None => return false };
        let our_keys = match self.low.store().cross_signing_keys() { Some(k) => k, None => return false };
        let target_msk = entry.master_key.key.clone();
        verify_b64(&our_keys.usk.public_key().to_base64(), &target_msk, &our_sig).is_ok()
    }

    pub async fn is_session_verified(&self, user_id: i64, session_id: i64) -> bool {
        { let state = self.state.read().await; if state.verified_sessions.contains(&session_id) { return true; } }
        let query = match self.low.crypto().query_cross_signing_keys(vec![user_id]).await { Ok(q) => q, Err(_) => return false };
        let entry = match query.get(&user_id) { Some(e) => e, None => return false };
        let ssk_pub = match entry.self_signing_key.as_ref() { Some(k) => k.key.clone(), None => return false };
        let device = match entry.devices.get(&session_id) { Some(d) => d, None => return false };
        let sig = match device.signatures.get(&user_id).and_then(|m| m.get("self_signing")) { Some(s) => s.clone(), None => return false };
        let ed = match &device.ed25519_key { s if s.is_empty() => return false, s => s.clone() };
        verify_b64(&ssk_pub, &ed, &sig).is_ok()
    }

    pub async fn user_info(&self, user_id: i64) -> Result<User> {
        let state = self.state.read().await;
        Ok(state.users.get(&user_id).cloned().unwrap_or_else(|| User::unknown(user_id)))
    }

    pub async fn setup_cross_signing(&self) -> Result<()> {
        if self.low.store().cross_signing_keys().is_some() { return Err(LockNetError::AlreadyConnected); }
        let keys = CrossSigningKeysPrivate::generate();
        let user_id = self.low.user_id();
        let msk_pub = keys.msk_pub_b64();
        let ssk_pub = keys.ssk_pub_b64();
        let usk_pub = keys.usk_pub_b64();
        let ssk_sig = sign_b64(&keys.msk, &ssk_pub)?;
        let usk_sig = sign_b64(&keys.msk, &usk_pub)?;
        let mut ssk_sigs = std::collections::HashMap::new();
        let mut inner = std::collections::HashMap::new();
        inner.insert("master".to_string(), ssk_sig);
        ssk_sigs.insert(user_id.to_string(), inner);
        let mut usk_sigs = std::collections::HashMap::new();
        let mut inner2 = std::collections::HashMap::new();
        inner2.insert("master".to_string(), usk_sig);
        usk_sigs.insert(user_id.to_string(), inner2);
        let payload = CrossSigningKeys {
            master_key: CrossSigningKey { key: msk_pub, signatures: std::collections::HashMap::new() },
            self_signing_key: CrossSigningKey { key: ssk_pub.clone(), signatures: ssk_sigs },
            user_signing_key: CrossSigningKey { key: usk_pub, signatures: usk_sigs },
        };
        self.low.crypto().upload_cross_signing_keys(payload).await?;
        let ed_b64 = { let account = self.low.store().account(); let acc = account.lock().await; acc.ed25519_public_b64() };
        let device_sig = sign_b64(&keys.ssk, &ed_b64)?;
        let mut device_sigs = std::collections::HashMap::new();
        device_sigs.insert(self.low.session_id(), device_sig);
        self.low.crypto().upload_signatures(Signatures { user_signatures: std::collections::HashMap::new(), device_signatures: device_sigs }).await?;
        self.low.store().cross_signing_keys_put(Arc::new(keys));
        Ok(())
    }

    pub async fn reset_cross_signing(&self, password: impl Into<String>) -> Result<()> {
        self.low.crypto().reset_cross_signing_keys(password).await?;
        self.low.store().cross_signing_keys_clear();
        let mut state = self.state.write().await;
        state.verified_users.clear();
        state.verified_sessions.clear();
        Ok(())
    }

    pub async fn sas_start(&self, user_id: i64, session_id: i64) -> Result<Arc<tokio::sync::Mutex<SasFlow>>> {
        let keys = self.low.store().cross_signing_keys().ok_or_else(|| LockNetError::InvalidResponse("setup_cross_signing required".into()))?;
        let ed_b64 = { let account = self.low.store().account(); let acc = account.lock().await; acc.ed25519_public_b64() };
        let flow = self.low.verification().sas_start(user_id, session_id, keys.msk_pub_b64(), ed_b64).await?;
        let txid = flow.transaction_id().to_string();
        let handle = Arc::new(tokio::sync::Mutex::new(flow));
        { let mut st = self.state.write().await; st.active_sas.insert(txid, handle.clone()); }
        Ok(handle)
    }

    pub async fn sas_accept(&self, transaction_id: String, user_id: i64, session_id: i64) -> Result<Arc<tokio::sync::Mutex<SasFlow>>> {
        let keys = self.low.store().cross_signing_keys().ok_or_else(|| LockNetError::InvalidResponse("setup_cross_signing required".into()))?;
        let ed_b64 = { let account = self.low.store().account(); let acc = account.lock().await; acc.ed25519_public_b64() };
        let flow = self.low.verification().sas_start_responder(user_id, session_id, transaction_id.clone(), keys.msk_pub_b64(), ed_b64).await?;
        let handle = Arc::new(tokio::sync::Mutex::new(flow));
        { let mut st = self.state.write().await; st.active_sas.insert(transaction_id, handle.clone()); }
        Ok(handle)
    }

    pub async fn sas_next(&self, transaction_id: &str) -> Result<SasStep> {
        let handle = { let st = self.state.read().await; st.active_sas.get(transaction_id).cloned() }.ok_or_else(|| LockNetError::InvalidResponse("sas flow not found".into()))?;
        let mut guard = handle.lock().await;
        guard.next().await
    }

    pub async fn sas_confirm(&self, transaction_id: &str, accept: bool) -> Result<()> {
        let handle = { let st = self.state.read().await; st.active_sas.get(transaction_id).cloned() }.ok_or_else(|| LockNetError::InvalidResponse("sas flow not found".into()))?;
        let mut guard = handle.lock().await;
        guard.confirm_emoji(accept).await
    }

    pub async fn sas_remove(&self, transaction_id: &str) {
        let mut st = self.state.write().await;
        st.active_sas.remove(transaction_id);
    }
}