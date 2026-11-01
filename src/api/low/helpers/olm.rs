use std::sync::Arc;
use serde_json::json;
use tokio::sync::mpsc;
use crate::api::low::command::{dispatch, Cmd};
use crate::api::low::models::{Otk, QueryKeysResult, ToDevicePayload};
use crate::core::crypto::olm::{
    create_inbound, create_outbound, curve_from_b64, decrypt_olm, encrypt_olm, parse_prekey, EncryptedOlm, OlmSessionEntry, OLM_ALGORITHM,
};
use crate::core::crypto::CryptoStore;
use crate::core::errors::{LockNetError, Result};
use crate::core::flow::SimpleFlow;

pub struct LockNetOlmHelper { pub(crate) cmd_tx: mpsc::Sender<Cmd>, pub(crate) store: Arc<dyn CryptoStore> }

impl LockNetOlmHelper {
    pub fn send(&self, to_user_id: i64, to_session_id: i64, plaintext: impl Into<String> + Send + 'static) -> SimpleFlow<()> {
        let cmd_tx = self.cmd_tx.clone();
        let store = self.store.clone();
        let plaintext = plaintext.into();
        SimpleFlow::spawn(async move { send_impl(cmd_tx, store, to_user_id, to_session_id, plaintext).await })
    }
    pub fn decrypt(&self, payload: ToDevicePayload) -> SimpleFlow<Option<String>> {
        let store = self.store.clone();
        SimpleFlow::spawn(async move { decrypt_impl(store, payload).await })
    }
}

async fn send_impl(cmd_tx: mpsc::Sender<Cmd>, store: Arc<dyn CryptoStore>, to_user_id: i64, to_session_id: i64, plaintext: String) -> Result<()> {
    if let Some(entry) = store.olm_sessions(to_session_id).into_iter().last() {
        let encrypted = { let mut session = entry.session.lock().await; encrypt_olm(&mut session, &plaintext) };
        send_to_device(&cmd_tx, to_user_id, to_session_id, &entry.their_curve25519, &encrypted).await?;
        return Ok(());
    }

    let keys: QueryKeysResult = dispatch(&cmd_tx, json!({ "type": "query_keys", "data": { "user_ids": [to_user_id] } })).await?;
    let their_curve = keys.get(&to_user_id).and_then(|m| m.get(&to_session_id)).map(|d| d.curve25519_key.clone())
        .ok_or_else(|| LockNetError::InvalidResponse("recipient device not found".into()))?;

    let otk: Otk = dispatch(&cmd_tx, json!({
        "type": "claim_one_time_key",
        "data": { "user_id": to_user_id, "session_id": to_session_id, "algorithm": "curve25519" }
    })).await?;

    let their_identity = curve_from_b64(&their_curve)?;
    let otk_key = curve_from_b64(&otk.key)?;

    let account = store.account();
    let mut session = { let acc = account.lock().await; create_outbound(acc.inner(), their_identity, otk_key) };
    let encrypted = encrypt_olm(&mut session, &plaintext);
    let entry = OlmSessionEntry { session: Arc::new(tokio::sync::Mutex::new(session)), their_curve25519: their_curve.clone() };
    store.olm_add(to_session_id, entry);

    send_to_device(&cmd_tx, to_user_id, to_session_id, &their_curve, &encrypted).await?;
    Ok(())
}

async fn send_to_device(cmd_tx: &mpsc::Sender<Cmd>, to_user_id: i64, to_session_id: i64, their_curve: &str, encrypted: &EncryptedOlm) -> Result<()> {
    let payload = json!({
        "algorithm": OLM_ALGORITHM,
        "sender_key": "WILL_BE_OVERWRITTEN",
        "sender_session_id": 0,
        "ciphertext": { their_curve: { "type": encrypted.message_type, "body": encrypted.body } }
    });
    let _: serde_json::Value = dispatch(cmd_tx, json!({
        "type": "send_to_device",
        "data": { "messages": { to_user_id.to_string(): { to_session_id.to_string(): payload } } }
    })).await?;
    Ok(())
}

async fn decrypt_impl(store: Arc<dyn CryptoStore>, payload: ToDevicePayload) -> Result<Option<String>> {
    if payload.algorithm != OLM_ALGORITHM {
        return Err(LockNetError::InvalidResponse(format!("unexpected algorithm: {}", payload.algorithm)));
    }
    let peer_session_id = payload.sender_session_id;
    let our_curve = { let account = store.account(); let acc = account.lock().await; acc.curve25519_public_b64() };
    let inner = payload.ciphertext.get(&our_curve).or_else(|| payload.ciphertext.values().next())
        .ok_or_else(|| LockNetError::InvalidResponse("no matching ciphertext".into()))?;

    for entry in store.olm_sessions(peer_session_id).into_iter().rev() {
        let mut session = entry.session.lock().await;
        if let Ok(pt) = decrypt_olm(&mut session, inner.ciphertext_type, &inner.body) {
            return Ok(Some(pt));
        }
    }

    if inner.ciphertext_type == 0 {
        let prekey = parse_prekey(&inner.body)?;
        let their_identity = curve_from_b64(&payload.sender_key)?;
        let account = store.account();
        let mut acc = account.lock().await;
        let result = create_inbound(acc.inner_mut(), their_identity, &prekey)?;
        drop(acc);

        let plaintext = String::from_utf8(result.plaintext).map_err(|e| LockNetError::InvalidResponse(format!("olm utf8: {e}")))?;
        let entry = OlmSessionEntry { session: Arc::new(tokio::sync::Mutex::new(result.session)), their_curve25519: payload.sender_key.clone() };
        store.olm_add(peer_session_id, entry);
        return Ok(Some(plaintext));
    }
    Ok(None)
}