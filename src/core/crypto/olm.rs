use std::sync::Arc;
use tokio::sync::Mutex;
use vodozemac::olm::{
    Account as OlmAccount, InboundCreationResult, Message as OlmNormalMessage, OlmMessage,
    PreKeyMessage, Session as OlmSession, SessionConfig,
};
use vodozemac::Curve25519PublicKey;

use crate::core::errors::{LockNetError, Result};

pub const OLM_ALGORITHM: &str = "ln.encryption.olm.v1";

#[derive(Clone)]
pub struct EncryptedOlm {
    pub message_type: u8,
    pub body: String,
}

#[derive(Clone)]
pub struct OlmSessionEntry {
    pub session: Arc<Mutex<OlmSession>>,
    pub their_curve25519: String,
}

pub fn encrypt_olm(session: &mut OlmSession, plaintext: &str) -> EncryptedOlm {
    let msg = session.encrypt(plaintext);
    match msg {
        OlmMessage::PreKey(m) => EncryptedOlm { message_type: 0, body: m.to_base64() },
        OlmMessage::Normal(m) => EncryptedOlm { message_type: 1, body: m.to_base64() },
    }
}

pub fn decrypt_olm(session: &mut OlmSession, message_type: u8, body: &str) -> Result<String> {
    let msg = if message_type == 0 {
        OlmMessage::PreKey(PreKeyMessage::from_base64(body).map_err(|e| LockNetError::InvalidResponse(format!("prekey b64: {e}")))?)
    } else {
        OlmMessage::Normal(OlmNormalMessage::from_base64(body).map_err(|e| LockNetError::InvalidResponse(format!("normal b64: {e}")))?)
    };
    let bytes = session.decrypt(&msg).map_err(|e| LockNetError::InvalidResponse(format!("olm decrypt: {e}")))?;
    String::from_utf8(bytes).map_err(|e| LockNetError::InvalidResponse(format!("olm utf8: {e}")))
}

pub fn curve_from_b64(s: &str) -> Result<Curve25519PublicKey> {
    Curve25519PublicKey::from_base64(s).map_err(|e| LockNetError::InvalidResponse(format!("curve b64: {e}")))
}

pub fn parse_prekey(body: &str) -> Result<PreKeyMessage> {
    PreKeyMessage::from_base64(body).map_err(|e| LockNetError::InvalidResponse(format!("prekey b64: {e}")))
}

pub fn create_outbound(account: &OlmAccount, their_identity: Curve25519PublicKey, otk: Curve25519PublicKey) -> OlmSession {
    account.create_outbound_session(SessionConfig::version_1(), their_identity, otk)
}

pub fn create_inbound(account: &mut OlmAccount, their_identity: Curve25519PublicKey, prekey: &PreKeyMessage) -> Result<InboundCreationResult> {
    account.create_inbound_session(their_identity, prekey).map_err(|e| LockNetError::InvalidResponse(format!("olm inbound: {e}")))
}