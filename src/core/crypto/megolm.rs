use vodozemac::megolm::{
    GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};
use crate::core::errors::{LockNetError, Result};

pub const MEGOLM_ALGORITHM: &str = "ln.encryption.megolm.v1";

pub fn create_outbound() -> (GroupSession, String) {
    let session = GroupSession::new(SessionConfig::version_1());
    (session, session.session_key().to_base64())
}

pub fn session_id(session: &GroupSession) -> String {
    session.session_id()
}

pub fn encrypt(session: &mut GroupSession, plaintext: &str) -> String {
    session.encrypt(plaintext).to_base64()
}

pub fn import_inbound(session_key_b64: &str) -> Result<InboundGroupSession> {
    let key = SessionKey::from_base64(session_key_b64).map_err(|e| LockNetError::InvalidResponse(format!("megolm key b64: {e}")))?;
    Ok(InboundGroupSession::new(&key, SessionConfig::version_1()))
}

pub fn decrypt_inbound(session: &mut InboundGroupSession, ciphertext_b64: &str) -> Result<String> {
    let msg = MegolmMessage::from_base64(ciphertext_b64).map_err(|e| LockNetError::InvalidResponse(format!("megolm ct b64: {e}")))?;
    let result = session.decrypt(&msg).map_err(|e| LockNetError::InvalidResponse(format!("megolm decrypt: {e}")))?;
    String::from_utf8(result.plaintext).map_err(|e| LockNetError::InvalidResponse(format!("megolm utf8: {e}")))
}