use vodozemac::megolm::{
    ExportedSessionKey, GroupSession, InboundGroupSession, MegolmMessage, SessionConfig,
    SessionKey,
};
use crate::core::errors::{LockNetError, Result};

pub const MEGOLM_ALGORITHM: &str = "ln.encryption.megolm.v1";

pub fn create_outbound() -> (GroupSession, String) {
    let session = GroupSession::new(SessionConfig::version_1());
    let key = session.session_key().to_base64();
    (session, key)
}

pub fn session_id(session: &GroupSession) -> String {
    session.session_id()
}

pub fn encrypt(session: &mut GroupSession, plaintext: &str) -> String {
    session.encrypt(plaintext).to_base64()
}

pub fn import_inbound(session_key_b64: &str) -> Result<InboundGroupSession> {
    if let Ok(key) = SessionKey::from_base64(session_key_b64) {
        return Ok(InboundGroupSession::new(&key, SessionConfig::version_1()));
    }
    if let Ok(key) = ExportedSessionKey::from_base64(session_key_b64) {
        return Ok(InboundGroupSession::import(&key, SessionConfig::version_1()));
    }
    Err(LockNetError::InvalidResponse(
        "megolm key: invalid v1 or v2 key".into(),
    ))
}

pub fn decrypt_inbound(session: &mut InboundGroupSession, ciphertext_b64: &str) -> Result<String> {
    let msg = MegolmMessage::from_base64(ciphertext_b64).map_err(|e| LockNetError::InvalidResponse(format!("megolm ct b64: {e}")))?;
    let result = session.decrypt(&msg).map_err(|e| LockNetError::InvalidResponse(format!("megolm decrypt: {e}")))?;
    String::from_utf8(result.plaintext).map_err(|e| LockNetError::InvalidResponse(format!("megolm utf8: {e}")))
}