//! Megolm session primitives: create, encrypt, import, decrypt.

use crate::core::errors::{LockNetError, Result};
use vodozemac::megolm::{
    ExportedSessionKey, GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};

/// Wire identifier for Megolm sessions.
pub const MEGOLM_ALGORITHM: &str = "ln.encryption.megolm.v1";

/// Create a new outbound Megolm session and return it together with its
/// base64-encoded session key.
///
/// The session key is shared with recipients via `ln.encryption.group_key`
/// (through Olm) and imported by them as an [`InboundGroupSession`].
pub fn create_outbound() -> (GroupSession, String) {
    let session = GroupSession::new(SessionConfig::version_1());
    let key = session.session_key().to_base64();
    (session, key)
}

/// Return the Megolm session identifier as a string.
pub fn session_id(session: &GroupSession) -> String {
    session.session_id()
}

/// Encrypt `plaintext` and return the base64-encoded ciphertext.
pub fn encrypt(session: &mut GroupSession, plaintext: &str) -> String {
    session.encrypt(plaintext).to_base64()
}

/// Import an inbound group session from a base64-encoded key.
///
/// Accepts both key formats produced by `vodozemac`:
/// - **v2** ([`SessionKey`]) — from [`GroupSession::session_key`] or
///   `ln.encryption.group_key`.
/// - **v1** ([`ExportedSessionKey`]) — from [`InboundGroupSession::export_at`],
///   used in key backup.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if neither v2 nor v1 parsing
/// succeeds.
pub fn import_inbound(session_key_b64: &str) -> Result<InboundGroupSession> {
    if let Ok(key) = SessionKey::from_base64(session_key_b64) {
        return Ok(InboundGroupSession::new(&key, SessionConfig::version_1()));
    }
    if let Ok(key) = ExportedSessionKey::from_base64(session_key_b64) {
        return Ok(InboundGroupSession::import(
            &key,
            SessionConfig::version_1(),
        ));
    }
    Err(LockNetError::InvalidResponse(
        "megolm key: invalid v1 or v2 key".into(),
    ))
}

/// Decrypt a base64-encoded Megolm ciphertext with an inbound session.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the base64 is malformed,
/// decryption fails (wrong session, corrupted ciphertext, or unknown message
/// index), or the plaintext is not valid UTF-8.
pub fn decrypt_inbound(session: &mut InboundGroupSession, ciphertext_b64: &str) -> Result<String> {
    let msg = MegolmMessage::from_base64(ciphertext_b64)
        .map_err(|e| LockNetError::InvalidResponse(format!("megolm ct b64: {e}")))?;
    let result = session
        .decrypt(&msg)
        .map_err(|e| LockNetError::InvalidResponse(format!("megolm decrypt: {e}")))?;
    String::from_utf8(result.plaintext)
        .map_err(|e| LockNetError::InvalidResponse(format!("megolm utf8: {e}")))
}
