//! Olm session primitives: encrypt/decrypt, pre-key parsing, session creation.

use std::sync::Arc;
use tokio::sync::Mutex;
use vodozemac::olm::{
    Account as OlmAccount, InboundCreationResult, Message as OlmNormalMessage, OlmMessage,
    PreKeyMessage, Session as OlmSession, SessionConfig,
};
use vodozemac::Curve25519PublicKey;

use crate::core::errors::{LockNetError, Result};

/// Wire identifier for Olm sessions.
pub const OLM_ALGORITHM: &str = "ln.encryption.olm.v1";

/// An encrypted Olm message ready for `send_to_device`.
#[derive(Clone)]
pub struct EncryptedOlm {
    /// `0` for a pre-key message, `1` for a normal message.
    pub message_type: u8,
    /// Base64-encoded message body.
    pub body: String,
}

/// An established Olm session with a specific peer device.
///
/// The `Arc<Mutex<_>>` wrapper allows the session to be shared between the
/// [`crate::core::crypto::CryptoStore`] and helper code that mutates the
/// ratchet state.
#[derive(Clone)]
pub struct OlmSessionEntry {
    /// The session itself.
    pub session: Arc<Mutex<OlmSession>>,
    /// The peer's Curve25519 identity key, base64.
    pub their_curve25519: String,
}

/// Encrypt `plaintext` with an Olm session.
///
/// The message type is `0` (pre-key) if the session has not yet received a
/// reply, and `1` (normal) once both sides have exchanged at least one
/// message.
pub fn encrypt_olm(session: &mut OlmSession, plaintext: &str) -> EncryptedOlm {
    let msg = session.encrypt(plaintext);
    match msg {
        OlmMessage::PreKey(m) => EncryptedOlm {
            message_type: 0,
            body: m.to_base64(),
        },
        OlmMessage::Normal(m) => EncryptedOlm {
            message_type: 1,
            body: m.to_base64(),
        },
    }
}

/// Decrypt an Olm message of the given `message_type` (`0` pre-key, `1` normal).
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the base64 is malformed, the
/// message type is unknown, decryption fails (wrong session or corrupted
/// ciphertext), or the plaintext is not valid UTF-8.
pub fn decrypt_olm(session: &mut OlmSession, message_type: u8, body: &str) -> Result<String> {
    let msg = if message_type == 0 {
        OlmMessage::PreKey(
            PreKeyMessage::from_base64(body)
                .map_err(|e| LockNetError::InvalidResponse(format!("prekey b64: {e}")))?,
        )
    } else {
        OlmMessage::Normal(
            OlmNormalMessage::from_base64(body)
                .map_err(|e| LockNetError::InvalidResponse(format!("normal b64: {e}")))?,
        )
    };
    let bytes = session
        .decrypt(&msg)
        .map_err(|e| LockNetError::InvalidResponse(format!("olm decrypt: {e}")))?;
    String::from_utf8(bytes).map_err(|e| LockNetError::InvalidResponse(format!("olm utf8: {e}")))
}

/// Parse a base64-encoded Curve25519 public key.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the base64 or key bytes are
/// malformed.
pub fn curve_from_b64(s: &str) -> Result<Curve25519PublicKey> {
    Curve25519PublicKey::from_base64(s)
        .map_err(|e| LockNetError::InvalidResponse(format!("curve b64: {e}")))
}

/// Parse a base64-encoded Olm pre-key message body.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the base64 is malformed.
pub fn parse_prekey(body: &str) -> Result<PreKeyMessage> {
    PreKeyMessage::from_base64(body)
        .map_err(|e| LockNetError::InvalidResponse(format!("prekey b64: {e}")))
}

/// Create an outbound Olm session from our account, the peer's identity key,
/// and a one-time key claimed from the peer.
pub fn create_outbound(
    account: &OlmAccount,
    their_identity: Curve25519PublicKey,
    otk: Curve25519PublicKey,
) -> OlmSession {
    account.create_outbound_session(SessionConfig::version_1(), their_identity, otk)
}

/// Create an inbound Olm session from a received pre-key message.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the peer's identity key does
/// not match the one embedded in the pre-key message, or if the one-time key
/// is unknown (already consumed).
pub fn create_inbound(
    account: &mut OlmAccount,
    their_identity: Curve25519PublicKey,
    prekey: &PreKeyMessage,
) -> Result<InboundCreationResult> {
    account
        .create_inbound_session(their_identity, prekey)
        .map_err(|e| LockNetError::InvalidResponse(format!("olm inbound: {e}")))
}
