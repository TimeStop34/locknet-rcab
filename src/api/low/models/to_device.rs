//! `to_device` payload and related types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One encrypted `to_device` ciphertext, keyed by the recipient's identity
/// key in [`ToDevicePayload::ciphertext`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDeviceCiphertext {
    /// `0` for an Olm pre-key message, `1` for a normal Olm message.
    #[serde(rename = "type")]
    pub ciphertext_type: u8,
    /// Base64-encoded message body.
    pub body: String,
}

/// A server-pushed `to_device` payload.
///
/// Contains end-to-end encrypted data addressed to this specific device
/// (Olm payloads, group keys, verification messages, …). Decrypted by
/// [`crate::api::low::helpers::LockNetOlmHelper::decrypt`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDevicePayload {
    /// Algorithm identifier (e.g. `"ln.encryption.olm.v1"`).
    pub algorithm: String,
    /// Sender's Curve25519 identity key (server-assigned).
    pub sender_key: String,
    /// Sender's session ID (server-assigned).
    pub sender_session_id: i64,
    /// Map `recipient_identity_key → ciphertext`.
    pub ciphertext: HashMap<String, ToDeviceCiphertext>,
}

/// Shape passed to `send_to_device`: `user_id → session_id → payload`.
pub type ToDeviceMessages = HashMap<i64, HashMap<i64, serde_json::Value>>;

/// Result of `send_to_device`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDeviceAck {
    /// Number of payloads delivered to online devices.
    pub accepted: usize,
    /// Number of payloads dropped (unknown session, wrong user, or offline).
    pub dropped: usize,
}
