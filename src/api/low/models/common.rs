//! Types shared across multiple API areas.

use serde::{Deserialize, Serialize};

/// Wire representation of an encrypted message payload.
///
/// Sent inside `send_message` / `edit_message` and received in
/// `message_create` / `message_update` / `get_messages`. The server rewrites
/// `sender_key` and `sender_session_id` from the authenticated session before
/// storage, so values coming from the server always reflect the actual
/// sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted {
    /// Algorithm identifier.
    ///
    /// - `"ln.encryption.megolm.v1"` — normal E2EE message.
    /// - `"ln.plaintext.v1"` — public groups (base64 of the UTF-8 plaintext).
    pub algorithm: String,

    /// Sender's Curve25519 identity key (server-assigned).
    pub sender_key: String,

    /// Sender's session ID (server-assigned).
    pub sender_session_id: i64,

    /// Megolm session ID (empty for `ln.plaintext.v1`).
    pub megolm_session_id: String,

    /// Base64-encoded ciphertext (or plaintext for `ln.plaintext.v1`).
    pub ciphertext: String,
}
