//! Messages as seen by the high-level layer.

use super::reaction::Reaction;
use super::user::User;
use crate::api::low::models::Encrypted;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A message with its decrypted text (if available) and resolved author.
///
/// For encrypted messages that could not be decrypted (e.g. the Megolm key
/// was not yet available), [`Self::text`] is `None` and
/// [`Self::encrypted_payload`] holds the wire data. Call
/// [`crate::Chat::request_missing_keys`] to try to obtain the key.
///
/// Soft-deleted messages have [`Self::deleted`] set to `true`,
/// [`Self::text`] = `None`, and [`Self::encrypted_payload`] = `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message ID.
    pub id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
    /// Author (resolved).
    pub author: User,
    /// Author's session ID.
    pub author_session_id: i64,
    /// Decrypted plaintext, if available.
    pub text: Option<String>,
    /// Whether the wire payload was encrypted (`ln.encryption.megolm.v1`),
    /// as opposed to plaintext (`ln.plaintext.v1`).
    pub encrypted: bool,
    /// Original wire payload (present even if decryption failed).
    pub encrypted_payload: Option<Encrypted>,
    /// Thread ID (reserved for future use).
    pub thread_id: Option<i64>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last edit timestamp, if edited.
    pub edited_at: Option<DateTime<Utc>>,
    /// Soft-delete flag.
    pub deleted: bool,
    /// Aggregated reactions.
    pub reactions: Vec<Reaction>,
}
