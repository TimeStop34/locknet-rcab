//! Messages helper: send, get, edit, delete, reactions.

use crate::api::low::command::{dispatch, dispatch_unit, CmdSender};
use crate::api::low::models::*;
use crate::core::errors::Result;
use serde_json::json;

/// Wraps the `/api/v1/messages` WebSocket methods.
///
/// Obtained via [`crate::LockNetLowAgent::messages`].
pub struct LockNetMessagesHelper {
    pub(crate) cmd_tx: CmdSender,
}

impl LockNetMessagesHelper {
    /// Send an encrypted message to `chat_id`.
    ///
    /// `encrypted` must use algorithm `ln.encryption.megolm.v1` (or
    /// `ln.plaintext.v1` for public groups). Its `sender_session_id` must
    /// match the current session — the server rewrites `sender_key` and
    /// `sender_session_id` from the authenticated session and rejects
    /// mismatches with `session_mismatch`.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `session_mismatch` if
    ///   `encrypted.sender_session_id` does not match the current session.
    /// - [`crate::LockNetError::Server`] with code `not_a_member` if the user is not
    ///   in the chat.
    /// - [`crate::LockNetError::Server`] with code `message_too_large` if the
    ///   ciphertext exceeds the server limit.
    /// - [`crate::LockNetError::Server`] with code `rate_limited` if the per-session
    ///   message rate limit is exceeded.
    /// - [`crate::LockNetError::Timeout`] if the request times out.
    pub async fn send(&self, chat_id: i64, encrypted: Encrypted) -> Result<SendMessageAck> {
        dispatch(&self.cmd_tx, json!({ "type": "send_message", "data": { "chat_id": chat_id, "encrypted": encrypted } })).await
    }

    /// Fetch a page of messages from `chat_id`.
    ///
    /// `before` is an optional cursor (`message_id`); `limit` must be between
    /// `1` and `100` (the server validates).
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `not_a_member` if the user is not
    ///   in the chat.
    /// - [`crate::LockNetError::Server`] with code `invalid_limit` if `limit` is out
    ///   of range.
    pub async fn get(&self, chat_id: i64, before: Option<i64>, limit: u32) -> Result<MessagesPage> {
        dispatch(&self.cmd_tx, json!({ "type": "get_messages", "data": { "chat_id": chat_id, "before": before, "limit": limit } })).await
    }

    /// Edit the ciphertext of a message.
    ///
    /// Only the author may edit, and only within the server-configured edit
    /// window (24 hours by default).
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `message_not_found`.
    /// - [`crate::LockNetError::Server`] with code `not_author`.
    /// - [`crate::LockNetError::Server`] with code `message_deleted`.
    /// - [`crate::LockNetError::Server`] with code `edit_window_expired`.
    pub async fn edit(&self, message_id: i64, encrypted: Encrypted) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "edit_message", "data": { "message_id": message_id, "encrypted": encrypted } })).await
    }

    /// Soft-delete a message.
    ///
    /// The message remains in history with `deleted = true` and
    /// `encrypted = None`. Available to the author and group moderators.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `message_not_found`.
    /// - [`crate::LockNetError::Server`] with code `forbidden` if the caller is
    ///   neither the author nor a moderator.
    pub async fn delete(&self, message_id: i64) -> Result<()> {
        dispatch_unit(
            &self.cmd_tx,
            json!({ "type": "delete_message", "data": { "message_id": message_id } }),
        )
        .await
    }

    /// Add a reaction.
    ///
    /// Idempotent: re-adding the same emoji produces `inserted = false` on
    /// the server and no duplicate push event.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `message_not_found`.
    /// - [`crate::LockNetError::Server`] with code `message_deleted`.
    /// - [`crate::LockNetError::Server`] with code `not_a_member`.
    /// - [`crate::LockNetError::Server`] with code `invalid_emoji`.
    pub async fn add_reaction(&self, message_id: i64, emoji: impl Into<String>) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "add_reaction", "data": { "message_id": message_id, "emoji": emoji.into() } })).await
    }

    /// Remove a reaction added by the current user.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `message_not_found`.
    /// - [`crate::LockNetError::Server`] with code `reaction_not_found` if the user
    ///   has not added this emoji to the message.
    pub async fn remove_reaction(&self, message_id: i64, emoji: impl Into<String>) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "remove_reaction", "data": { "message_id": message_id, "emoji": emoji.into() } })).await
    }
}
