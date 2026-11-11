//! Message, reaction, and message-related event wire types.

use super::common::Encrypted;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of `send_message`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageAck {
    /// Assigned message ID (snowflake).
    pub message_id: i64,
    /// Server-side creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Aggregated reaction on a message.
///
/// The server groups reactions by emoji; each [`Reaction`] in a
/// [`Message::reactions`] list represents one distinct emoji with its
/// reactors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    /// Emoji character(s).
    pub emoji: String,
    /// Total number of users who reacted with this emoji.
    pub count: usize,
    /// IDs of the users who reacted.
    pub user_ids: Vec<i64>,
}

/// A message as returned by `get_messages`.
///
/// Soft-deleted messages remain in history with `deleted = true` and
/// `encrypted = None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message ID.
    pub message_id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
    /// Author's user ID.
    pub author_id: i64,
    /// Author's session ID.
    pub author_session_id: i64,
    /// Encrypted payload. `None` if the message is deleted.
    pub encrypted: Option<Encrypted>,
    /// Thread ID (currently unused; reserved for threaded messages).
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

/// One page of messages from `get_messages`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesPage {
    /// Messages, newest first.
    pub messages: Vec<Message>,
    /// `true` if more pages exist (`before = last.message_id` to fetch them).
    pub has_more: bool,
}

/// Payload of a `message_create` event.
///
/// Unlike [`Message`], `encrypted` is non-optional: a newly created message
/// is never deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageCreate {
    /// Message ID.
    pub message_id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
    /// Author's user ID.
    pub author_id: i64,
    /// Author's session ID.
    pub author_session_id: i64,
    /// Encrypted payload.
    pub encrypted: Encrypted,
    /// Thread ID (reserved).
    pub thread_id: Option<i64>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last edit timestamp, if edited (always `None` in create events).
    pub edited_at: Option<DateTime<Utc>>,
    /// Aggregated reactions (empty for new messages).
    pub reactions: Vec<Reaction>,
}

/// Payload of a `message_update` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageUpdate {
    /// Message ID.
    pub message_id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
    /// New encrypted payload.
    pub encrypted: Encrypted,
    /// New edit timestamp.
    pub edited_at: DateTime<Utc>,
}

/// Payload of a `message_delete` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDelete {
    /// Message ID.
    pub message_id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
}

/// Payload of a `reaction_add` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionAdd {
    /// Reacted message.
    pub message_id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
    /// User who reacted.
    pub user_id: i64,
    /// Emoji added.
    pub emoji: String,
    /// When the reaction was created.
    pub created_at: DateTime<Utc>,
}

/// Payload of a `reaction_remove` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionRemove {
    /// Reacted message.
    pub message_id: i64,
    /// Chat (group) ID.
    pub chat_id: i64,
    /// User who removed their reaction.
    pub user_id: i64,
    /// Emoji removed.
    pub emoji: String,
}
