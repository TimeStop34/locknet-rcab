use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::common::Encrypted;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageAck {
    pub message_id: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    pub count: usize,
    pub user_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub chat_id: i64,
    pub author_id: i64,
    pub author_session_id: i64,
    pub encrypted: Option<Encrypted>,
    pub thread_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub edited_at: Option<DateTime<Utc>>,
    pub deleted: bool,
    pub reactions: Vec<Reaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesPage {
    pub messages: Vec<Message>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageCreate {
    pub message_id: i64,
    pub chat_id: i64,
    pub author_id: i64,
    pub author_session_id: i64,
    pub encrypted: Encrypted,
    pub thread_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub edited_at: Option<DateTime<Utc>>,
    pub reactions: Vec<Reaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageUpdate {
    pub message_id: i64,
    pub chat_id: i64,
    pub encrypted: Encrypted,
    pub edited_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDelete {
    pub message_id: i64,
    pub chat_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionAdd {
    pub message_id: i64,
    pub chat_id: i64,
    pub user_id: i64,
    pub emoji: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionRemove {
    pub message_id: i64,
    pub chat_id: i64,
    pub user_id: i64,
    pub emoji: String,
}