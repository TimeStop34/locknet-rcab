use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::low::models::Encrypted;

use super::reaction::Reaction;
use super::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: i64,
    pub chat_id: i64,
    pub author: User,
    pub author_session_id: i64,
    pub text: Option<String>,
    pub encrypted: bool,
    pub encrypted_payload: Option<Encrypted>,
    pub thread_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub edited_at: Option<DateTime<Utc>>,
    pub deleted: bool,
    pub reactions: Vec<Reaction>,
}