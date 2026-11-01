use serde_json::json;
use tokio::sync::mpsc;
use crate::api::low::command::{dispatch, dispatch_unit, Cmd};
use crate::api::low::models::*;
use crate::core::errors::Result;

pub struct LockNetMessagesHelper { pub(crate) cmd_tx: mpsc::Sender<Cmd> }

impl LockNetMessagesHelper {
    pub async fn send(&self, chat_id: i64, encrypted: Encrypted) -> Result<SendMessageAck> {
        dispatch(&self.cmd_tx, json!({ "type": "send_message", "data": { "chat_id": chat_id, "encrypted": encrypted } })).await
    }
    pub async fn get(&self, chat_id: i64, before: Option<i64>, limit: u32) -> Result<MessagesPage> {
        dispatch(&self.cmd_tx, json!({ "type": "get_messages", "data": { "chat_id": chat_id, "before": before, "limit": limit } })).await
    }
    pub async fn edit(&self, message_id: i64, encrypted: Encrypted) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "edit_message", "data": { "message_id": message_id, "encrypted": encrypted } })).await
    }
    pub async fn delete(&self, message_id: i64) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "delete_message", "data": { "message_id": message_id } })).await
    }
    pub async fn add_reaction(&self, message_id: i64, emoji: impl Into<String>) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "add_reaction", "data": { "message_id": message_id, "emoji": emoji.into() } })).await
    }
    pub async fn remove_reaction(&self, message_id: i64, emoji: impl Into<String>) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "remove_reaction", "data": { "message_id": message_id, "emoji": emoji.into() } })).await
    }
}