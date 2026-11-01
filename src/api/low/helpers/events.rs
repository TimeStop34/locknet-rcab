use serde_json::json;
use tokio::sync::mpsc;

use crate::api::low::command::{dispatch, Cmd};
use crate::api::low::models::*;
use crate::core::errors::Result;

pub struct LockNetEventsHelper {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
}

impl LockNetEventsHelper {
    pub async fn sync(&self) -> Result<EventSyncAck> {
        dispatch(&self.cmd_tx, json!({ "type": "event_sync", "data": {} })).await
    }

    pub async fn sync_until_empty(&self, max_iterations: u32) -> Result<u64> {
        let mut total = 0u64;
        for _ in 0..max_iterations {
            let ack = self.sync().await?;
            total += ack.sent as u64;
            if !ack.more {
                return Ok(total);
            }
        }
        Ok(total)
    }
}