//! Event sync helper.

use serde_json::json;
use crate::api::low::command::{dispatch, CmdSender};
use crate::api::low::models::*;
use crate::core::errors::Result;

/// Wraps the `event_sync` WebSocket method.
///
/// Obtained via [`crate::LockNetLowAgent::events`].
pub struct LockNetEventsHelper { pub(crate) cmd_tx: CmdSender }

impl LockNetEventsHelper {
    /// Fetch one batch of queued events.
    ///
    /// Each call returns up to the server-side limit of events that were
    /// queued for this session while it was offline. Events are removed from
    /// the queue as they are delivered. If `ack.more == true`, call `sync()`
    /// again to drain the rest.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Timeout`] if the request times out.
    pub async fn sync(&self) -> Result<EventSyncAck> {
        dispatch(&self.cmd_tx, json!({ "type": "event_sync", "data": {} })).await
    }

    /// Drain the event queue: call [`Self::sync`] repeatedly until
    /// `more == false`, up to `max_iterations` batches.
    ///
    /// Returns the total number of events delivered across all batches.
    pub async fn sync_until_empty(&self, max_iterations: u32) -> Result<u64> {
        let mut total = 0u64;
        for _ in 0..max_iterations {
            let ack = self.sync().await?;
            total += ack.sent as u64;
            if !ack.more { return Ok(total); }
        }
        Ok(total)
    }
}