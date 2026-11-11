//! `event_sync` result.

use serde::{Deserialize, Serialize};

/// Result of `event_sync`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSyncAck {
    /// Number of events delivered in this batch.
    pub sent: usize,
    /// `true` if more events are queued and another `event_sync` call is
    /// needed.
    pub more: bool,
}
