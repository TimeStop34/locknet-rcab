use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSyncAck {
    pub sent: usize,
    pub more: bool,
}