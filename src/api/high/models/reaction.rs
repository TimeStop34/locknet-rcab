//! Message reactions.

use serde::{Deserialize, Serialize};

/// Aggregated reaction on a message.
///
/// One `Reaction` per distinct emoji. All reactors for a given emoji are
/// grouped together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    /// Emoji character(s).
    pub emoji: String,
    /// User IDs who reacted with this emoji.
    pub user_ids: Vec<i64>,
    /// Number of reactors (`user_ids.len()`).
    pub count: usize,
}
