//! Wire-format DTOs for LockNet server messages.
//!
//! Each type here mirrors a JSON payload exchanged with the server. They are
//! deliberately dumb (no logic, no invariants) — validation and translation
//! to domain types happen in [`crate::api::high`].
//!
//! All timestamps are ISO-8601 (`chrono::DateTime<Utc>`). All IDs are
//! snowflakes (`i64`).

pub mod backup;
pub mod common;
pub mod crypto;
pub mod events;
pub mod groups;
pub mod keys;
pub mod messages;
pub mod to_device;

pub use backup::*;
pub use common::*;
pub use crypto::*;
pub use events::*;
pub use groups::*;
pub use keys::*;
pub use messages::*;
pub use to_device::*;