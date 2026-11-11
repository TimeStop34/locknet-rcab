//! Object-oriented, stateful layer on top of [`crate::api::low`].
//!
//! [`crate::LockNetAgent`] maintains a cache of chats, users, invites, and
//! messages, processes incoming low-level events into high-level
//! [`HighEvent`]s, and orchestrates the multi-step E2EE flows (fan-out of
//! group keys, key requests, verification, policy sync).
//!
//! Applications typically use this layer directly. The lower-level
//! [`crate::api::low`] is useful when raw control over individual requests is
//! needed.

pub mod agent;
pub mod event;
pub(crate) mod group_key;
pub mod models;
pub mod security;
pub(crate) mod state;
pub mod trust;
pub mod verification;

pub use agent::LockNetAgent;
pub use event::HighEvent;
pub use models::{
    chat::Chat,
    group::{Group, GroupMember},
    invite::Invite,
    message::Message,
    reaction::Reaction,
    user::{SessionInfo, User},
};
pub use security::SecurityHelper;
pub use verification::{QrCode, QrFlow, QrMode, QrStep, SasEmoji, SasFlow, SasStatus, SasStep};
