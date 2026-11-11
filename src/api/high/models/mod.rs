//! Domain models.
//!
//! Unlike the wire DTOs in [`crate::api::low::models`], these carry resolved
//! references (a [`Message`] has a [`User`], not a `user_id`) and the
//! decrypted Megolm policy where available.

pub mod chat;
pub mod group;
pub mod invite;
pub mod message;
pub mod reaction;
pub mod user;

pub use chat::Chat;
pub use group::{Group, GroupMember};
pub use invite::Invite;
pub use message::Message;
pub use reaction::Reaction;
pub use user::{SessionInfo, User};
