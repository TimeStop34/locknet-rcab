//! LockNet API layers.
//!
//! - [`client`] — [`crate::LockNetClient`], the entry point.
//! - [`low`] — thin wrappers over individual WebSocket methods.
//! - [`high`] — object-oriented layer (chats, users, events) on top of low.
//! - [`session`] — credentials and session context.

pub mod client;
pub mod high;
pub mod low;
pub mod session;