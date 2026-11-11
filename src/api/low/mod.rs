//! Low-level agent and helpers.
//!
//! [`LockNetLowAgent`] wraps individual WebSocket methods as typed `async fn`
//! calls. This is the layer between the raw WS protocol and the
//! object-oriented [`crate::api::high`] layer.
//!
//! Most applications should use [`crate::LockNetAgent`] from [`crate::api::high`]
//! instead of calling low-level helpers directly. Use the low layer when you
//! need explicit control over each request (for example, when building a custom
//! UI that wants raw server events rather than processed `HighEvent`s).

pub mod agent;
pub(crate) mod command;
pub mod event;
pub mod helpers;
pub mod models;

pub use agent::LockNetLowAgent;
pub use event::Event;
