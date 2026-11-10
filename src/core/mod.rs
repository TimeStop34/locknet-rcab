//! Core building blocks: configuration, errors, transports, cryptography.
//!
//! This module contains everything that is not specific to the LockNet
//! protocol. The protocol itself lives in [`crate::api`].
//!
//! - [`config`] — connection and behavior settings.
//! - [`errors`] — the shared error type.
//! - [`flow`] — background task handles.
//! - [`policies`] — E2EE group policies (history visibility, rotation).
//! - [`runner`] — WebSocket connection loop (private).
//! - [`transport`] — HTTP and WebSocket transports.
//! - [`crypto`] — Olm, Megolm, cross-signing, and persistent stores.

pub mod config;
pub mod crypto;
pub mod errors;
pub mod flow;
pub mod policies;
pub(crate) mod runner;
pub mod transport;

pub use policies::{HistoryVisibility, MegolmRotationVisibility};