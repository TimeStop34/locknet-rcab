//! Transport layer.
//!
//! - [`http`] — the three HTTP endpoints under `/api/v1/auth/` used for
//!   login, registration, and token refresh.
//! - [`ws`] — the single WebSocket connection that carries every other
//!   request/response and all server-pushed events.

pub mod http;
pub mod ws;