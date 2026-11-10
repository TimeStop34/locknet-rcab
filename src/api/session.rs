//! Credentials and session context.

use chrono::{DateTime, Utc};

/// State of an authenticated session.
///
/// Produced by [`crate::LockNetClient::connection_request`] and available via
/// [`crate::LockNetClient::session`].
#[derive(Debug, Clone)]
pub struct LockNetSessionContext {
    /// Server-side user ID (snowflake).
    pub user_id: i64,

    /// Server-side session ID (snowflake). Bound to the device identity keys
    /// stored in the client's [`crate::CryptoStore`].
    pub session_id: i64,

    /// Current access JWT (short-lived, ~1 hour).
    pub ajwt: String,

    /// Current refresh JWT (long-lived, ~30 days). Rotated on every refresh.
    pub rjwt: String,

    /// When `ajwt` was issued.
    pub rtime: DateTime<Utc>,

    /// Server namespace (mirror of [`crate::LockNetConfig::space`]).
    pub space: String,

    /// Display name, if cached by the caller.
    pub vname: Option<String>,

    /// Avatar URL, if cached by the caller.
    pub image: Option<String>,
}

/// How to establish a session with the server.
///
/// Passed to [`crate::LockNetClient::connection_request`].
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Username/password login. On success, generates **new** identity keys
    /// if the store has none, and uploads 50 one-time keys.
    Login {
        /// Username as registered on the server.
        username: String,
        /// Plain-text password.
        password: String,
    },

    /// Create a new user account. Behaves like [`Credentials::Login`] after
    /// registration (keys are generated and uploaded).
    Register {
        /// Desired username.
        username: String,
        /// Plain-text password.
        password: String,
        /// Optional display name.
        display_name: Option<String>,
    },

    /// Reconnect using an existing refresh token.
    ///
    /// The session ID is preserved (the server refreshes the **existing**
    /// session rather than creating a new one), so the device identity keys in
    /// the store remain associated with the same `session_id`.
    Session {
        /// Refresh JWT from a previous session.
        refresh_jwt: String,
    },
}