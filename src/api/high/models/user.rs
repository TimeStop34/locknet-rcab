//! Users and their sessions.

use serde::{Deserialize, Serialize};

/// Information about one device session of a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID.
    pub id: i64,
    /// Device's Ed25519 identity key, if published.
    pub ed25519_key: Option<String>,
    /// Device's Curve25519 identity key, if published.
    pub curve25519_key: Option<String>,
    /// Whether the session is verified by cross-signing (SSK-signed
    /// `ed25519`).
    pub verified: bool,
}

/// A user.
///
/// Unknown users (referenced by ID only, never seen with full metadata) are
/// represented as [`User::unknown`] with `username = "unknown"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID (snowflake).
    pub id: i64,
    /// Login username.
    pub username: String,
    /// Display name, if set.
    pub display_name: Option<String>,
    /// Avatar URL, if set.
    pub avatar_url: Option<String>,
    /// Whether this is a bot account.
    pub is_bot: bool,
    /// Whether this user is trusted via the Web of Trust
    /// ([`crate::SecurityHelper::is_user_verified`]).
    pub verified: bool,
    /// Known sessions of this user.
    pub sessions: Vec<SessionInfo>,
}

impl User {
    /// Create a placeholder for a user referenced only by ID.
    pub fn unknown(id: i64) -> Self {
        Self {
            id,
            username: "unknown".into(),
            display_name: None,
            avatar_url: None,
            is_bot: false,
            verified: false,
            sessions: Vec::new(),
        }
    }

    /// Display name if set, otherwise username.
    pub fn display(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.username)
    }
}
