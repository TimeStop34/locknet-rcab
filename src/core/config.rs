//! Configuration types for [`crate::LockNetClient`].

use std::time::Duration;
use url::Url;
use crate::core::policies::{HistoryVisibility, MegolmRotationVisibility};

/// Connection and behavior configuration for [`crate::LockNetClient`].
///
/// Groups of settings:
/// - **Transport**: `base_url`, `space`, `user_agent`, TLS verification, timeouts.
/// - **WebSocket lifecycle**: ping interval, reconnect backoff, request timeout.
/// - **Event sync**: `sync_on_connect`, `event_sync_limit`.
/// - **E2EE defaults**: group policies and Megolm auto-rotation.
///
/// # Examples
///
/// ```rust
/// use locknet_rcab::LockNetConfig;
///
/// let config = LockNetConfig::new("https://locknet.example.com", "example.com")
///     .expect("valid URL");
/// assert_eq!(config.space, "example.com");
/// ```
#[derive(Clone, Debug)]
pub struct LockNetConfig {
    /// Base URL of the LockNet server. Must include the scheme (`https://` or
    /// `http://`) and may include a port.
    pub base_url: Url,

    /// Server namespace.
    ///
    /// Must match the server's `SPACE` setting. Sent as the `space` claim in
    /// JWTs and validated on every request; a mismatch causes token rejection.
    pub space: String,

    /// User-Agent header sent with HTTP requests.
    ///
    /// Defaults to `LockNet-RCAB/<crate-version>`.
    pub user_agent: String,

    /// Whether to sync offline events immediately after connecting.
    pub sync_on_connect: bool,

    /// Maximum number of events requested per `event_sync` call.
    pub event_sync_limit: u32,

    /// Timeout for individual HTTP requests (login, register, refresh).
    pub http_timeout: Duration,

    /// Interval between WebSocket ping frames.
    pub ws_ping_interval: Duration,

    /// Initial delay before the first reconnect attempt.
    pub reconnect_backoff_initial: Duration,

    /// Maximum delay between reconnect attempts (exponential backoff cap).
    pub reconnect_backoff_max: Duration,

    /// Whether to accept invalid TLS certificates.
    ///
    /// **Security:** defaults to `false`. Enable only for local testing
    /// against self-signed certificates.
    pub accept_invalid_certs: bool,

    /// Maximum time to wait for a reply to a single WebSocket request.
    ///
    /// On expiry, `dispatch` returns [`crate::LockNetError::Timeout`].
    pub request_timeout: Duration,

    /// Fallback `HistoryVisibility` when the server does not supply
    /// `encrypted_group_data` for a group.
    ///
    /// The **safe** default is [`HistoryVisibility::AfterJoin`] — never share
    /// history with anyone until the policy is known and verified.
    pub default_history_visibility: HistoryVisibility,

    /// Fallback `MegolmRotationVisibility` when the server does not supply
    /// `encrypted_group_data` for a group.
    ///
    /// The **safe** default is [`MegolmRotationVisibility::OnlyVerifiedUsers`].
    pub default_megolm_rotation_visibility: MegolmRotationVisibility,

    /// Rotate the outbound Megolm session after this many messages.
    ///
    /// `0` disables rotation by message count. Default: `100`.
    pub megolm_rotation_message_count: u64,

    /// Rotate the outbound Megolm session after this many seconds since
    /// creation.
    ///
    /// `0` disables rotation by TTL. Default: `7 days`.
    pub megolm_rotation_ttl_secs: u64,
}

impl LockNetConfig {
    /// Build a config with default values.
    ///
    /// # Arguments
    ///
    /// * `base_url` — server URL, e.g. `"https://locknet.example.com"`.
    /// * `space` — server namespace, must match the server's `SPACE`.
    ///
    /// # Errors
    ///
    /// Returns [`url::ParseError`] if `base_url` is not a valid URL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use locknet_rcab::LockNetConfig;
    ///
    /// let config = LockNetConfig::new("https://locknet.example.com", "example.com")
    ///     .expect("valid URL");
    /// assert_eq!(config.space, "example.com");
    /// assert!(!config.accept_invalid_certs);
    /// ```
    pub fn new(base_url: &str, space: &str) -> std::result::Result<Self, url::ParseError> {
        Ok(Self {
            base_url: Url::parse(base_url)?,
            space: space.to_string(),
            user_agent: format!("LockNet-RCAB/{}", env!("CARGO_PKG_VERSION")),
            sync_on_connect: true,
            event_sync_limit: 200,
            http_timeout: Duration::from_secs(30),
            ws_ping_interval: Duration::from_secs(30),
            reconnect_backoff_initial: Duration::from_secs(1),
            reconnect_backoff_max: Duration::from_secs(60),
            accept_invalid_certs: false,
            request_timeout: Duration::from_secs(30),
            default_history_visibility: HistoryVisibility::AfterJoin,
            default_megolm_rotation_visibility: MegolmRotationVisibility::OnlyVerifiedUsers,
            megolm_rotation_message_count: 100,
            megolm_rotation_ttl_secs: 7 * 24 * 3600,
        })
    }

    /// Derive the WebSocket URL from `base_url`.
    ///
    /// Uses `wss` for `https` bases and `ws` for `http` bases.
    pub fn ws_url(&self) -> String {
        let scheme = if self.base_url.scheme() == "https" { "wss" } else { "ws" };
        let host = self.base_url.host_str().unwrap_or("localhost");
        let port = self.base_url.port().map(|p| format!(":{}", p)).unwrap_or_default();
        format!("{}://{}{}/ws", scheme, host, port)
    }

    /// Build a full HTTP endpoint URL by appending `path` to `base_url`.
    ///
    /// Handles trailing slashes on `base_url` so that the result never has
    /// double slashes.
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url.as_str().trim_end_matches('/'), path)
    }
}