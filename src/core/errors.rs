//! Error type and [`Result`] alias used throughout the crate.

use thiserror::Error;

/// Errors returned by `locknet-rcab`.
///
/// Combines transport (HTTP, WebSocket), serialization (JSON), local I/O, and
/// protocol-level errors into a single type. Server-returned errors surface as
/// [`LockNetError::Server`] with the machine-readable `code` and human-readable
/// `message` from the server.
///
/// Transport errors are boxed to keep `LockNetError` small (≈ 50 bytes on
/// 64-bit platforms) — unboxed `tungstenite::Error` alone is 136 bytes, which
/// bloats every `Result<T, LockNetError>` in the crate.
///
/// `LockNetError` implements [`std::error::Error`] via `thiserror`, so it can be
/// used with `?` and `Box<dyn Error>` interchangeably.
#[derive(Debug, Error)]
pub enum LockNetError {
    /// HTTP transport error (TLS, DNS, connection reset, etc.).
    #[error("HTTP error: {0}")]
    Http(Box<reqwest::Error>),

    /// WebSocket transport error.
    #[error("WebSocket error: {0}")]
    Ws(Box<tokio_tungstenite::tungstenite::Error>),

    /// JSON (de)serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Local I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Server-returned error with a stable machine-readable code.
    #[error("server error: {code}: {message}")]
    Server { code: String, message: String },

    /// The WebSocket runner task is not running.
    #[error("runner is not running")]
    RunnerDown,

    /// `connection_request` has not been called.
    #[error("not connected")]
    NotConnected,

    /// `connection_request` was already called.
    #[error("already connected")]
    AlreadyConnected,

    /// Invalid credentials (wrong username or password).
    #[error("invalid credentials")]
    InvalidCredentials,

    /// The session is no longer valid; re-authenticate via
    /// [`crate::Credentials::Session`].
    #[error("session expired")]
    SessionExpired,

    /// An operation exceeded its configured timeout
    /// (see [`crate::LockNetConfig::request_timeout`]).
    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Missing or malformed `Authorization: Bearer` header.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Malformed response from the server.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Malformed argument passed to an API method.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<reqwest::Error> for LockNetError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(Box::new(e))
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for LockNetError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Ws(Box::new(e))
    }
}

impl LockNetError {
    /// Returns a runner-safe clone that does not include non-`Clone` payloads.
    ///
    /// Used internally to propagate errors from the WebSocket runner task,
    /// where the original `reqwest`/`tungstenite`/`serde_json` error cannot be
    /// cloned. Transport errors are mapped to [`LockNetError::RunnerDown`];
    /// [`LockNetError::Server`] preserves its `code` and `message`.
    pub(crate) fn clone_for_runner(&self) -> LockNetError {
        match self {
            LockNetError::Http(_) => LockNetError::RunnerDown,
            LockNetError::Ws(_) => LockNetError::RunnerDown,
            LockNetError::Json(_) => LockNetError::RunnerDown,
            LockNetError::Io(_) => LockNetError::RunnerDown,
            LockNetError::Server { code, message } => LockNetError::Server {
                code: code.clone(),
                message: message.clone(),
            },
            LockNetError::RunnerDown => LockNetError::RunnerDown,
            LockNetError::NotConnected => LockNetError::NotConnected,
            LockNetError::AlreadyConnected => LockNetError::AlreadyConnected,
            LockNetError::InvalidCredentials => LockNetError::InvalidCredentials,
            LockNetError::SessionExpired => LockNetError::SessionExpired,
            LockNetError::Timeout(d) => LockNetError::Timeout(*d),
            LockNetError::Unauthorized(m) => LockNetError::Unauthorized(m.clone()),
            LockNetError::InvalidResponse(m) => LockNetError::InvalidResponse(m.clone()),
            LockNetError::InvalidArgument(m) => LockNetError::InvalidArgument(m.clone()),
        }
    }
}

/// Convenience alias for `Result<T, LockNetError>`.
pub type Result<T> = std::result::Result<T, LockNetError>;
