use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockNetError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("WebSocket error: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("server error: {code}: {message}")]
    Server { code: String, message: String },
    #[error("runner is not running")]
    RunnerDown,
    #[error("not connected")]
    NotConnected,
    #[error("already connected")]
    AlreadyConnected,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("session expired")]
    SessionExpired,
    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl LockNetError {
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

pub type Result<T> = std::result::Result<T, LockNetError>;