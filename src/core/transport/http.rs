//! HTTP endpoints used for authentication.
//!
//! Only three endpoints live here (all under `/api/v1/auth/`):
//!
//! - [`login`] — username/password → access + refresh JWT pair.
//! - [`register`] — create a user and get the initial token pair.
//! - [`refresh`] — rotate an access/refresh pair using a valid refresh JWT.
//!
//! Everything else (messages, groups, keys, …) goes through the WebSocket
//! transport in [`crate::core::transport::ws`].

use serde::Deserialize;
use serde_json::json;

use crate::core::config::LockNetConfig;
use crate::core::errors::{LockNetError, Result};

/// Response from `/api/v1/auth/login` and `/api/v1/auth/register`.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    /// Server-side user ID.
    pub user_id: i64,
    /// Access JWT (1 hour).
    pub access_token: String,
    /// Refresh JWT (30 days).
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    #[serde(default)]
    pub expires_in: i64,
}

/// Response from `/api/v1/auth/refresh`.
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    /// New access JWT.
    pub access_token: String,
    /// New refresh JWT (rotated on every refresh).
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    #[serde(default)]
    pub expires_in: i64,
}

/// Log in with username and password.
///
/// # Errors
///
/// - [`LockNetError::InvalidCredentials`] on HTTP 401.
/// - [`LockNetError::InvalidResponse`] on any other non-200 status.
/// - [`LockNetError::Http`] on transport failure.
pub async fn login(
    config: &LockNetConfig,
    http: &reqwest::Client,
    username: &str,
    password: &str,
) -> Result<AuthResponse> {
    let url = config.endpoint("/api/v1/auth/login");
    let resp = http
        .post(&url)
        .json(&json!({ "username": username, "password": password }))
        .send()
        .await?;
    match resp.status().as_u16() {
        200 => Ok(resp.json::<AuthResponse>().await?),
        401 => Err(LockNetError::InvalidCredentials),
        s => {
            let body = resp.text().await.unwrap_or_default();
            Err(LockNetError::InvalidResponse(format!(
                "login: HTTP {s}: {body}"
            )))
        }
    }
}

/// Register a new user.
///
/// # Errors
///
/// - [`LockNetError::Server`] with code `username_taken` on HTTP 409.
/// - [`LockNetError::InvalidResponse`] on any other non-201 status.
/// - [`LockNetError::Http`] on transport failure.
pub async fn register(
    config: &LockNetConfig,
    http: &reqwest::Client,
    username: &str,
    password: &str,
    display_name: Option<&str>,
) -> Result<AuthResponse> {
    let url = config.endpoint("/api/v1/auth/register");
    let resp = http
        .post(&url)
        .json(&json!({
            "username": username, "password": password, "display_name": display_name,
        }))
        .send()
        .await?;
    match resp.status().as_u16() {
        201 => Ok(resp.json::<AuthResponse>().await?),
        409 => Err(LockNetError::Server {
            code: "username_taken".into(),
            message: "Username already taken".into(),
        }),
        s => {
            let body = resp.text().await.unwrap_or_default();
            Err(LockNetError::InvalidResponse(format!(
                "register: HTTP {s}: {body}"
            )))
        }
    }
}

/// Exchange a refresh token for a new access/refresh pair.
///
/// # Errors
///
/// - [`LockNetError::SessionExpired`] on HTTP 401 (refresh token rejected).
/// - [`LockNetError::InvalidResponse`] on any other non-200 status.
/// - [`LockNetError::Http`] on transport failure.
pub async fn refresh(
    config: &LockNetConfig,
    http: &reqwest::Client,
    refresh_jwt: &str,
) -> Result<RefreshResponse> {
    let url = config.endpoint("/api/v1/auth/refresh");
    let resp = http
        .post(&url)
        .json(&json!({ "refresh_token": refresh_jwt }))
        .send()
        .await?;
    match resp.status().as_u16() {
        200 => Ok(resp.json::<RefreshResponse>().await?),
        401 => Err(LockNetError::SessionExpired),
        s => {
            let body = resp.text().await.unwrap_or_default();
            Err(LockNetError::InvalidResponse(format!(
                "refresh: HTTP {s}: {body}"
            )))
        }
    }
}
