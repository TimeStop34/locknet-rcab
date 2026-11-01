use serde::Deserialize;
use serde_json::json;

use crate::core::config::LockNetConfig;
use crate::core::errors::{LockNetError, Result};

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub user_id: i64,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: i64,
}

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
            Err(LockNetError::InvalidResponse(format!("login: HTTP {s}: {body}")))
        }
    }
}

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
            "username": username,
            "password": password,
            "display_name": display_name,
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
            Err(LockNetError::InvalidResponse(format!("register: HTTP {s}: {body}")))
        }
    }
}

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
            Err(LockNetError::InvalidResponse(format!("refresh: HTTP {s}: {body}")))
        }
    }
}