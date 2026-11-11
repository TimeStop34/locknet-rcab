//! Authentication tests.
//!
//! Cover the three [`locknet_rcab::Credentials`] variants (`Register`,
//! `Login`, `Session`) and the corresponding `connection_request`
//! behaviours:
//!
//! - Fresh registration returns a valid token pair and positive user/session
//!   IDs, matching the configured `space`.
//! - `Login` creates a **new** session for the same user (devices are
//!   per-login, not shared).
//! - Wrong credentials fail with `InvalidCredentials` (not a transport or
//!   parse error — the HTTP handler maps 401 to that variant).
//! - Duplicate username registration fails with `username_taken` (HTTP 409
//!   mapped to `LockNetError::Server`).
//! - `Session` (refresh JWT) reuses the existing `session_id` and populates
//!   the low-level agent.
//! - `disconnect()` drops the low-level agent and the session context.
//!
//! All tests assert on the [`locknet_rcab::LockNetSessionContext`] returned
//! by `connection_request` and on what the client exposes via
//! `get_low_agent()` / `session()`.
//!
//! Not covered here: WebSocket reconnect after disconnect
//! (`tests/reconnect.rs`), the runner's internal automatic reconnect on
//! network failure (unit-tested in `src/core/runner.rs`).

mod common;

use locknet_rcab::{Credentials, LockNetClient, LockNetError};

/// Registering a fresh user returns non-empty tokens, positive user and
/// session IDs, the expected `space`, and a connected client (low-level
/// agent + session context both present).
#[tokio::test]
async fn register_returns_session() {
    let user = common::register_new("auth_reg").await;

    assert!(user.session.user_id > 0);
    assert!(user.session.session_id > 0);
    assert!(!user.session.ajwt.is_empty());
    assert!(!user.session.rjwt.is_empty());
    assert_eq!(user.session.space, common::space());

    assert!(user.client.get_low_agent().is_some());
    assert!(user.client.session().is_some());
}

/// Logging in with the same username/password succeeds, keeps the user ID,
/// and creates a **new** session ID.
#[tokio::test]
async fn login_creates_new_session_for_same_user() {
    let mut user = common::register_new("auth_login").await;
    let first_uid = user.session.user_id;
    let first_sid = user.session.session_id;

    let mut c = LockNetClient::new(common::test_config());
    let s = c
        .connection_request(Credentials::Login {
            username: user.username.clone(),
            password: user.password.clone(),
        })
        .await
        .expect("login");

    assert_eq!(s.user_id, first_uid, "same user");
    assert_ne!(s.session_id, first_sid, "new session per login");
    assert_eq!(s.space, common::space());

    c.disconnect().await.expect("disconnect");
    user.client.disconnect().await.ok();
}

/// Wrong password returns [`LockNetError::InvalidCredentials`], not a
/// transport or parse error.
#[tokio::test]
async fn login_wrong_password_fails() {
    let mut user = common::register_new("auth_wrongpw").await;

    let mut c = LockNetClient::new(common::test_config());
    let err = c
        .connection_request(Credentials::Login {
            username: user.username.clone(),
            password: "definitely-wrong".into(),
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, LockNetError::InvalidCredentials),
        "expected InvalidCredentials, got {err:?}"
    );

    user.client.disconnect().await.ok();
}

/// Registering an already-taken username fails with server code
/// `username_taken`.
#[tokio::test]
async fn register_duplicate_username_fails() {
    let mut user = common::register_new("auth_dup").await;

    let mut c = LockNetClient::new(common::test_config());
    let err = c
        .connection_request(Credentials::Register {
            username: user.username.clone(),
            password: "whatever".into(),
            display_name: None,
        })
        .await
        .unwrap_err();

    common::assert_server_code(err, "username_taken");

    user.client.disconnect().await.ok();
}

/// Reconnecting via `Credentials::Session` (refresh JWT) keeps the existing
/// `session_id` rather than creating a new one.
#[tokio::test]
async fn session_credentials_reuse_existing_session() {
    let user = common::register_new("auth_sess").await;
    let uid = user.session.user_id;
    let sid = user.session.session_id;
    let rjwt = user.session.rjwt.clone();

    let mut c = LockNetClient::new(common::test_config());
    let s = c
        .connection_request(Credentials::Session { refresh_jwt: rjwt })
        .await
        .expect("session");

    assert_eq!(s.user_id, uid);
    assert_eq!(s.session_id, sid, "refresh keeps the same session_id");

    let low = c.get_low_agent().expect("low agent");
    assert_eq!(low.user_id(), uid);
    assert_eq!(low.session_id(), sid);

    c.disconnect().await.expect("disconnect");
    assert!(c.get_low_agent().is_none());
    assert!(c.session().is_none());

    let mut user = user;
    user.client.disconnect().await.ok();
}

/// `disconnect()` drops the low-level agent and the session context. Safe to
/// call even after the test has already exercised the connection.
#[tokio::test]
async fn disconnect_clears_state() {
    let mut user = common::register_new("auth_disc").await;

    assert!(user.client.get_low_agent().is_some());
    assert!(user.client.session().is_some());

    user.client.disconnect().await.expect("disconnect");

    assert!(user.client.get_low_agent().is_none());
    assert!(user.client.session().is_none());
}
