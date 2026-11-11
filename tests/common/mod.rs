//! Shared helpers for the integration test suite.
//!
//! Every test binary depends on `common`. The helpers fall into four groups:
//!
//! - **Bootstrap** — [`register_new`], [`test_config`], [`base_url`], [`space`]:
//!   create a fresh client, register a user, and return a [`TestUser`].
//! - **Wire mocking** — [`fake_encrypted`], [`decode_fake`]: build fake
//!   [`locknet_rcab::models::Encrypted`] payloads whose plaintext is base64,
//!   without involving real Megolm. Useful for tests that exercise routing
//!   and server validation rather than E2EE.
//! - **Event waiting** — [`wait_event`]: block until an [`Event`] matching a
//!   predicate arrives on a broadcast channel.
//! - **Assertions** — [`assert_server_code`]: assert that an error is
//!   [`LockNetError::Server`] with a specific machine-readable code.
//!
//! Most helpers call `expect(...)` and are therefore **not suitable for
//! production code** — they abort the test on failure. That is deliberate:
//! a failed setup should produce a readable panic at the call site, not a
//! silent `None` deep inside the test body.
//!
//! [`LockNetError::Server`]: locknet_rcab::LockNetError::Server

#![allow(dead_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use locknet_rcab::{
    Credentials, Event, LockNetClient, LockNetConfig, LockNetError, LockNetLowAgent,
    LockNetSessionContext,
};
use tokio::sync::broadcast;

/// Base URL of the test server.
///
/// Reads `LOCKNET_TEST_BASE_URL`; defaults to `https://localhost:8000`.
/// Override when running the server on a non-default port or host.
pub fn base_url() -> String {
    std::env::var("LOCKNET_TEST_BASE_URL")
        .unwrap_or_else(|_| "https://localhost:8000".into())
}

/// Server namespace (`SPACE` setting).
///
/// Reads `LOCKNET_TEST_SPACE`; defaults to `ts34.tech`. Must match the
/// server's `SPACE` — a mismatch causes JWT rejection.
pub fn space() -> String {
    std::env::var("LOCKNET_TEST_SPACE").unwrap_or_else(|_| "ts34.tech".into())
}

/// A [`LockNetConfig`] tuned for integration tests.
///
/// Differences from the production default:
///
/// - `sync_on_connect = false` — tests that exercise `event_sync` do it
///   explicitly, so we don't drain the queue before the test can inspect it.
/// - `default_history_visibility = AllVerifiedSessions` — more permissive
///   than production (`AfterJoin`), so tests that don't exercise policies
///   can still share history between sessions without extra setup. Tests
///   that **do** exercise policies override this field locally.
/// - `default_megolm_rotation_visibility = AllMembers` — same reasoning:
///   most tests don't set up cross-signing for all participants.
pub fn test_config() -> LockNetConfig {
    let mut cfg = LockNetConfig::new(&base_url(), &space()).expect("config");
    cfg.sync_on_connect = false;
    cfg.default_history_visibility = locknet_rcab::HistoryVisibility::AllVerifiedSessions;
    cfg.default_megolm_rotation_visibility = locknet_rcab::MegolmRotationVisibility::AllMembers;
    cfg.accept_invalid_certs = true;
    cfg
}

/// A short, almost-unique suffix for usernames and public IDs.
///
/// Derived from the current time in nanoseconds, truncated to 32 bits.
/// Collisions are possible in theory (two calls in the same nanosecond), but
/// in practice each test runs in its own process or thread and the
/// registration endpoint would reject a duplicate username — surfacing the
/// collision as a `register failed: username_taken` panic, not a silent
/// cross-test bleed.
pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos & 0xFFFF_FFFF)
}

/// A registered user with their client and session context.
///
/// Produced by [`register_new`]; the registration path is used (not login)
/// so that the client also uploads 50 one-time keys and can immediately act
/// as a Megolm sender.
pub struct TestUser {
    /// The [`LockNetClient`] this user is authenticated through.
    pub client: LockNetClient,
    /// The session context returned by `connection_request`.
    pub session: LockNetSessionContext,
    /// The username used for registration (needed for re-login in multi-device
    /// tests).
    pub username: String,
    /// The password used for registration.
    pub password: String,
}

impl TestUser {
    /// The low-level agent, or panic if the client is not connected.
    ///
    /// Most tests use the low-level API directly because it is more explicit
    /// about which requests are sent. High-level tests use
    /// [`LockNetClient::get_agent`] instead.
    pub fn low(&self) -> std::sync::Arc<LockNetLowAgent> {
        self.client.get_low_agent().expect("low agent not started")
    }
}

/// Register a new user with a unique username and password `secret123`.
///
/// `prefix` is prepended to the username (useful for grepping logs). The
/// user is registered via [`Credentials::Register`], which means the client
/// also generates and uploads 50 one-time keys as a side effect.
///
/// # Panics
///
/// Panics if registration fails for any reason (network, name collision, etc.).
/// Use this only when the registration is guaranteed to succeed — typically
/// the setup phase of a test.
pub async fn register_new(prefix: &str) -> TestUser {
    let username = format!("{}_{}", prefix, unique_suffix());
    let password = "secret123".to_string();
    let mut client = LockNetClient::new(test_config());

    let session = client
        .connection_request(Credentials::Register {
            username: username.clone(),
            password: password.clone(),
            display_name: Some(username.clone()),
        })
        .await
        .unwrap_or_else(|e| panic!("register({username}) failed: {e:?}"));

    TestUser { client, session, username, password }
}

/// Build a fake [`locknet_rcab::models::Encrypted`] payload.
///
/// The result has `algorithm = "test.algorithm"` (not a real algorithm), so
/// the server will **store** it but the client will never try to decrypt it.
/// `ciphertext` is the base64 of `plaintext` in UTF-8; use [`decode_fake`]
/// to recover the original string when asserting on push payloads.
///
/// `session_id` must match the sender's session ID, otherwise the server
/// rejects the request with `session_mismatch` — the server rewrites
/// `sender_key` and `sender_session_id` from the authenticated session but
/// validates that they match what the client sent.
pub fn fake_encrypted(session_id: i64, plaintext: &str) -> locknet_rcab::models::Encrypted {
    locknet_rcab::models::Encrypted {
        algorithm: "test.algorithm".into(),
        sender_key: "test_sender_key".into(),
        sender_session_id: session_id,
        megolm_session_id: format!("test-megolm-{}", unique_suffix()),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes()),
    }
}

/// Recover the plaintext embedded by [`fake_encrypted`].
///
/// # Panics
///
/// Panics if `ciphertext` is not valid base64 or not valid UTF-8.
pub fn decode_fake(ciphertext: &str) -> String {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .expect("base64");
    String::from_utf8(bytes).expect("utf8")
}

/// Block until an [`Event`] matching `pred` arrives on `rx`.
///
/// Polls for up to **4 seconds** (40 × 100 ms) before giving up. The short
/// poll interval means we do not miss events that arrive between checks:
/// `broadcast::Receiver::recv` is itself a future, so we can simply await it
/// with a timeout and loop on mismatch.
///
/// Non-matching events are consumed and discarded — the predicate is the only
/// filter. If a test needs to inspect several different events, call this
/// multiple times with different predicates, or use
/// `tokio::sync::broadcast::Receiver` directly.
///
/// Lagged receivers are tolerated (the broadcast buffer is 1024; a slow
/// consumer that misses events logs a warning from the runner but does not
/// break the test).
///
/// # Panics
///
/// Panics on timeout (the test would otherwise hang), or if the channel is
/// closed (the runner died).
pub async fn wait_event<F>(rx: &mut broadcast::Receiver<Event>, pred: F) -> Event
where
    F: Fn(&Event) -> bool,
{
    for _ in 0..40 {
        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(evt)) if pred(&evt) => return evt,
            Ok(Ok(_)) => continue,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => panic!("channel closed"),
            Err(_) => continue,
        }
    }
    panic!("timeout waiting for event");
}

/// Create a private group `name`, invite `bob`, and have `bob` accept.
///
/// Returns the group ID. Leaves both users as members (the only members).
/// The group's policy is set from [`test_config`] defaults
/// (`AllVerifiedSessions` / `AllMembers`); tests that need stricter policies
/// override them via `group_data_state_put`.
///
/// # Panics
///
/// Panics if creation, invite listing, or acceptance fails — this is a setup
/// helper; a failure here means the test server is misbehaving or a previous
/// test left state behind.
pub async fn setup_group_with_two(alice: &TestUser, bob: &TestUser, name: &str) -> i64 {
    let alice_low = alice.low();
    let bob_low = bob.low();

    let group = alice_low
        .groups()
        .create(name, false, None, vec![bob.session.user_id])
        .await
        .expect("create_group");

    let invites = bob_low.groups().invites().await.expect("invites");
    let inv = invites
        .iter()
        .find(|i| i.group_id == group.id)
        .expect("invite not found");

    bob_low
        .groups()
        .accept_invite(inv.id)
        .await
        .expect("accept_invite");

    group.id
}

/// Assert that `err` is [`LockNetError::Server`] with `expected` as the
/// machine-readable `code`.
///
/// # Panics
///
/// Panics if `err` is not a `Server` variant, or if the code differs. The
/// panic message includes the human-readable `message` from the server, which
/// usually explains *why* the code is different (rate-limited, not found,
/// etc.).
pub fn assert_server_code(err: LockNetError, expected: &str) {
    match err {
        LockNetError::Server { code, message } => {
            assert_eq!(code, expected, "server code mismatch: message={message}");
        }
        other => panic!("expected Server({expected}), got {other:?}"),
    }
}