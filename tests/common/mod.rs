#![allow(dead_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use locknet_rcab::{
    Credentials, Event, LockNetClient, LockNetConfig, LockNetError, LockNetLowAgent,
    LockNetSessionContext,
};
use tokio::sync::broadcast;

pub fn base_url() -> String {
    std::env::var("LOCKNET_TEST_BASE_URL")
        .unwrap_or_else(|_| "https://localhost:8000".into())
}

pub fn space() -> String {
    std::env::var("LOCKNET_TEST_SPACE").unwrap_or_else(|_| "ts34.tech".into())
}

pub fn test_config() -> LockNetConfig {
    let mut cfg = LockNetConfig::new(&base_url(), &space()).expect("config");
    cfg.sync_on_connect = false;
    cfg
}

pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos & 0xFFFF_FFFF)
}

pub struct TestUser {
    pub client: LockNetClient,
    pub session: LockNetSessionContext,
    pub username: String,
    pub password: String,
}

impl TestUser {
    pub fn low(&self) -> std::sync::Arc<LockNetLowAgent> {
        self.client.get_low_agent().expect("low agent not started")
    }
}

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

pub fn fake_encrypted(session_id: i64, plaintext: &str) -> locknet_rcab::models::Encrypted {
    locknet_rcab::models::Encrypted {
        algorithm: "test.algorithm".into(),
        sender_key: "test_sender_key".into(),
        sender_session_id: session_id,
        megolm_session_id: format!("test-megolm-{}", unique_suffix()),
        ciphertext: base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes()),
    }
}

pub fn decode_fake(ciphertext: &str) -> String {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .expect("base64");
    String::from_utf8(bytes).expect("utf8")
}

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

pub fn assert_server_code(err: LockNetError, expected: &str) {
    match err {
        LockNetError::Server { code, message } => {
            assert_eq!(code, expected, "server code mismatch: message={message}");
        }
        other => panic!("expected Server({expected}), got {other:?}"),
    }
}