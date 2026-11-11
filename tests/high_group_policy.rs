//! Backup via the high-level API.
//!
//! Covers `SecurityHelper::backup_*()`. These are thin wrappers over
//! `LockNetLowAgent::backup().export/import/versions/get/delete` that
//! additionally expose `backup_export_default()` — a shortcut that generates
//! a fresh `RecoveryKey`, exports, and returns both.
//!
//! The underlying crypto (HKDF, XSalsa20-Poly1305, auth_data fingerprint) is
//! the same as in `tests/backup.rs`; this file verifies that the high-level
//! wrappers preserve the contract, in particular:
//!
//! - `backup_export_default()` returns a `RecoveryKey` whose bytes match the
//!   `auth_data.public_key` derived by `import`.
//! - A second device can recover historical messages via `backup_import`.
//! - Wrong recovery key fails at the auth_data check.
//!
//! Not covered here: low-level wire and crypto tests (`tests/backup.rs`),
//! key request recovery (`tests/high_key_request.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::{Credentials, HighEvent, LockNetClient, RecoveryKey};
use tokio::sync::broadcast;

async fn wait_high<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
where
    F: Fn(&HighEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("timeout waiting for HighEvent");
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(evt)) if pred(&evt) => return evt,
            Ok(Ok(_)) => continue,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => panic!("channel closed"),
            Err(_) => panic!("timeout"),
        }
    }
}

/// Full export/import via `SecurityHelper::backup_*`.
///
/// Verifies:
/// - `backup_export_default()` returns a non-empty version and at least one
///   uploaded item;
/// - a fresh client (Alice2) can `backup_import` with the returned key;
/// - imported sessions decrypt historical messages via `Chat::messages`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_backup_export_import_roundtrip() {
    let alice = common::register_new("hbk_a").await;
    let bob = common::register_new("hbk_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_sec = alice_agent.security();
    let group_id = common::setup_group_with_two(&alice, &bob, "HBk").await;

    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let mut bob_rx = bob_agent.subscribe();
    let sent = alice_chat.send("backup payload").await.expect("send");
    let _ = wait_high(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;

    let (recovery, export) = alice_sec
        .backup_export_default()
        .await
        .expect("export_default");
    assert!(export.version >= 1);
    assert!(
        export.items_uploaded >= 1,
        "at least one Megolm session expected"
    );

    let mut alice2_client = LockNetClient::new(common::test_config());
    let alice2_session = alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    assert_eq!(alice2_session.user_id, alice.session.user_id);

    let alice2_agent = alice2_client.get_agent().expect("alice2 agent");
    let alice2_sec = alice2_agent.security();
    let alice2_chat = alice2_agent.chat(group_id).await.expect("alice2 chat");

    let unread = alice2_chat
        .messages(None, 20)
        .await
        .expect("alice2 messages");
    let msg_unread = unread
        .iter()
        .find(|m| m.id == sent.id)
        .expect("msg in history");
    assert_eq!(msg_unread.text, None, "without the key, text is None");

    let import = alice2_sec
        .backup_import(export.version, &recovery)
        .await
        .expect("import");
    assert_eq!(import.version, export.version);
    assert!(import.sessions_imported >= 1);

    let read = alice2_chat
        .messages(None, 20)
        .await
        .expect("alice2 messages #2");
    let msg_read = read.iter().find(|m| m.id == sent.id).expect("msg #2");
    assert_eq!(msg_read.text.as_deref(), Some("backup payload"));

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Importing with the wrong recovery key fails with `InvalidArgument` and
/// mentions the recovery key (the auth_data check runs first).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_backup_wrong_recovery_key_fails() {
    let alice = common::register_new("hbkw_a").await;
    let bob = common::register_new("hbkw_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_sec = alice_agent.security();
    let group_id = common::setup_group_with_two(&alice, &bob, "HBkW").await;

    let chat = alice_agent.chat(group_id).await.expect("chat");
    let _ = chat.send("payload").await.expect("send");

    let (_recovery, export) = alice_sec.backup_export_default().await.expect("export");

    let mut alice2_client = LockNetClient::new(common::test_config());
    alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    let alice2_agent = alice2_client.get_agent().expect("alice2 agent");
    let alice2_sec = alice2_agent.security();

    let wrong = RecoveryKey::generate().expect("RNG");
    let err = alice2_sec
        .backup_import(export.version, &wrong)
        .await
        .unwrap_err();
    match err {
        locknet_rcab::LockNetError::InvalidArgument(msg) => {
            assert!(msg.contains("recovery key"), "unexpected message: {msg}");
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `backup_versions()` returns all created versions; `backup_delete(v)`
/// removes one without affecting the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_backup_versions_and_delete() {
    let alice = common::register_new("hbkv_a").await;
    let bob = common::register_new("hbkv_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_sec = alice_agent.security();
    let group_id = common::setup_group_with_two(&alice, &bob, "HBkV").await;

    let chat = alice_agent.chat(group_id).await.expect("chat");
    let _ = chat.send("v1").await.expect("send");

    let (_rk1, e1) = alice_sec.backup_export_default().await.expect("export1");
    let (_rk2, e2) = alice_sec.backup_export_default().await.expect("export2");
    assert!(e2.version > e1.version);

    let versions = alice_sec.backup_versions().await.expect("versions");
    assert_eq!(versions.len(), 2);

    alice_sec.backup_delete(e1.version).await.expect("delete");

    let versions = alice_sec.backup_versions().await.expect("versions");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version, e2.version);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}
