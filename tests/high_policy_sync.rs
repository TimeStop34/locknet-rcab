//! Policy sync between the creator and the server-side blob.
//!
//! The group policy ([`locknet_rcab::core::policies::GroupData`]) is
//! encrypted client-side with a `group_data_key` and stored on the server as
//! an opaque `encrypted_group_data` blob. Only the **creator** can update the
//! blob; other members can read it (after decrypting with the key received
//! via `ln.encryption.group_key`).
//!
//! Lifecycle rules implemented by the high layer:
//!
//! 1. **New group** — the creator has not created a Megolm session yet, so
//!    the server blob is `None`.
//! 2. **Creator's first `Chat::send`** — creates a Megolm session, which
//!    also creates `GroupDataState` and uploads the encrypted blob via
//!    `update_group_data` (server-side, creator-only).
//! 3. **Non-creator with no policy** — if a member (Bob) has no local
//!    `GroupDataState` and the server has not given them a policy yet,
//!    `Chat::send` returns `InvalidArgument("policy unknown")`. The user
//!    must recover the policy (via `key_request` from the creator, or by
//!    receiving a fresh `group_key`).
//! 4. **Non-creator `update_group_data`** — the server rejects with
//!    `not_creator`.
//!
//! What is verified:
//!
//! - Creator uploads the policy blob after the first send.
//! - Creator's `encrypted_group_data` matches the local blob exactly.
//! - A new device of the creator that has not decrypted the blob cannot
//!   send (server has `Some(blob)`, local state is `None`).
//! - Bob (non-creator) is rejected when trying to update the policy blob.
//!
//! Requirements:
//!
//! - The group is private (`create_group` with `is_public = false`).
//! - Bob must accept the invite before Alice sends the first message, so
//!   the fan-out includes him.
//!
//! Not covered here: policy-driven key sharing decisions
//! (`tests/history_visibility.rs`, `tests/megolm_visibility.rs`).

mod common;

use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creator_uploads_policy_after_first_send() {
    let alice = common::register_new("ps_upload_a").await;
    let bob = common::register_new("ps_upload_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_low = alice_agent.low();

    let group = alice_agent
        .create_group("PSUpload", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    let info_before = alice_low.groups().info(group_id).await.expect("info");
    assert!(
        info_before.encrypted_group_data.is_none(),
        "new group must not have an encrypted_group_data blob yet"
    );

    let alice_chat = alice_agent.chat(group_id).await.expect("chat");
    let _ = alice_chat.send("hello").await.expect("send");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let info_after = alice_low.groups().info(group_id).await.expect("info");
    assert!(
        info_after.encrypted_group_data.is_some(),
        "the creator must upload encrypted_group_data after the first send"
    );

    let local_state = alice_low
        .store()
        .group_data_state(group_id)
        .await
        .expect("state");
    assert_eq!(
        info_after.encrypted_group_data.as_deref(),
        Some(local_state.blob.as_str()),
        "server blob must match the local blob"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// A new device of the creator cannot send until it decrypts the policy
/// blob.
///
/// Setup: Alice1 creates a group, Bob accepts, Alice1 sends a message (the
/// server now has a policy blob). Alice2 logs in with `Credentials::Login`
/// (fresh session, empty local store), joins the group via fan-out on
/// subsequent messages, and tries to send. Since Alice2 has no local
/// `GroupDataState` and the server already has a blob (which Alice2 cannot
/// decrypt without receiving the `group_data_key`), `Chat::send` refuses.
///
/// Alice2 recovers by requesting keys (not exercised here), which delivers
/// the `group_data_key` and populates `GroupDataState`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_device_cannot_create_policy_when_server_has_blob() {
    let alice = common::register_new("ps_newdev_a").await;
    let bob = common::register_new("ps_newdev_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");

    let group = alice_agent
        .create_group("PSNewDev", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("inv");
    bob_agent.accept_invite(inv.id).await.expect("accept");

    let alice_chat = alice_agent.chat(group_id).await.expect("chat");
    let _ = alice_chat.send("hello").await.expect("send");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut alice2_client = locknet_rcab::LockNetClient::new(common::test_config());
    let alice2_session = alice2_client
        .connection_request(locknet_rcab::Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    assert_eq!(alice2_session.user_id, alice.session.user_id);

    let alice2_agent = alice2_client.get_agent().expect("alice2 agent");
    let alice2_chat = alice2_agent.chat(group_id).await.expect("chat");

    let err = alice2_chat.send("hacked").await.unwrap_err();
    match err {
        locknet_rcab::LockNetError::InvalidArgument(msg) => {
            assert!(
                msg.contains("server has group policy blob") || msg.contains("policy unknown"),
                "unexpected error: {msg}"
            );
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Only the group creator can update the encrypted policy blob. Bob (a
/// regular member) calling `update_group_data` receives `not_creator`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_creator_can_update_policy_blob() {
    let alice = common::register_new("ps_upd_a").await;
    let bob = common::register_new("ps_upd_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_low = bob_agent.low();

    let group = alice_agent
        .create_group("PSUpd", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("inv");
    bob_agent.accept_invite(inv.id).await.expect("accept");

    let err = bob_low
        .groups()
        .update_group_data(group_id, "AAAA")
        .await
        .unwrap_err();
    common::assert_server_code(err, "not_creator");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}