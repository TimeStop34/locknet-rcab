//! Event sync and offline queue tests.
//!
//! Covers the `event_sync` WebSocket method and the `sync_until_empty`
//! convenience helper. These tests verify that:
//!
//! - Events generated while a device is offline are queued server-side.
//! - Reconnecting via [`locknet_rcab::Credentials::Session`] preserves the
//!   `session_id` and allows draining the queue.
//! - Draining happens in batches (`more` flag) and stops when the queue is
//!   empty.
//! - `message_create` and `group_invite_created` events are delivered with
//!   their original payloads intact.
//!
//! The batch size is controlled by the server (`event_sync_limit`); the
//! client's `sync_until_empty(max_iterations)` simply loops until `more` is
//! `false` or the iteration cap is reached.
//!
//! Not covered here: `HighEvent` translation (see `tests/high_events.rs`),
//! event ordering guarantees, or drop behavior on queue overflow.

mod common;

use std::time::Duration;

use locknet_rcab::{Credentials, Event, LockNetClient};

/// Bob goes offline; Alice creates three groups; Bob reconnects.
///
/// Verifies that:
/// - reconnecting via `Credentials::Session` preserves `session_id` (so the
///   queued events, keyed by session, are still addressable);
/// - `event_sync` drains the events in batches and reports `more = false`
///   when the queue is empty;
/// - the three `group_invite_created` pushes arrive with their original
///   `group_id`s;
/// - a second `event_sync` drains nothing.
#[tokio::test]
async fn events_offline_drain_and_reconnect() {
    let alice = common::register_new("ev_drain_a").await;
    let bob = common::register_new("ev_drain_b").await;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;
    let bob_rjwt = bob.session.rjwt.clone();
    let alice_low = alice.low();

    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut created_ids = Vec::new();
    for i in 0..3 {
        let g = alice_low
            .groups()
            .create(&format!("EvDrain{i}"), false, None, vec![bob_uid])
            .await
            .expect("create");
        created_ids.push(g.id);
    }

    let mut bob2 = LockNetClient::new(common::test_config());
    let s2 = bob2
        .connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("reconnect");
    assert_eq!(s2.user_id, bob_uid);
    assert_eq!(s2.session_id, bob_sid, "refresh preserves session_id");

    let bob2_low = bob2.get_low_agent().expect("low agent");
    let mut bob_rx = bob2_low.subscribe();

    let ack = bob2_low.events().sync().await.expect("sync");
    assert!(ack.sent >= 3, "expected >=3 events, got {}", ack.sent);
    assert!(!ack.more, "3 events < 200, so `more` must be false");

    let mut invite_count = 0;
    for _ in 0..60 {
        match tokio::time::timeout(Duration::from_millis(80), bob_rx.recv()).await {
            Ok(Ok(Event::GroupInviteCreated(e))) => {
                assert!(
                    created_ids.contains(&e.group_id),
                    "unexpected group_id {}",
                    e.group_id
                );
                invite_count += 1;
                if invite_count == 3 {
                    break;
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(invite_count, 3, "expected 3 group_invite_created events");

    let invites = bob2_low.groups().invites().await.expect("invites");
    let bob_invites: Vec<_> = invites
        .iter()
        .filter(|i| created_ids.contains(&i.group_id))
        .collect();
    assert_eq!(bob_invites.len(), 3);

    let ack2 = bob2_low.events().sync().await.expect("sync2");
    assert_eq!(ack2.sent, 0);
    assert!(!ack2.more);

    bob2.disconnect().await.ok();
    let mut alice = alice;
    alice.client.disconnect().await.ok();
}

/// Verifies that [`locknet_rcab::api::low::helpers::events::LockNetEventsHelper::sync_until_empty`]
/// drains the queue correctly across multiple batches and reports the total
/// number of delivered events.
///
/// Two groups → `total >= 2` on the first call, `0` on the second.
#[tokio::test]
async fn events_sync_until_empty_helper() {
    let alice = common::register_new("ev_sue_a").await;
    let bob = common::register_new("ev_sue_b").await;
    let bob_uid = bob.session.user_id;
    let bob_rjwt = bob.session.rjwt.clone();
    let alice_low = alice.low();

    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    for i in 0..2 {
        alice_low
            .groups()
            .create(&format!("EvSUE{i}"), false, None, vec![bob_uid])
            .await
            .expect("create");
    }

    let mut bob2 = LockNetClient::new(common::test_config());
    bob2.connection_request(Credentials::Session {
        refresh_jwt: bob_rjwt,
    })
    .await
    .expect("reconnect");

    let bob2_low = bob2.get_low_agent().expect("low agent");

    let total = bob2_low
        .events()
        .sync_until_empty(10)
        .await
        .expect("sync_until_empty");
    assert!(total >= 2, "expected >=2 events total, got {}", total);

    let total2 = bob2_low
        .events()
        .sync_until_empty(10)
        .await
        .expect("sync2");
    assert_eq!(total2, 0, "a second sync_until_empty must return 0");

    bob2.disconnect().await.ok();
    let mut alice = alice;
    alice.client.disconnect().await.ok();
}

/// Bob is offline while Alice sends two messages. Upon reconnection, the
/// queued `message_create` events are drained, and the messages appear in
/// `get_messages` (the queue and the history are consistent).
#[tokio::test]
async fn events_message_queue_offline() {
    let alice = common::register_new("ev_msg_a").await;
    let bob = common::register_new("ev_msg_b").await;
    let bob_rjwt = bob.session.rjwt.clone();

    let group_id = common::setup_group_with_two(&alice, &bob, "EvMsg").await;

    let alice_low = alice.low();

    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut msg_ids = Vec::new();
    for i in 0..2 {
        let ack = alice_low
            .messages()
            .send(
                group_id,
                common::fake_encrypted(alice.session.session_id, &format!("off{i}")),
            )
            .await
            .expect("send");
        msg_ids.push(ack.message_id);
    }

    let mut bob2 = LockNetClient::new(common::test_config());
    bob2.connection_request(Credentials::Session {
        refresh_jwt: bob_rjwt,
    })
    .await
    .expect("reconnect");

    let bob2_low = bob2.get_low_agent().expect("low agent");
    let mut bob_rx = bob2_low.subscribe();

    let ack = bob2_low.events().sync().await.expect("sync");
    assert!(ack.sent >= 2, "expected >=2 events, got {}", ack.sent);

    let mut received = Vec::new();
    for _ in 0..60 {
        match tokio::time::timeout(Duration::from_millis(80), bob_rx.recv()).await {
            Ok(Ok(Event::MessageCreate(m))) => {
                if msg_ids.contains(&m.message_id) {
                    received.push(m.message_id);
                    if received.len() == 2 {
                        break;
                    }
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(received.len(), 2, "expected 2 message_create events");

    let page = bob2_low
        .messages()
        .get(group_id, None, 20)
        .await
        .expect("get");
    for id in &msg_ids {
        assert!(
            page.messages.iter().any(|m| m.message_id == *id),
            "message {id} not in history"
        );
    }

    bob2.disconnect().await.ok();
    let mut alice = alice;
    alice.client.disconnect().await.ok();
}