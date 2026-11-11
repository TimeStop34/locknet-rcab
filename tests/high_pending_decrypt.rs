//! `HighEvent::MessageDecrypted` — deferred decryption for pending messages.
//!
//! When a message arrives **before** its Megolm key, the receiver cannot
//! decrypt it. The high layer:
//!
//! 1. Stores the message in `state.messages` with `text = None`.
//! 2. Records its id in `state.pending_decrypt[chat_id]`.
//!
//! When the key arrives later (via `ln.encryption.group_key`), the high
//! layer:
//!
//! 3. Retries decryption for all pending ids of that chat.
//! 4. On success, updates `state.messages[id].text` and emits
//!    `HighEvent::MessageDecrypted { chat_id, message_id, text }`.
//!
//! What is verified:
//!
//! - The pending message can be read via `Chat::messages()` with
//!   `text = None` before the key arrives.
//! - After fan-out, `MessageDecrypted` fires for each pending message
//!   (both single and multiple pending messages).
//! - After the event fires, `Chat::messages()` returns the plaintext.
//!
//! Requirements:
//!
//! - A group via `setup_group_with_two`.
//! - The test bypasses `Chat::send` on Alice's side: it uses low-level
//!   `megolm().create` + `encrypt` + `messages().send()` **without**
//!   fan-out, so Bob does not have the key yet.
//!
//! Not covered here: policy checks that gate key delivery
//! (`tests/history_visibility.rs`), the `key_request` path
//! (`tests/high_key_request.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::HighEvent;
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

/// A message that arrives before its key is decrypted lazily: `text = None`
/// in the first `messages()` call, then after fan-out `MessageDecrypted`
/// fires and `text` becomes `Some(...)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn message_decrypted_event_after_group_key() {
    let alice = common::register_new("md_a").await;
    let bob = common::register_new("md_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();

    let group_id = common::setup_group_with_two(&alice, &bob, "MD").await;

    let info = alice_low.megolm().create(group_id).await.expect("create");
    let enc = alice_low
        .megolm()
        .encrypt(group_id, "pending secret")
        .await
        .expect("encrypt");
    let ack = alice_low
        .messages()
        .send(group_id, enc)
        .await
        .expect("send");

    let bob_chat = bob_agent.chat(group_id).await.expect("chat");
    let history = bob_chat.messages(None, 20).await.expect("messages");
    let msg = history.iter().find(|m| m.id == ack.message_id).expect("msg");
    assert_eq!(msg.text, None, "without the key, text must be None");

    let mut bob_rx = bob_agent.subscribe();

    alice_low
        .megolm()
        .share_group_key_with_session_key(
            group_id,
            bob.session.user_id,
            bob.session.session_id,
            info.megolm_session_id.clone(),
            info.session_key.clone(),
        )
        .await
        .expect("share");

    let evt = wait_high(&mut bob_rx, |e| {
        matches!(e, HighEvent::MessageDecrypted { message_id, .. } if *message_id == ack.message_id)
    })
    .await;

    match evt {
        HighEvent::MessageDecrypted { chat_id, message_id, text } => {
            assert_eq!(chat_id, group_id);
            assert_eq!(message_id, ack.message_id);
            assert_eq!(text, "pending secret");
        }
        _ => unreachable!(),
    }

    let history2 = bob_chat.messages(None, 20).await.expect("messages 2");
    let msg2 = history2.iter().find(|m| m.id == ack.message_id).unwrap();
    assert_eq!(msg2.text.as_deref(), Some("pending secret"));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Three messages queued before the key: after fan-out, three
/// `MessageDecrypted` events fire, each with the correct plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_pending_messages_all_decrypted() {
    let alice = common::register_new("md_multi_a").await;
    let bob = common::register_new("md_multi_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();

    let group_id = common::setup_group_with_two(&alice, &bob, "MDMulti").await;

    let info = alice_low.megolm().create(group_id).await.expect("create");
    let mut ack_ids = Vec::new();
    for i in 0..3 {
        let enc = alice_low
            .megolm()
            .encrypt(group_id, &format!("msg-{i}"))
            .await
            .expect("encrypt");
        let ack = alice_low
            .messages()
            .send(group_id, enc)
            .await
            .expect("send");
        ack_ids.push(ack.message_id);
    }

    let bob_chat = bob_agent.chat(group_id).await.expect("chat");
    let history = bob_chat.messages(None, 20).await.expect("messages");
    for id in &ack_ids {
        let m = history.iter().find(|m| m.id == *id).expect("msg");
        assert_eq!(m.text, None, "msg {id}: text=None before key");
    }

    let mut bob_rx = bob_agent.subscribe();

    alice_low
        .megolm()
        .share_group_key_with_session_key(
            group_id,
            bob.session.user_id,
            bob.session.session_id,
            info.megolm_session_id.clone(),
            info.session_key.clone(),
        )
        .await
        .expect("share");

    let mut received = Vec::new();
    for _ in 0..30 {
        match tokio::time::timeout(Duration::from_millis(200), bob_rx.recv()).await {
            Ok(Ok(HighEvent::MessageDecrypted { message_id, text, .. })) => {
                if ack_ids.contains(&message_id) {
                    received.push((message_id, text));
                    if received.len() == 3 {
                        break;
                    }
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(received.len(), 3, "3 MessageDecrypted events");

    for (mid, text) in received {
        let expected_idx = ack_ids.iter().position(|id| *id == mid).unwrap();
        assert_eq!(text, format!("msg-{expected_idx}"), "plaintext for msg {mid}");
    }

    let history2 = bob_chat.messages(None, 20).await.expect("messages 2");
    for (i, id) in ack_ids.iter().enumerate() {
        let m = history2.iter().find(|m| m.id == *id).unwrap();
        assert_eq!(m.text.as_deref(), Some(format!("msg-{i}").as_str()));
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}