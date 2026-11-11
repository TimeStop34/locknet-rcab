//! `Chat::send` — high-level fan-out and rotation semantics.
//!
//! `Chat::send` on an **encrypted** chat does more than the low-level
//! `messages().send()`:
//!
//! 1. `megolm().ensure_session()` — reuses the existing Megolm session or
//!    creates one (rotating if a rotation threshold was crossed).
//! 2. Fan-out the group key (`ln.encryption.group_key`) to every active
//!    session of every group member except the sender's current session.
//! 3. Encrypt the plaintext and send it.
//!
//! On a **public** chat, `Chat::send` uses `ln.plaintext.v1`: the
//! ciphertext is `base64(plaintext)` and the server stores it as is.
//!
//! Rotation on membership change: when a member joins or leaves,
//! `process_event` rotates the Megolm session **before** emitting
//! `GroupMembershipChanged`. The new key is fanned out only to the new
//! membership, so a user who just left never receives the post-leave
//! session.
//!
//! What is verified:
//!
//! - Alice `Chat::send` → Bob decrypts via `HighEvent::NewMessage` and via
//!   history.
//! - Fan-out reaches every session of every member (Alice + Bob + Charlie).
//! - After Bob leaves, the Megolm session rotates; Bob keeps the old session
//!   (so old messages remain decryptable for him) but never gets the new
//!   one.
//! - Public groups use plaintext: `encrypted == false`, text matches the
//!   plaintext, and `process_event` skips decryption.
//!
//! Requirements:
//!
//! - A group via `setup_group_with_two` (or `create_group` when three
//!   members are needed).
//! - No `setup_olm` needed — fan-out uses `share_group_key` which creates
//!   the Olm session on the fly.
//!
//! Not covered here: auto-rotation by TTL / message count
//! (`tests/megolm_auto_rotation.rs`), fan-out policy filters
//! (`tests/megolm_visibility.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::HighEvent;
use tokio::sync::broadcast;

async fn wait_high_event<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
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
            Err(_) => panic!("timeout waiting for HighEvent"),
        }
    }
}

/// Alice sends a private message via `Chat::send`; Bob receives a
/// decrypted `HighEvent::NewMessage` and sees the message in history.
///
/// Verifies that `Chat::send` performs the whole pipeline (ensure session,
/// fan-out, encrypt, send) without exposing the low-level details to the
/// caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_sends_bob_decrypts_via_high() {
    let alice = common::register_new("hs_ab_a").await;
    let bob = common::register_new("hs_ab_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HS_AB").await;

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let sent = alice_chat.send("hello through high").await.expect("send");

    assert!(sent.encrypted);
    assert_eq!(sent.text.as_deref(), Some("hello through high"));

    let evt = wait_high_event(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;

    match evt {
        HighEvent::NewMessage { chat, message } => {
            assert_eq!(chat.id(), group_id);
            assert_eq!(message.id, sent.id);
            assert_eq!(message.text.as_deref(), Some("hello through high"));
            assert!(message.encrypted);
        }
        _ => unreachable!(),
    }

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let history = bob_chat.messages(None, 20).await.expect("messages");
    let found = history
        .iter()
        .find(|m| m.id == sent.id)
        .expect("message in history");
    assert_eq!(found.text.as_deref(), Some("hello through high"));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Fan-out reaches every session of every member.
///
/// Three members (Alice, Bob, Charlie) in one group; the initial fan-out
/// must deliver the group key to Bob and Charlie, and both must decrypt the
/// same message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_sends_to_three_participants() {
    let alice = common::register_new("hs3_a").await;
    let bob = common::register_new("hs3_b").await;
    let charlie = common::register_new("hs3_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let charlie_agent = charlie.client.get_agent().expect("charlie agent");

    let group = alice_agent
        .create_group(
            "HS3",
            false,
            None,
            vec![bob.session.user_id, charlie.session.user_id],
        )
        .await
        .expect("create");

    let bob_invites = bob_agent.invites().await.expect("bob invites");
    let bob_inv = bob_invites
        .iter()
        .find(|i| i.group.id == group.id())
        .expect("bob inv");
    bob_agent
        .accept_invite(bob_inv.id)
        .await
        .expect("bob accept");

    let charlie_invites = charlie_agent.invites().await.expect("charlie invites");
    let charlie_inv = charlie_invites
        .iter()
        .find(|i| i.group.id == group.id())
        .expect("charlie inv");
    charlie_agent
        .accept_invite(charlie_inv.id)
        .await
        .expect("charlie accept");

    let alice_chat = alice_agent
        .chat(group.id())
        .await
        .expect("alice chat fresh");

    let mut bob_rx = bob_agent.subscribe();
    let mut charlie_rx = charlie_agent.subscribe();

    let sent = alice_chat.send("to everyone").await.expect("send");
    assert!(sent.encrypted);

    let evt_b = wait_high_event(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_b {
        assert_eq!(message.text.as_deref(), Some("to everyone"));
    }

    let evt_c = wait_high_event(
        &mut charlie_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_c {
        assert_eq!(message.text.as_deref(), Some("to everyone"));
    }

    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}

/// After a member leaves, the Megolm session rotates.
///
/// Verifies:
/// - S1 (pre-leave) and S2 (post-leave) have different `session_id`s;
/// - Bob still has S1 and can decrypt the pre-leave message;
/// - Bob does not have S2, so the post-leave message does not decrypt;
/// - Alice (who has both inbound sessions) decrypts everything.
///
/// Uses the low-level `bob_low.store().megolm_inbound(...)` to inspect the
/// session store directly — the API-level `bob_chat.messages()` would refuse
/// to query because Bob is no longer a member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_change_rotates_megolm() {
    let alice = common::register_new("hs_rot_a").await;
    let bob = common::register_new("hs_rot_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let _alice_low = alice.low();
    let bob_low = bob.low();

    let group_id = common::setup_group_with_two(&alice, &bob, "HS_Rot").await;

    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");

    let mut bob_rx = bob_agent.subscribe();

    let first = alice_chat.send("msg1 pre-bob-leave").await.expect("send1");
    let first_enc = first.encrypted_payload.clone().expect("first enc");
    let s1 = first_enc.megolm_session_id.clone();

    let _ = wait_high_event(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == first.id),
    )
    .await;

    let pt1 = bob_low
        .megolm()
        .decrypt(group_id, &first_enc)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pt1, "msg1 pre-bob-leave");
    assert!(
        bob_low
            .store()
            .megolm_inbound(group_id, &s1)
            .await
            .is_some(),
        "Bob must have S1"
    );

    let mut alice_rx = alice_agent.subscribe();
    bob_agent.leave_chat(group_id).await.expect("bob leave");

    let _ = wait_high_event(&mut alice_rx, |e| {
        matches!(
            e,
            HighEvent::GroupMembershipChanged {
                change: locknet_rcab::api::low::models::MembershipChange::Left,
                ..
            }
        )
    })
    .await;

    let alice_chat2 = alice_agent.chat(group_id).await.expect("alice chat fresh");
    let second = alice_chat2.send("msg2 post-bob").await.expect("send2");
    let second_enc = second.encrypted_payload.clone().expect("second enc");
    let s2 = second_enc.megolm_session_id.clone();

    assert_ne!(s1, s2, "Megolm must rotate after leave");

    assert!(
        bob_low
            .store()
            .megolm_inbound(group_id, &s2)
            .await
            .is_none(),
        "Bob must NOT have S2"
    );
    assert!(
        bob_low
            .store()
            .megolm_inbound(group_id, &s1)
            .await
            .is_some(),
        "Bob must still have S1"
    );

    let pt2 = bob_low
        .megolm()
        .decrypt(group_id, &second_enc)
        .await
        .unwrap();
    assert!(pt2.is_none(), "Bob must not decrypt msg2");

    let pt1_again = bob_low
        .megolm()
        .decrypt(group_id, &first_enc)
        .await
        .unwrap();
    assert_eq!(pt1_again.as_deref(), Some("msg1 pre-bob-leave"));

    let alice_hist = alice_chat2.messages(None, 20).await.expect("alice history");
    assert!(alice_hist
        .iter()
        .any(|m| m.text.as_deref() == Some("msg1 pre-bob-leave")));
    assert!(alice_hist
        .iter()
        .any(|m| m.text.as_deref() == Some("msg2 post-bob")));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Public groups use plaintext: `encrypted == false` in the returned
/// `Message`, and the receiving side sees the text without any Megolm
/// involvement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_group_uses_plaintext() {
    let alice = common::register_new("hs_pub_a").await;
    let bob = common::register_new("hs_pub_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");

    let public_id = format!("&hspub{}", common::unique_suffix());
    let group = alice_agent
        .create_group("HS_Pub", true, Some(public_id.clone()), vec![])
        .await
        .expect("create public");

    bob_agent.join_group(public_id).await.expect("bob join");

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group.id()).await.expect("alice chat");
    let sent = alice_chat.send("plaintext hello").await.expect("send");

    assert!(!sent.encrypted, "public groups use plaintext");

    let evt = wait_high_event(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;

    match evt {
        HighEvent::NewMessage { message, .. } => {
            assert_eq!(message.text.as_deref(), Some("plaintext hello"));
            assert!(!message.encrypted);
        }
        _ => unreachable!(),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}
