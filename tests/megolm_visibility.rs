//! `MegolmRotationVisibility` policy enforcement.
//!
//! The policy controls **who receives a Megolm key when the session is
//! rotated** (including the initial `Chat::send` fan-out). Enforced by
//! `fan_out_group_key` in `api/high/group_key.rs`, which is called from
//! `Chat::send` and from `process_event` on membership changes.
//!
//! Three values:
//!
//! - **AllMembers** — fan-out to every session of every member.
//! - **OnlyVerifiedSessions** — only to sessions whose `ed25519` is signed
//!   by the owner's SSK (session-verified).
//! - **OnlyVerifiedUsers** — only to sessions that are both
//!   session-verified and whose owner is trusted via the Web of Trust
//!   (`USK -> MSK` chain from the sender).
//!
//! What is verified:
//!
//! - `AllMembers` reaches every session, including those without CS.
//! - `OnlyVerifiedSessions` delivers to a session-verified recipient (Bob)
//!   and skips an unverified one (Charlie without CS).
//! - `OnlyVerifiedUsers` skips a session-verified recipient who has not been
//!   `USK`-verified; after the sender uploads a `USK -> MSK` signature, the
//!   recipient receives the key.
//! - After a member leaves under `OnlyVerifiedSessions`, the rotated key
//!   does not reach the departed member.
//!
//! Test pattern: the test sends a message through `Chat::send` (which
//! performs fan-out) and asserts on decryption at the peer via
//! `HighEvent::NewMessage`. `set_megolm_visibility(...)` overwrites the
//! local `GroupDataState` (bumping `version`), so the fan-out picks up the
//! new policy — the server does not enforce policies.
//!
//! Requirements:
//!
//! - Alice is the creator (she calls `Chat::send`); Bob and (in some tests)
//!   Charlie are members.
//! - Cross-signing (`setup_cs`) is only needed for the "verified" variants.
//!
//! Not covered here: `HistoryVisibility` enforcement
//! (`tests/history_visibility.rs`), WoT transitive trust
//! (`tests/trust_graph.rs`).

mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::core::policies::MegolmRotationVisibility;
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{HighEvent, LockNetLowAgent};
use tokio::sync::broadcast;

// ---- helpers ----

fn build_cs_payload(user_id: i64, keys: &CrossSigningKeysPrivate) -> CrossSigningKeys {
    let msk_pub = keys.msk_pub_b64();
    let ssk_pub = keys.ssk_pub_b64();
    let usk_pub = keys.usk_pub_b64();
    let ssk_sig = sign_b64(&keys.msk, &ssk_pub).expect("ssk sig");
    let usk_sig = sign_b64(&keys.msk, &usk_pub).expect("usk sig");

    let mut ssk_inner = HashMap::new();
    ssk_inner.insert("master".to_string(), ssk_sig);
    let mut ssk_sigs = HashMap::new();
    ssk_sigs.insert(user_id.to_string(), ssk_inner);

    let mut usk_inner = HashMap::new();
    usk_inner.insert("master".to_string(), usk_sig);
    let mut usk_sigs = HashMap::new();
    usk_sigs.insert(user_id.to_string(), usk_inner);

    CrossSigningKeys {
        master_key: CrossSigningKey {
            key: msk_pub,
            signatures: HashMap::new(),
        },
        self_signing_key: CrossSigningKey {
            key: ssk_pub,
            signatures: ssk_sigs,
        },
        user_signing_key: CrossSigningKey {
            key: usk_pub,
            signatures: usk_sigs,
        },
    }
}

async fn setup_cs(low: &LockNetLowAgent) -> CrossSigningKeysPrivate {
    let uid = low.user_id();
    let sid = low.session_id();
    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(uid, &keys))
        .await
        .expect("upload cs");
    let own_ed = {
        let acc = low.store().account().await;
        let acc = acc.lock().await;
        acc.ed25519_public_b64()
    };
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(sid, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload device sig");
    keys
}

/// Sign the target user's MSK with the signer's USK.
async fn sign_msk(
    signer_low: &LockNetLowAgent,
    signer_keys: &CrossSigningKeysPrivate,
    target_uid: i64,
) {
    let query = signer_low
        .crypto()
        .query_cross_signing_keys(vec![target_uid])
        .await
        .unwrap();
    let target_msk = query
        .get(&target_uid)
        .map(|u| u.master_key.key.clone())
        .unwrap();
    let sig = sign_b64(&signer_keys.usk, &target_msk).unwrap();
    signer_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(target_uid, sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .unwrap();
}

/// Overwrite `GroupDataState.megolm_rotation_visibility` and bump
/// `version` to defeat the anti-replay check.
async fn set_megolm_visibility(low: &LockNetLowAgent, chat_id: i64, vis: MegolmRotationVisibility) {
    use locknet_rcab::core::crypto::group_data::encrypt_group_data;
    use locknet_rcab::core::policies::GroupDataState;

    let state = low
        .store()
        .group_data_state(chat_id)
        .await
        .expect("group_data");
    let mut data = state.data.clone();
    data.version += 1;
    data.megolm_rotation_visibility = vis;
    let blob = encrypt_group_data(&data, &state.key).expect("re-encrypt");
    low.store()
        .group_data_state_put(
            chat_id,
            GroupDataState {
                key: state.key,
                data,
                blob,
            },
        )
        .await;
}

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

// ---- tests ----

/// `AllMembers` fans out to every session regardless of verification status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_members_reaches_everyone() {
    let alice = common::register_new("mv_all_a").await;
    let bob = common::register_new("mv_all_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();

    let group_id = common::setup_group_with_two(&alice, &bob, "MVAll").await;

    alice_low.megolm().create(group_id).await.expect("create");
    set_megolm_visibility(&alice_low, group_id, MegolmRotationVisibility::AllMembers).await;

    let mut bob_rx = bob_agent.subscribe();
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let sent = alice_chat.send("hello all").await.expect("send");

    let evt = wait_high(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;

    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(message.text.as_deref(), Some("hello all"));
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `OnlyVerifiedSessions`: a session-verified recipient (Bob with CS) gets
/// the key; an unverified one (Charlie without CS) does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_verified_sessions_skips_unverified() {
    let alice = common::register_new("mv_ovs_a").await;
    let bob = common::register_new("mv_ovs_b").await;
    let charlie = common::register_new("mv_ovs_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let charlie_agent = charlie.client.get_agent().expect("charlie agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    setup_cs(&bob_low).await;

    let group = alice_agent
        .create_group(
            "MVOVS",
            false,
            None,
            vec![bob.session.user_id, charlie.session.user_id],
        )
        .await
        .expect("create");

    let bob_inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group.id())
        .unwrap();
    bob_agent.accept_invite(bob_inv.id).await.unwrap();

    let charlie_low = charlie.low();
    let charlie_inv = charlie_low
        .groups()
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group_id == group.id())
        .unwrap();
    charlie_low
        .groups()
        .accept_invite(charlie_inv.id)
        .await
        .unwrap();

    alice_low.megolm().create(group.id()).await.unwrap();
    set_megolm_visibility(
        &alice_low,
        group.id(),
        MegolmRotationVisibility::OnlyVerifiedSessions,
    )
    .await;

    let mut bob_rx = bob_agent.subscribe();
    let mut charlie_rx = charlie_agent.subscribe();

    let alice_chat = alice_agent.chat(group.id()).await.unwrap();
    let sent = alice_chat.send("secret").await.unwrap();

    let evt_b = wait_high(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_b {
        assert_eq!(
            message.text.as_deref(),
            Some("secret"),
            "Bob must decrypt (session-verified)"
        );
    }

    let evt_c = wait_high(
        &mut charlie_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_c {
        assert_eq!(message.text, None, "Charlie must not decrypt (no CS)");
    }

    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}

/// `OnlyVerifiedUsers`: Bob has CS (session-verified) but no `USK -> MSK`
/// signature from Alice, so he is not user-verified and receives no key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_verified_users_skips_untrusted() {
    let alice = common::register_new("mv_ovu_a").await;
    let bob = common::register_new("mv_ovu_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    setup_cs(&bob_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MVOVU").await;

    alice_low.megolm().create(group_id).await.unwrap();
    set_megolm_visibility(
        &alice_low,
        group_id,
        MegolmRotationVisibility::OnlyVerifiedUsers,
    )
    .await;

    let _ = alice_agent.user_info(bob.session.user_id).await;

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group_id).await.unwrap();
    let sent = alice_chat.send("super secret").await.unwrap();

    let evt = wait_high(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;

    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(
            message.text, None,
            "Bob is not user-verified, so he cannot decrypt"
        );
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `OnlyVerifiedUsers` after Alice uploads a `USK -> MSK` signature for
/// Bob: Bob becomes user-verified and receives the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_verified_users_reaches_after_usk_signature() {
    let alice = common::register_new("mv_ovu_usk_a").await;
    let bob = common::register_new("mv_ovu_usk_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    let alice_cs = setup_cs(&alice_low).await;
    setup_cs(&bob_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MVOVUUSK").await;

    alice_low.megolm().create(group_id).await.unwrap();
    set_megolm_visibility(
        &alice_low,
        group_id,
        MegolmRotationVisibility::OnlyVerifiedUsers,
    )
    .await;

    let _ = alice_agent.user_info(bob.session.user_id).await;
    sign_msk(&alice_low, &alice_cs, bob.session.user_id).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group_id).await.unwrap();
    let sent = alice_chat.send("after usk").await.unwrap();

    let evt = wait_high(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;

    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(
            message.text.as_deref(),
            Some("after usk"),
            "Bob is now user-verified"
        );
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// After Bob leaves under `OnlyVerifiedSessions`, the post-leave rotation
/// does not reach Bob — he can decrypt pre-leave messages but not the
/// rotated one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_on_membership_respects_policy() {
    let alice = common::register_new("mv_rot_a").await;
    let bob = common::register_new("mv_rot_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    setup_cs(&bob_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MVRot").await;

    alice_low.megolm().create(group_id).await.unwrap();
    set_megolm_visibility(
        &alice_low,
        group_id,
        MegolmRotationVisibility::OnlyVerifiedSessions,
    )
    .await;

    let mut bob_rx = bob_agent.subscribe();
    let alice_chat = alice_agent.chat(group_id).await.unwrap();
    let sent = alice_chat.send("pre-leave").await.unwrap();
    let evt = wait_high(
        &mut bob_rx,
        |e| matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id),
    )
    .await;
    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(
            message.text.as_deref(),
            Some("pre-leave"),
            "Bob can read pre-leave messages"
        );
    }

    let mut alice_rx = alice_agent.subscribe();
    bob_agent.leave_chat(group_id).await.unwrap();
    let _ = wait_high(&mut alice_rx, |e| {
        matches!(e, HighEvent::GroupMembershipChanged { .. })
    })
    .await;

    let alice_chat2 = alice_agent.chat(group_id).await.unwrap();
    let sent2 = alice_chat2.send("post-leave").await.unwrap();
    let s2 = sent2
        .encrypted_payload
        .as_ref()
        .unwrap()
        .megolm_session_id
        .clone();

    assert!(
        bob_low
            .store()
            .megolm_inbound(group_id, &s2)
            .await
            .is_none(),
        "Bob must not have the key for the post-leave message"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}
