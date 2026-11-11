//! SAS via the high-level API.
//!
//! Covers `SecurityHelper::sas_*()` (the high-level flow built on top of
//! `LockNetLowAgent::verification().sas_*()`). Differences from the
//! low-level `tests/sas.rs`:
//!
//! - The flow is stored in `state.active_sas` keyed by `transaction_id`,
//!   and initiated/responded through `security().sas_start` /
//!   `security().sas_accept`.
//! - Incoming `ln.encryption.key.verification.start` is **not** auto-accepted;
//!   it lands in `state.pending_sas_starts`. The UI must call `sas_accept` or
//!   `sas_decline`. This gate gives the user a chance to refuse before any
//!   cryptographic work.
//! - `sas_next` writes to `state.verified_users` / `verified_sessions` on
//!   `Verified` and emits `HighEvent::SessionVerified` /
//!   `HighEvent::UserVerified`.
//! - `emoji_confirm(txid, true)` resolves peer keys (`ed25519` and `msk`)
//!   from `query_keys` / `query_cross_signing_keys` automatically; the caller
//!   does not need to call `set_peer_keys`.
//!
//! What is verified:
//!
//! - Full flow (`sas_via_high_full_flow`): START via HighEvent, accept,
//!   emoji agreement, MAC verification, both sides verified, and
//!   `is_user_verified` / `is_session_verified` return true.
//! - `sas_decline` removes the pending start; a subsequent `sas_next`
//!   returns `InvalidArgument`.
//! - `sas_cancel` removes the active flow; a subsequent `sas_next` returns
//!   `InvalidArgument`.
//!
//! Not covered here: low-level flow (`tests/sas.rs`), QR
//! (`tests/high_qr.rs`), cross-signing itself
//! (`tests/cross_signing.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::{HighEvent, LockNetAgent};
use tokio::sync::broadcast;

async fn setup_cs(agent: &LockNetAgent) {
    agent
        .security()
        .setup_cross_signing()
        .await
        .expect("setup_cross_signing");
}

async fn wait_sas_message<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
where
    F: Fn(&HighEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("timeout waiting for HighEvent::SasMessage");
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

/// Full SAS flow through `SecurityHelper`.
///
/// Verifies:
/// - the initiator's START surfaces at the responder as
///   `HighEvent::SasMessage { type: start }` with matching `transaction_id`;
/// - `sas_accept` consumes the pending start and creates a responder flow;
/// - `sas_next` on both sides yields the same 7-emoji sequence;
/// - `emoji_confirm(true)` on both sides resolves peer keys automatically
///   and completes with `SasStep::Verified`;
/// - both peers are added to `state.verified_users` /
///   `state.verified_sessions`, visible via `is_user_verified` /
///   `is_session_verified`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_via_high_full_flow() {
    let alice = common::register_new("hsas_a").await;
    let bob = common::register_new("hsas_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_cs(&alice_agent).await;
    setup_cs(&bob_agent).await;

    let _group_id = common::setup_group_with_two(&alice, &bob, "HSAS").await;

    let mut bob_high_rx = bob_agent.subscribe();

    let alice_txid = alice_agent
        .security()
        .sas_start(bob_uid, bob_sid)
        .await
        .expect("alice sas_start");

    let evt = wait_sas_message(&mut bob_high_rx, |e| matches!(e, HighEvent::SasMessage { .. })).await;
    let bob_txid = match evt {
        HighEvent::SasMessage { content, .. } => {
            let t = content.get("type").and_then(|v| v.as_str()).unwrap_or("");
            assert_eq!(t, "ln.encryption.key.verification.start");
            content
                .pointer("/content/transaction_id")
                .and_then(|v| v.as_str())
                .expect("txid")
                .to_string()
        }
        _ => unreachable!(),
    };
    assert_eq!(alice_txid, bob_txid, "transaction_id must match on both sides");

    bob_agent
        .security()
        .sas_accept(&bob_txid)
        .await
        .expect("bob sas_accept");

    let alice_step = tokio::time::timeout(
        Duration::from_secs(10),
        alice_agent.security().sas_next(&alice_txid),
    )
    .await
    .expect("alice sas_next timeout")
    .expect("alice sas_next");

    let alice_emojis = match alice_step {
        locknet_rcab::SasStep::Emoji(e) => e,
        other => panic!("alice expected Emoji, got {other:?}"),
    };

    let bob_step = tokio::time::timeout(
        Duration::from_secs(10),
        bob_agent.security().sas_next(&bob_txid),
    )
    .await
    .expect("bob sas_next timeout")
    .expect("bob sas_next");

    let bob_emojis = match bob_step {
        locknet_rcab::SasStep::Emoji(e) => e,
        other => panic!("bob expected Emoji, got {other:?}"),
    };

    assert_eq!(alice_emojis.len(), 7);
    assert_eq!(bob_emojis.len(), 7);
    for (a, b) in alice_emojis.iter().zip(bob_emojis.iter()) {
        assert_eq!(a.symbol, b.symbol, "emoji mismatch");
    }

    let ag = alice_agent.security().emojis_get(&alice_txid).await.expect("alice emojis_get");
    assert!(ag.is_some());
    assert_eq!(ag.unwrap().len(), 7);

    alice_agent
        .security()
        .emoji_confirm(&alice_txid, true)
        .await
        .expect("alice confirm");
    bob_agent
        .security()
        .emoji_confirm(&bob_txid, true)
        .await
        .expect("bob confirm");

    let alice_final = tokio::time::timeout(
        Duration::from_secs(10),
        alice_agent.security().sas_next(&alice_txid),
    )
    .await
    .expect("alice final timeout")
    .expect("alice final");
    assert!(matches!(alice_final, locknet_rcab::SasStep::Verified), "alice: {alice_final:?}");

    let bob_final = tokio::time::timeout(
        Duration::from_secs(10),
        bob_agent.security().sas_next(&bob_txid),
    )
    .await
    .expect("bob final timeout")
    .expect("bob final");
    assert!(matches!(bob_final, locknet_rcab::SasStep::Verified), "bob: {bob_final:?}");

    assert!(
        alice_agent.security().is_session_verified(bob_uid, bob_sid).await,
        "alice: bob session is verified"
    );
    assert!(
        bob_agent.security().is_session_verified(alice_uid, alice_sid).await,
        "bob: alice session is verified"
    );
    assert!(alice_agent.security().is_user_verified(bob_uid).await);
    assert!(bob_agent.security().is_user_verified(alice_uid).await);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `sas_decline` removes the pending START. A subsequent `sas_next` on the
/// same txid returns `InvalidArgument` (flow does not exist).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_decline_leaves_no_flow() {
    let alice = common::register_new("hsasd_a").await;
    let bob = common::register_new("hsasd_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_cs(&alice_agent).await;
    setup_cs(&bob_agent).await;

    let _group_id = common::setup_group_with_two(&alice, &bob, "HSASDecl").await;

    let mut bob_high_rx = bob_agent.subscribe();
    let _alice_txid = alice_agent
        .security()
        .sas_start(bob_uid, bob_sid)
        .await
        .expect("alice start");

    let evt = wait_sas_message(&mut bob_high_rx, |e| matches!(e, HighEvent::SasMessage { .. })).await;
    let bob_txid = match evt {
        HighEvent::SasMessage { content, .. } => content
            .pointer("/content/transaction_id")
            .and_then(|v| v.as_str())
            .expect("txid")
            .to_string(),
        _ => unreachable!(),
    };

    bob_agent
        .security()
        .sas_decline(&bob_txid)
        .await
        .expect("bob decline");

    let err = bob_agent
        .security()
        .sas_next(&bob_txid)
        .await
        .unwrap_err();
    assert!(
        matches!(err, locknet_rcab::LockNetError::InvalidArgument(_)),
        "expected InvalidArgument, got {err:?}"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `sas_cancel` removes an active flow; a subsequent `sas_next` on the same
/// txid returns `InvalidArgument`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_cancel_works_before_confirm() {
    let alice = common::register_new("hsasc_a").await;
    let bob = common::register_new("hsasc_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_cs(&alice_agent).await;
    setup_cs(&bob_agent).await;

    let _group_id = common::setup_group_with_two(&alice, &bob, "HSASC").await;

    let mut bob_high_rx = bob_agent.subscribe();
    let alice_txid = alice_agent
        .security()
        .sas_start(bob_uid, bob_sid)
        .await
        .expect("alice start");

    let evt = wait_sas_message(&mut bob_high_rx, |e| matches!(e, HighEvent::SasMessage { .. })).await;
    let bob_txid = match evt {
        HighEvent::SasMessage { content, .. } => content
            .pointer("/content/transaction_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string(),
        _ => unreachable!(),
    };

    bob_agent.security().sas_accept(&bob_txid).await.expect("bob accept");

    let _ = alice_agent.security().sas_next(&alice_txid).await.expect("alice emoji");
    let _ = bob_agent.security().sas_next(&bob_txid).await.expect("bob emoji");

    alice_agent.security().sas_cancel(&alice_txid).await.expect("alice cancel");

    let err = alice_agent
        .security()
        .sas_next(&alice_txid)
        .await
        .unwrap_err();
    assert!(matches!(err, locknet_rcab::LockNetError::InvalidArgument(_)));

    bob_agent.security().sas_cancel(&bob_txid).await.expect("bob cancel");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}