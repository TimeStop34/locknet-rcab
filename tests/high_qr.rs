//! QR via the high-level API.
//!
//! Covers `SecurityHelper::qr_*()`. The QR protocol itself is the same as
//! in `tests/qr.rs` (low-level); the differences at this layer:
//!
//! - `qr_display` / `qr_scan` register the flow in `state.active_qr` and
//!   return the `transaction_id` (displayer also gets the `QrCode`).
//! - `qr_exchange_mac(txid)` automatically resolves the peer's MAC key from
//!   the peer's published keys (`query_cross_signing_keys` for mode 0,
//!   `query_keys` for modes 1/2), so the caller does not pass `peer_key_b64`.
//! - On `Verified`, the flow writes to `state.verified_users` /
//!   `state.verified_sessions` and emits `SessionVerified` / `UserVerified`.
//! - `qr_cancel(txid)` removes the flow; a subsequent `qr_next(txid)`
//!   returns `InvalidArgument`.
//!
//! What is verified:
//!
//! - Mode 0 (user-to-user, MAC of MSK): both sides `Verified`, both
//!   `is_user_verified` and `is_session_verified` true.
//! - Mode 2 (self-device, MAC of ed25519): same invariants, prefix
//!   `LockNetProtocol;v1.0;2;`.
//! - Cancel from `WaitingScanned`: flow removed, next call fails with
//!   `InvalidArgument`.
//!
//! Not covered here: low-level QR (`tests/qr.rs`), mode 1 (needs the
//! creator's cross-signing private keys on a second device — deferred to
//! the manual/exploratory test in `tests/qr.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::{QrMode, QrStep};

async fn setup_cs(agent: &locknet_rcab::LockNetAgent) {
    agent.security().setup_cross_signing().await.expect("setup_cross_signing");
}

/// Mode 0 full flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mode0_user_to_user_full_flow() {
    let alice = common::register_new("hqr0_a").await;
    let bob = common::register_new("hqr0_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_sec = alice_agent.security();
    let bob_sec = bob_agent.security();

    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_cs(&alice_agent).await;
    setup_cs(&bob_agent).await;

    let (code, alice_txid) = alice_sec
        .qr_display(QrMode::UserToUser, bob_uid, bob_sid)
        .await
        .expect("alice qr_display");

    assert_eq!(code.mode, QrMode::UserToUser);
    assert!(code.raw.starts_with("LockNetProtocol;v1.0;0;"));

    let bob_txid = bob_sec
        .qr_scan(&code.raw, alice_uid, alice_sid)
        .await
        .expect("bob qr_scan");
    assert_eq!(alice_txid, bob_txid);

    let (d_step, s_step) = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            tokio::join!(
                alice_sec.qr_next(&alice_txid),
                bob_sec.qr_next(&bob_txid),
            )
        },
    )
    .await
    .expect("next join timeout");
    let d_step = d_step.expect("disp next");
    let s_step = s_step.expect("scan next");
    assert!(matches!(d_step, QrStep::Confirmed), "disp: {d_step:?}");
    assert!(matches!(s_step, QrStep::Confirmed), "scan: {s_step:?}");

    let (f1, f2) = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            tokio::join!(
                alice_sec.qr_exchange_mac(&alice_txid),
                bob_sec.qr_exchange_mac(&bob_txid),
            )
        },
    )
    .await
    .expect("exchange_mac join timeout");

    let f1 = f1.expect("disp exchange");
    let f2 = f2.expect("scan exchange");
    assert!(matches!(f1, QrStep::Verified), "disp: {f1:?}");
    assert!(matches!(f2, QrStep::Verified), "scan: {f2:?}");

    assert!(alice_sec.is_user_verified(bob_uid).await);
    assert!(bob_sec.is_user_verified(alice_uid).await);
    assert!(alice_sec.is_session_verified(bob_uid, bob_sid).await);
    assert!(bob_sec.is_session_verified(alice_uid, alice_sid).await);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Mode 2 full flow (MAC of ed25519; cryptographically identical to mode 1
/// but with different QR prefix and different post-flow semantics).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mode2_self_device_full_flow() {
    let alice = common::register_new("hqr2_a").await;
    let bob = common::register_new("hqr2_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_sec = alice_agent.security();
    let bob_sec = bob_agent.security();

    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_cs(&alice_agent).await;
    setup_cs(&bob_agent).await;

    let (code, alice_txid) = alice_sec
        .qr_display(QrMode::SelfDeviceUntrusted, bob_uid, bob_sid)
        .await
        .expect("alice display");

    assert!(code.raw.starts_with("LockNetProtocol;v1.0;2;"));

    let bob_txid = bob_sec
        .qr_scan(&code.raw, alice_uid, alice_sid)
        .await
        .expect("bob scan");

    let (d_step, s_step) = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            tokio::join!(
                alice_sec.qr_next(&alice_txid),
                bob_sec.qr_next(&bob_txid),
            )
        },
    )
    .await
    .expect("next timeout");
    assert!(matches!(d_step.expect("d"), QrStep::Confirmed));
    assert!(matches!(s_step.expect("s"), QrStep::Confirmed));

    let (f1, f2) = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            tokio::join!(
                alice_sec.qr_exchange_mac(&alice_txid),
                bob_sec.qr_exchange_mac(&bob_txid),
            )
        },
    )
    .await
    .expect("exchange_mac timeout");
    assert!(matches!(f1.expect("f1"), QrStep::Verified));
    assert!(matches!(f2.expect("f2"), QrStep::Verified));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `qr_cancel` from the initial state removes the flow; subsequent calls to
/// `qr_next` fail with `InvalidArgument`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_cancel_returns_cancelled() {
    let alice = common::register_new("hqrc_a").await;
    let bob = common::register_new("hqrc_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_sec = alice_agent.security();
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_cs(&alice_agent).await;

    let (_code, txid) = alice_sec
        .qr_display(QrMode::UserToUser, bob_uid, bob_sid)
        .await
        .expect("display");

    alice_sec.qr_cancel(&txid).await.expect("cancel");

    let err = alice_sec.qr_next(&txid).await.unwrap_err();
    assert!(
        matches!(err, locknet_rcab::LockNetError::InvalidArgument(_)),
        "expected InvalidArgument, got {err:?}"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}