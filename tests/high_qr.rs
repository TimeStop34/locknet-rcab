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
//! - Mode 1 (self-device, MAC of ed25519 with pre-trusted MSK): the second
//!   device imports CS private keys from the first via
//!   `SecurityHelper::export_cross_signing_keys` /
//!   `import_cross_signing_keys`, then after the QR handshake each side
//!   signs the other's session with its SSK (`sign_device_session`).
//!
//! Not covered here: low-level QR (`tests/qr.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::{Credentials, LockNetClient, QrMode, QrStep};

async fn setup_cs(agent: &locknet_rcab::LockNetAgent) {
    agent
        .security()
        .setup_cross_signing()
        .await
        .expect("setup_cross_signing");
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

    let (d_step, s_step) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(alice_sec.qr_next(&alice_txid), bob_sec.qr_next(&bob_txid),)
    })
    .await
    .expect("next join timeout");
    let d_step = d_step.expect("disp next");
    let s_step = s_step.expect("scan next");
    assert!(matches!(d_step, QrStep::Confirmed), "disp: {d_step:?}");
    assert!(matches!(s_step, QrStep::Confirmed), "scan: {s_step:?}");

    let (f1, f2) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            alice_sec.qr_exchange_mac(&alice_txid),
            bob_sec.qr_exchange_mac(&bob_txid),
        )
    })
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

    let (d_step, s_step) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(alice_sec.qr_next(&alice_txid), bob_sec.qr_next(&bob_txid),)
    })
    .await
    .expect("next timeout");
    assert!(matches!(d_step.expect("d"), QrStep::Confirmed));
    assert!(matches!(s_step.expect("s"), QrStep::Confirmed));

    let (f1, f2) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            alice_sec.qr_exchange_mac(&alice_txid),
            bob_sec.qr_exchange_mac(&bob_txid),
        )
    })
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

/// Mode 1 full flow: self-device verification where the MSK is already
/// trusted by both devices.
///
/// Setup: Alice1 has cross-signing, Alice2 is a second device (fresh
/// store, same user). Alice1 exports CS private keys, Alice2 imports them
/// (application-controlled channel — here, in-process).
///
/// Flow:
/// 1. Mode-1 QR handshake (display / scan / next / exchange_mac). The MAC
///    covers each device's `ed25519`, not the MSK (which is shared).
/// 2. After `Verified`, each device signs the other's session ed25519 with
///    its SSK via `sign_device_session`. This is the cross-signing step that
///    the QR handshake alone cannot do (it proves the device holds the key
///    but does not publish the signature).
///
/// Verified: both sessions carry an SSK signature from the user, and the
/// server-visible `query_cross_signing_keys` reflects it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mode1_self_device_full_flow() {
    let alice = common::register_new("hqr1_a").await;
    let alice_uid = alice.session.user_id;
    let alice1_sid = alice.session.session_id;
    let alice1_agent = alice.client.get_agent().expect("alice1 agent");
    let alice1_sec = alice1_agent.security();
    let alice1_low = alice1_agent.low();

    setup_cs(&alice1_agent).await;

    // Alice2 — second device of the same user, fresh store.
    let mut alice2_client = LockNetClient::new(common::test_config());
    let alice2_session = alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    assert_eq!(alice2_session.user_id, alice_uid);
    let alice2_sid = alice2_session.session_id;
    assert_ne!(alice1_sid, alice2_sid);
    let alice2_agent = alice2_client.get_agent().expect("alice2 agent");
    let alice2_sec = alice2_agent.security();

    // Transfer CS private keys from Alice1 to Alice2 (application-controlled
    // channel — here, in-process; in production, encrypted local file / OS
    // keychain / manual transfer).
    let exported = alice1_sec
        .export_cross_signing_keys()
        .await
        .expect("alice1 export CS");
    alice2_sec
        .import_cross_signing_keys(exported)
        .await
        .expect("alice2 import CS");

    // Sanity: same MSK on both devices.
    let alice1_cs = alice1_low
        .store()
        .cross_signing_keys()
        .await
        .expect("alice1 CS");
    let alice2_cs = alice2_agent
        .low()
        .store()
        .cross_signing_keys()
        .await
        .expect("alice2 CS");
    assert_eq!(alice1_cs.msk_pub_b64(), alice2_cs.msk_pub_b64());

    // Mode-1 QR handshake.
    let (code, disp_txid) = alice1_sec
        .qr_display(QrMode::SelfDeviceTrusted, alice_uid, alice2_sid)
        .await
        .expect("alice1 display");
    assert!(
        code.raw.starts_with("LockNetProtocol;v1.0;1;"),
        "mode 1 QR prefix, got {}",
        &code.raw[..code.raw.len().min(32)]
    );

    let scan_txid = alice2_sec
        .qr_scan(&code.raw, alice_uid, alice1_sid)
        .await
        .expect("alice2 scan");
    assert_eq!(disp_txid, scan_txid);

    let (d_step, s_step) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            alice1_sec.qr_next(&disp_txid),
            alice2_sec.qr_next(&scan_txid),
        )
    })
    .await
    .expect("next join timeout");
    assert!(matches!(d_step.expect("d"), QrStep::Confirmed));
    assert!(matches!(s_step.expect("s"), QrStep::Confirmed));

    let (f1, f2) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            alice1_sec.qr_exchange_mac(&disp_txid),
            alice2_sec.qr_exchange_mac(&scan_txid),
        )
    })
    .await
    .expect("exchange_mac join timeout");
    let f1 = f1.expect("disp exchange");
    let f2 = f2.expect("scan exchange");
    assert!(matches!(f1, QrStep::Verified), "disp: {f1:?}");
    assert!(matches!(f2, QrStep::Verified), "scan: {f2:?}");

    // Cross-sign each other's sessions (the SSK step that makes the
    // self-device trust persistent on the server).
    alice1_sec
        .sign_device_session(alice_uid, alice2_sid)
        .await
        .expect("alice1 signs alice2");
    alice2_sec
        .sign_device_session(alice_uid, alice1_sid)
        .await
        .expect("alice2 signs alice1");

    // Server-visible check: both sessions carry an SSK signature.
    let query = alice1_low
        .crypto()
        .query_cross_signing_keys(vec![alice_uid])
        .await
        .expect("query CS");
    let entry = query.get(&alice_uid).expect("alice entry");

    for sid in [alice1_sid, alice2_sid] {
        let dev = entry
            .devices
            .get(&sid)
            .unwrap_or_else(|| panic!("session {sid} not in query_cross_signing_keys"));
        let sig = dev
            .signatures
            .get(&alice_uid.to_string())
            .and_then(|m| m.get("self_signing"));
        assert!(
            sig.is_some(),
            "session {sid} must have an SSK signature after mode 1"
        );
    }

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    a.client.disconnect().await.ok();
}
