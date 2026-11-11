//! QR verification — low-level API.
//!
//! Covers `LockNetLowAgent::verification().qr_*()` (low-level QR flows that
//! operate on `Event::ToDevice`). For the higher-level flow via
//! `SecurityHelper` and `HighEvent`, see `tests/high_qr.rs`.
//!
//! LockNet's QR format (unlike Matrix):
//!
//! ```text
//! LockNetProtocol;v1.0;<mode>;<txid>;<eph_pub_b64>;<secret_b64>
//! ```
//!
//! Modes:
//!
//! - **0** — user-to-user. Both sides MAC their MSKs (`master`).
//! - **1** — self-device with the MSK already trusted. Both sides MAC
//!   their per-device `ed25519` keys.
//! - **2** — self-device with the MSK not yet trusted. Cryptographically
//!   identical to mode 1; the difference is semantic (whether the MSK is
//!   marked as verified after the flow).
//!
//! The handshake:
//!
//! 1. Displayer generates an ephemeral X25519 keypair and an 8-byte secret,
//!    both encoded in the QR string.
//! 2. Scanner decodes the QR, generates its own X25519 ephemeral, computes
//!    the ECDH shared secret, and sends `qr.scanned` (with the secret and its
//!    public key) via Olm.
//! 3. Displayer verifies the secret matches, computes the same ECDH shared
//!    secret, and sends `qr.confirm`.
//! 4. Both sides derive a MAC key from the shared secret via HKDF (info =
//!    `LOCKNET_ENCRYPTION_QR_VERIFICATION_V1`), then exchange `qr.mac` of
//!    their respective keys (MSK in mode 0, `ed25519` in modes 1/2).
//! 5. Each side recomputes the peer's expected MAC from the peer's published
//!    key and compares.
//!
//! Requirements:
//!
//! - `setup_full()` for each participant (cross-signing + device signature);
//!   mode 0 needs both peers' MSKs to be queryable, modes 1/2 need both
//!   peers' `ed25519` keys.
//! - `setup_olm()` — QR messages are carried inside Olm.
//!
//! Not covered here: high-level QR via `SecurityHelper` (`tests/high_qr.rs`),
//! SAS (`tests/sas.rs`, `tests/high_sas.rs`).

mod common;

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine;
use locknet_rcab::api::low::helpers::verification::{QrMode, QrStep};
use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{Credentials, Event, LockNetClient, LockNetLowAgent};

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

async fn own_ed25519(low: &LockNetLowAgent) -> String {
    let acc = low.store().account().await;
    let acc = acc.lock().await;
    acc.ed25519_public_b64()
}

async fn setup_full(user: &common::TestUser) -> CrossSigningKeysPrivate {
    let low = user.low();
    let uid = user.session.user_id;
    let sid = user.session.session_id;

    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(uid, &keys))
        .await
        .expect("upload cross-signing");

    let own_ed = own_ed25519(&low).await;
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(sid, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload device signature");

    keys
}

async fn setup_olm(a_low: &LockNetLowAgent, b_low: &LockNetLowAgent, b_uid: i64, b_sid: i64) {
    let mut rx = b_low.subscribe();
    a_low
        .olm()
        .send(b_uid, b_sid, "setup")
        .wait()
        .await
        .expect("olm forward setup");
    let evt = common::wait_event(&mut rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else {
        unreachable!()
    };
    b_low
        .olm()
        .decrypt(p)
        .wait()
        .await
        .expect("forward setup decrypt");

    let mut rx2 = a_low.subscribe();
    b_low
        .olm()
        .send(a_low.user_id(), a_low.session_id(), "setup-rev")
        .wait()
        .await
        .expect("olm reverse setup");
    let evt = common::wait_event(&mut rx2, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else {
        unreachable!()
    };
    a_low
        .olm()
        .decrypt(p)
        .wait()
        .await
        .expect("reverse setup decrypt");
}

async fn peer_msk(observer: &LockNetLowAgent, peer_uid: i64) -> String {
    let cs = observer
        .crypto()
        .query_cross_signing_keys(vec![peer_uid])
        .await
        .expect("query_cross_signing_keys");
    cs.get(&peer_uid)
        .map(|u| u.master_key.key.clone())
        .expect("peer msk")
}

fn parse_qr_txid(raw: &str) -> String {
    let parts: Vec<&str> = raw.split(';').collect();
    assert_eq!(parts.len(), 6, "QR must have 6 parts: {raw}");
    parts[3].to_string()
}

fn b64_no_pad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

// ---- tests ----

/// Mode 0 (user-to-user) full flow.
///
/// Verifies:
/// - QR string prefix is `LockNetProtocol;v1.0;0;`;
/// - both sides produce the same MAC key (identical ECDH shared secret);
/// - both sides' MACs verify (mode 0 MACs the MSK);
/// - both flows end in `QrStep::Verified`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mode0_user_to_user_full_flow() {
    let alice = common::register_new("qr0_a").await;
    let bob = common::register_new("qr0_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_msk = a_keys.msk_pub_b64();
    let b_msk = b_keys.msk_pub_b64();

    let (code, mut alice_flow) = alice_low
        .verification()
        .qr_display(
            QrMode::UserToUser,
            bob_uid,
            bob_sid,
            a_msk.clone(),
            own_ed25519(&alice_low).await,
        )
        .await
        .expect("alice qr_display");

    assert_eq!(code.mode, QrMode::UserToUser);
    assert!(code.raw.starts_with("LockNetProtocol;v1.0;0;"));

    let mut bob_flow = bob_low
        .verification()
        .qr_scan(
            &code.raw,
            alice_uid,
            alice_sid,
            b_msk.clone(),
            own_ed25519(&bob_low).await,
        )
        .await
        .expect("bob qr_scan");

    assert_eq!(bob_flow.transaction_id(), code.transaction_id);
    assert_eq!(bob_flow.mode(), QrMode::UserToUser);

    let alice_step = tokio::time::timeout(Duration::from_secs(10), alice_flow.next())
        .await
        .expect("alice next timeout")
        .expect("alice next");
    assert!(
        matches!(alice_step, QrStep::Confirmed),
        "alice: {alice_step:?}"
    );

    let bob_step = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
        .await
        .expect("bob next timeout")
        .expect("bob next");
    assert!(matches!(bob_step, QrStep::Confirmed), "bob: {bob_step:?}");

    let alice_mk = alice_flow.mac_key().copied().expect("alice mac_key");
    let bob_mk = bob_flow.mac_key().copied().expect("bob mac_key");
    assert_eq!(alice_mk, bob_mk, "both sides must derive the same MAC key");

    let (alice_res, bob_res) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            alice_flow.exchange_mac(b_msk.clone()),
            bob_flow.exchange_mac(a_msk.clone()),
        )
    })
    .await
    .expect("exchange_mac timeout");

    let alice_final = alice_res.expect("alice exchange_mac");
    let bob_final = bob_res.expect("bob exchange_mac");
    assert!(
        matches!(alice_final, QrStep::Verified),
        "alice: {alice_final:?}"
    );
    assert!(matches!(bob_final, QrStep::Verified), "bob: {bob_final:?}");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Mode 1 (self-device with trusted MSK) full flow.
///
/// Uses two sessions of the same user (via a second login). MACs the
/// `ed25519` key of each session rather than the shared MSK — which is why
/// the two sessions must have different `ed25519` keys.
///
/// Verifies the same invariants as mode 0, plus the prefix
/// `LockNetProtocol;v1.0;1;`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mode1_self_device_full_flow() {
    let alice = common::register_new("qr1_a").await;
    let alice_uid = alice.session.user_id;
    let alice1_sid = alice.session.session_id;
    let alice1_low = alice.low();

    let mut alice2_client = LockNetClient::new(common::test_config());
    let alice2_session = alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    assert_eq!(alice2_session.user_id, alice_uid);
    assert_ne!(alice2_session.session_id, alice1_sid);
    let alice2_sid = alice2_session.session_id;
    let alice2_low = alice2_client.get_low_agent().expect("alice2 low");

    let a_keys = setup_full(&alice).await;
    setup_olm(&alice1_low, &alice2_low, alice_uid, alice2_sid).await;

    let alice1_ed = own_ed25519(&alice1_low).await;
    let alice2_ed = own_ed25519(&alice2_low).await;
    assert_ne!(
        alice1_ed, alice2_ed,
        "two sessions of the same user must have different ed25519 keys"
    );

    let (code, mut disp_flow) = alice1_low
        .verification()
        .qr_display(
            QrMode::SelfDeviceTrusted,
            alice_uid,
            alice2_sid,
            a_keys.msk_pub_b64(),
            alice1_ed.clone(),
        )
        .await
        .expect("alice1 qr_display");

    assert_eq!(code.mode, QrMode::SelfDeviceTrusted);
    assert!(code.raw.starts_with("LockNetProtocol;v1.0;1;"));

    let mut scan_flow = alice2_low
        .verification()
        .qr_scan(
            &code.raw,
            alice_uid,
            alice1_sid,
            a_keys.msk_pub_b64(),
            alice2_ed.clone(),
        )
        .await
        .expect("alice2 qr_scan");

    let (d_step, s_step) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(disp_flow.next(), scan_flow.next())
    })
    .await
    .expect("next join timeout");
    let d_step = d_step.expect("disp next");
    let s_step = s_step.expect("scan next");
    assert!(matches!(d_step, QrStep::Confirmed), "disp: {d_step:?}");
    assert!(matches!(s_step, QrStep::Confirmed), "scan: {s_step:?}");

    let (f1, f2) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            disp_flow.exchange_mac(alice2_ed.clone()),
            scan_flow.exchange_mac(alice1_ed.clone()),
        )
    })
    .await
    .expect("exchange_mac timeout");

    let f1 = f1.expect("disp exchange");
    let f2 = f2.expect("scan exchange");
    assert!(matches!(f1, QrStep::Verified), "disp: {f1:?}");
    assert!(matches!(f2, QrStep::Verified), "scan: {f2:?}");

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    a.client.disconnect().await.ok();
}

/// Mode 2 (self-device with untrusted MSK) full flow.
///
/// Cryptographically identical to mode 1 (MACs `ed25519`), but the QR prefix
/// is `LockNetProtocol;v1.0;2;` and the semantics at the application level
/// differ (whether the MSK is marked as trusted after the flow).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mode2_self_device_full_flow() {
    let alice = common::register_new("qr2_a").await;
    let bob = common::register_new("qr2_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_ed = own_ed25519(&alice_low).await;
    let b_ed = own_ed25519(&bob_low).await;

    let (code, mut disp_flow) = alice_low
        .verification()
        .qr_display(
            QrMode::SelfDeviceUntrusted,
            bob_uid,
            bob_sid,
            a_keys.msk_pub_b64(),
            a_ed.clone(),
        )
        .await
        .expect("qr_display");

    assert_eq!(code.mode, QrMode::SelfDeviceUntrusted);
    assert!(code.raw.starts_with("LockNetProtocol;v1.0;2;"));

    let mut scan_flow = bob_low
        .verification()
        .qr_scan(
            &code.raw,
            alice_uid,
            alice_sid,
            b_keys.msk_pub_b64(),
            b_ed.clone(),
        )
        .await
        .expect("qr_scan");

    let (d_step, s_step) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(disp_flow.next(), scan_flow.next())
    })
    .await
    .expect("next join timeout");
    let d_step = d_step.expect("disp next");
    let s_step = s_step.expect("scan next");
    assert!(matches!(d_step, QrStep::Confirmed));
    assert!(matches!(s_step, QrStep::Confirmed));

    let (f1, f2) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            disp_flow.exchange_mac(b_ed.clone()),
            scan_flow.exchange_mac(a_ed.clone()),
        )
    })
    .await
    .expect("exchange_mac timeout");

    let f1 = f1.expect("disp exchange");
    let f2 = f2.expect("scan exchange");
    assert!(matches!(f1, QrStep::Verified), "disp: {f1:?}");
    assert!(matches!(f2, QrStep::Verified), "scan: {f2:?}");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// A `qr.scanned` message with the wrong `secret` cancels the flow with
/// `QrStep::Cancelled("secret mismatch")`.
///
/// The 8-byte secret proves the scanner actually scanned the displayed QR
/// (rather than guessing the txid). Bob is forged here to simulate a scanner
/// that tried to short-circuit the challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_secret_mismatch_cancels() {
    let alice = common::register_new("qrss_a").await;
    let bob = common::register_new("qrss_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let (code, mut alice_flow) = alice_low
        .verification()
        .qr_display(
            QrMode::UserToUser,
            bob_uid,
            bob_sid,
            a_keys.msk_pub_b64(),
            own_ed25519(&alice_low).await,
        )
        .await
        .expect("qr_display");

    let txid = parse_qr_txid(&code.raw);

    // Craft a fake scanned message with the wrong secret.
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("getrandom");
    let eph_sk = x25519_dalek::StaticSecret::from(sk);
    let eph_pub = x25519_dalek::PublicKey::from(&eph_sk);

    let wrong_secret = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let msg = serde_json::json!({
        "type": "ln.encryption.key.verification.qr.scanned",
        "content": {
            "transaction_id": txid,
            "public_key": b64_no_pad(eph_pub.as_bytes()),
            "secret": b64_no_pad(&wrong_secret),
        }
    });

    bob_low
        .olm()
        .send(alice_uid, alice_sid, msg.to_string())
        .wait()
        .await
        .expect("bob manual send scanned");

    let step = tokio::time::timeout(Duration::from_secs(10), alice_flow.next())
        .await
        .expect("alice next timeout")
        .expect("alice next");
    match step {
        QrStep::Cancelled(reason) => assert_eq!(reason, "secret mismatch"),
        other => panic!("expected Cancelled(secret mismatch), got {other:?}"),
    }

    // Cancelled is sticky: subsequent `next()` calls return the same state.
    let step2 = alice_flow.next().await.expect("alice next #2");
    assert!(matches!(step2, QrStep::Cancelled(_)));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// If the initiator recomputes the peer's MAC against the wrong key (here
/// Alice passes her own MSK instead of Bob's), the initiator's flow cancels
/// with `QrStep::Cancelled("MAC mismatch")` while the responder — whose peer
/// keys are correct — still verifies.
///
/// This asymmetry is what catches a MITM on the initiator's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_mac_mismatch_cancels() {
    let alice = common::register_new("qrmm_a").await;
    let bob = common::register_new("qrmm_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_msk = a_keys.msk_pub_b64();
    let b_msk = b_keys.msk_pub_b64();

    let (code, mut alice_flow) = alice_low
        .verification()
        .qr_display(
            QrMode::UserToUser,
            bob_uid,
            bob_sid,
            a_msk.clone(),
            own_ed25519(&alice_low).await,
        )
        .await
        .expect("qr_display");

    let mut bob_flow = bob_low
        .verification()
        .qr_scan(
            &code.raw,
            alice_uid,
            alice_sid,
            b_msk.clone(),
            own_ed25519(&bob_low).await,
        )
        .await
        .expect("qr_scan");

    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(alice_flow.next(), bob_flow.next())
    })
    .await
    .expect("next join timeout");

    // Alice passes her OWN msk as the expected peer key.
    let real_a_msk = peer_msk(&bob_low, alice_uid).await;
    let (alice_res, bob_res) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            alice_flow.exchange_mac(a_msk.clone()),
            bob_flow.exchange_mac(real_a_msk),
        )
    })
    .await
    .expect("exchange_mac timeout");

    let alice_final = alice_res.expect("alice exchange");
    let bob_final = bob_res.expect("bob exchange");

    match alice_final {
        QrStep::Cancelled(reason) => assert_eq!(reason, "MAC mismatch"),
        other => panic!("alice expected Cancelled(MAC mismatch), got {other:?}"),
    }
    assert!(matches!(bob_final, QrStep::Verified), "bob: {bob_final:?}");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Malformed QR strings are rejected with `LockNetError::InvalidArgument`.
///
/// Three cases: garbage input, wrong prefix, and an invalid mode value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_invalid_raw_fails() {
    let alice = common::register_new("qrbad_a").await;
    let alice_low = alice.low();
    let a_keys = setup_full(&alice).await;
    let a_msk = a_keys.msk_pub_b64();
    let a_ed = own_ed25519(&alice_low).await;

    let r1 = alice_low
        .verification()
        .qr_scan("not-a-qr", 1, 1, a_msk.clone(), a_ed.clone())
        .await;
    match r1 {
        Ok(_) => panic!("qr_scan with garbage must not return Ok"),
        Err(locknet_rcab::LockNetError::InvalidArgument(_)) => {}
        Err(other) => panic!("expected InvalidArgument, got {other:?}"),
    }

    let r2 = alice_low
        .verification()
        .qr_scan(
            "WrongPrefix;v1.0;0;txid;AAAA;BBBB",
            1,
            1,
            a_msk.clone(),
            a_ed.clone(),
        )
        .await;
    match r2 {
        Ok(_) => panic!("qr_scan with wrong prefix must not return Ok"),
        Err(locknet_rcab::LockNetError::InvalidArgument(_)) => {}
        Err(other) => panic!("expected InvalidArgument, got {other:?}"),
    }

    let r3 = alice_low
        .verification()
        .qr_scan("LockNetProtocol;v1.0;5;txid;AAAA;BBBB", 1, 1, a_msk, a_ed)
        .await;
    match r3 {
        Ok(_) => panic!("qr_scan with invalid mode must not return Ok"),
        Err(locknet_rcab::LockNetError::InvalidArgument(_)) => {}
        Err(other) => panic!("expected InvalidArgument, got {other:?}"),
    }

    let mut a = alice;
    a.client.disconnect().await.ok();
}

/// `cancel()` from the `WaitingScanned` state transitions the flow to
/// `QrStep::Cancelled("cancelled by user")` without any message exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn qr_cancel_from_waiting_scanned() {
    let alice = common::register_new("qrcc_a").await;
    let bob = common::register_new("qrcc_b").await;

    let alice_low = alice.low();
    let _bob_low = bob.low();
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    setup_full(&bob).await;

    let (_code, mut flow) = alice_low
        .verification()
        .qr_display(
            QrMode::UserToUser,
            bob_uid,
            bob_sid,
            a_keys.msk_pub_b64(),
            own_ed25519(&alice_low).await,
        )
        .await
        .expect("display");

    flow.cancel().await.expect("cancel");

    let step = flow.next().await.expect("next after cancel");
    match step {
        QrStep::Cancelled(reason) => assert_eq!(reason, "cancelled by user"),
        other => panic!("expected Cancelled, got {other:?}"),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}
