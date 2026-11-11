//! Olm (1-to-1) encryption tests.
//!
//! Covers the low-level Olm protocol over the real server and the real
//! `vodozemac` implementation (no mocking):
//!
//! - Sending a pre-key message from Alice to Bob and decrypting it.
//! - Establishing a bidirectional session (Bob must reply before Alice can
//!   send a normal, non-pre-key message).
//! - Olm message-type semantics: the first message in a session is always
//!   type=0 (pre-key), the second and subsequent messages are type=1
//!   (normal).
//! - Error paths: decrypting a normal message without an established session
//!   returns `Ok(None)`; decrypting with the wrong algorithm returns
//!   [`locknet_rcab::LockNetError::InvalidResponse`].
//!
//! Not covered here (see other files):
//! - Olm session persistence across process restarts — `tests/sqlite_e2e.rs`.
//! - Olm inside SAS / QR flows — `tests/sas.rs`, `tests/qr.rs`.
//! - Olm as the transport for `group_key` and `key_request` —
//!   `tests/megolm.rs`, `tests/key_sharing.rs`.

mod common;

use locknet_rcab::Event;

/// Alice sends an Olm message; Bob decrypts it.
///
/// Verifies that:
/// - the server rewrites `sender_session_id` to Alice's authenticated
///   session (clients do not control this field);
/// - the algorithm name is exactly `ln.encryption.olm.v1`;
/// - the plaintext round-trips byte-for-byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_send_and_receive() {
    let alice = common::register_new("olm_sr_a").await;
    let bob = common::register_new("olm_sr_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let mut bob_rx = bob_low.subscribe();

    alice_low
        .olm()
        .send(bob_uid, bob_sid, "hello from alice")
        .wait()
        .await
        .expect("olm send");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(payload) = evt else {
        unreachable!()
    };

    assert_eq!(payload.sender_session_id, alice.session.session_id);
    assert_eq!(payload.algorithm, "ln.encryption.olm.v1");

    let pt = bob_low
        .olm()
        .decrypt(payload)
        .wait()
        .await
        .expect("olm decrypt")
        .expect("plaintext present");
    assert_eq!(pt, "hello from alice");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Bidirectional Olm: Alice → Bob, then Bob → Alice over the same session.
///
/// Verifies that the session established by Alice's pre-key message is
/// reusable in the reverse direction: Bob can encrypt a reply that Alice
/// decrypts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_bidirectional() {
    let alice = common::register_new("olm_bid_a").await;
    let bob = common::register_new("olm_bid_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let mut alice_rx = alice_low.subscribe();
    let mut bob_rx = bob_low.subscribe();

    alice_low
        .olm()
        .send(bob_uid, bob_sid, "hi bob")
        .wait()
        .await
        .expect("alice send");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else {
        unreachable!()
    };
    let pt = bob_low
        .olm()
        .decrypt(p)
        .wait()
        .await
        .expect("bob decrypt")
        .unwrap();
    assert_eq!(pt, "hi bob");

    bob_low
        .olm()
        .send(alice_uid, alice_sid, "hi alice")
        .wait()
        .await
        .expect("bob send");

    let evt = common::wait_event(&mut alice_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else {
        unreachable!()
    };
    let pt = alice_low
        .olm()
        .decrypt(p)
        .wait()
        .await
        .expect("alice decrypt")
        .unwrap();
    assert_eq!(pt, "hi alice");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// The first Olm message in a session is a pre-key (type=0). After Bob
/// replies, subsequent messages from Alice become normal (type=1).
///
/// This is the fundamental Olm handshake behavior: a session is only "fully
/// established" after both directions have been used at least once. Higher
/// layers rely on this: sending a burst of messages before any reply uses a
/// pre-key for each one, which is expensive and server-visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_second_message_is_normal_type() {
    let alice = common::register_new("olm_t2_a").await;
    let bob = common::register_new("olm_t2_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let mut alice_rx = alice_low.subscribe();
    let mut bob_rx = bob_low.subscribe();

    // Step 1: Alice → Bob, "first" (pre-key, type=0).
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "first")
        .wait()
        .await
        .expect("send #1");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p1) = evt else {
        unreachable!()
    };

    let bob_curve = {
        let acc = bob_low.store().account().await;
        let a = acc.lock().await;
        a.curve25519_public_b64()
    };
    let inner1 = p1.ciphertext.get(&bob_curve).expect("ciphertext for bob");
    assert_eq!(
        inner1.ciphertext_type, 0,
        "first message must be a pre-key (type=0)"
    );

    let pt1 = bob_low
        .olm()
        .decrypt(p1)
        .wait()
        .await
        .expect("decrypt #1")
        .unwrap();
    assert_eq!(pt1, "first");

    // Step 2: Bob → Alice, "ack" — establishes the session on both sides.
    bob_low
        .olm()
        .send(alice_uid, alice_sid, "ack")
        .wait()
        .await
        .expect("send ack");

    let evt = common::wait_event(&mut alice_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(pa) = evt else {
        unreachable!()
    };
    let pta = alice_low
        .olm()
        .decrypt(pa)
        .wait()
        .await
        .expect("decrypt ack")
        .unwrap();
    assert_eq!(pta, "ack");

    // Step 3: Alice → Bob, "second" — must be type=1 (normal) now.
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "second")
        .wait()
        .await
        .expect("send #2");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p2) = evt else {
        unreachable!()
    };
    let inner2 = p2.ciphertext.get(&bob_curve).expect("ciphertext");
    assert_eq!(
        inner2.ciphertext_type, 1,
        "second message must be normal (type=1), got {}",
        inner2.ciphertext_type
    );

    let pt2 = bob_low
        .olm()
        .decrypt(p2)
        .wait()
        .await
        .expect("decrypt #2")
        .unwrap();
    assert_eq!(pt2, "second");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Decrypting a type=1 (normal) message without any established session
/// returns `Ok(None)` rather than an error.
///
/// This contract lets callers distinguish "no session yet, the message is
/// lost" (which they should surface to the UI as undecryptable) from
/// "decryption failed because the message is corrupt" (which is a protocol
/// error).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_decrypt_returns_none_without_session() {
    let alice = common::register_new("olm_none_a").await;
    let bob = common::register_new("olm_none_b").await;

    let _alice_low = alice.low();
    let bob_low = bob.low();
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;

    let bob_curve = {
        let acc = bob_low.store().account().await;
        let a = acc.lock().await;
        a.curve25519_public_b64()
    };
    let _ = bob_uid;

    let mut ciphertext = std::collections::HashMap::new();
    ciphertext.insert(
        bob_curve,
        locknet_rcab::models::ToDeviceCiphertext {
            ciphertext_type: 1,
            body: "AAAA".to_string(),
        },
    );
    let payload = locknet_rcab::models::ToDevicePayload {
        algorithm: "ln.encryption.olm.v1".into(),
        sender_key: "some_fake_curve".into(),
        sender_session_id: alice_sid,
        ciphertext,
    };

    let result = bob_low.olm().decrypt(payload).wait().await;
    assert!(
        matches!(result, Ok(None)),
        "type=1 without a session must yield Ok(None), got {result:?}"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Decrypting with the wrong algorithm returns
/// [`locknet_rcab::LockNetError::InvalidResponse`].
///
/// This guards against protocol confusion: a non-Olm payload (for example a
/// Megolm message routed by mistake) must not be fed to the Olm decryptor
/// silently — the error surfaces the mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_decrypt_wrong_algorithm_fails() {
    let bob = common::register_new("olm_alg_b").await;
    let bob_low = bob.low();
    let bob_curve = {
        let acc = bob_low.store().account().await;
        let a = acc.lock().await;
        a.curve25519_public_b64()
    };

    let mut ciphertext = std::collections::HashMap::new();
    ciphertext.insert(
        bob_curve,
        locknet_rcab::models::ToDeviceCiphertext {
            ciphertext_type: 0,
            body: "AAAA".to_string(),
        },
    );
    let payload = locknet_rcab::models::ToDevicePayload {
        algorithm: "totally.not.olm".into(),
        sender_key: "x".into(),
        sender_session_id: 0,
        ciphertext,
    };

    let err = bob_low.olm().decrypt(payload).wait().await.unwrap_err();
    match err {
        locknet_rcab::LockNetError::InvalidResponse(msg) => {
            assert!(msg.contains("unexpected algorithm"), "got msg: {msg}");
        }
        other => panic!("expected InvalidResponse, got {other:?}"),
    }

    let mut b = bob;
    b.client.disconnect().await.ok();
}
