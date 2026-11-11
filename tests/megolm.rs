//! Megolm (group) encryption tests — low-level API.
//!
//! Covers `LockNetLowAgent::megolm().*` and the interaction with
//! `messages()` / `olm()`:
//!
//! - Creating an outbound Megolm session and sharing its key via Olm.
//! - Encrypting and decrypting messages through the public helper API.
//! - Session rotation: after `rotate()`, the previous session no longer
//!   decrypts new ciphertext, but still decrypts its own history.
//! - `ensure_session()` idempotency: repeated calls return the same session
//!   until rotation is triggered.
//! - `import()` round-trips a raw `(session_id, session_key)` pair without
//!   going through Olm.
//! - The wire format of the group-key payload
//!   (`ln.encryption.group_key`) and its `type` field.
//! - Error paths: unknown `chat_id`, unknown `megolm_session_id`, wrong
//!   algorithm in the `Encrypted` struct, malformed group-key JSON.
//!
//! Requirements:
//!
//! - `setup_olm()` before `share_group_key()`: the group key is carried as a
//!   `to_device` Olm payload, so an Olm session must exist first.
//! - A group (via `setup_group_with_two`) for message sending, though Megolm
//!   itself is group-agnostic.
//!
//! Not covered here: cross-signing policy enforcement during rotation
//! (`tests/megolm_visibility.rs`), auto-rotation by TTL/count
//! (`tests/megolm_auto_rotation.rs`), high-level `Chat::send` fan-out
//! (`tests/high_chat_send.rs`).

mod common;

use std::time::Duration;

use locknet_rcab::{models::Encrypted, Event, LockNetLowAgent};

/// Establish an Olm session in both directions.
///
/// Megolm group keys are carried inside Olm; without an Olm session the
/// recipient cannot decrypt the `group_key` payload.
async fn setup_olm(
    alice_low: &LockNetLowAgent,
    bob_low: &LockNetLowAgent,
    bob_uid: i64,
    bob_sid: i64,
) {
    let mut rx = bob_low.subscribe();
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "setup")
        .wait()
        .await
        .expect("olm setup send");

    let evt = common::wait_event(&mut rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    bob_low
        .olm()
        .decrypt(p)
        .wait()
        .await
        .expect("setup decrypt");

    let mut rx2 = alice_low.subscribe();
    bob_low
        .olm()
        .send(alice_low.user_id(), alice_low.session_id(), "setup-rev")
        .wait()
        .await
        .expect("reverse setup send");
    let evt = common::wait_event(&mut rx2, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    alice_low.olm().decrypt(p).wait().await.expect("reverse setup decrypt");
}

/// Read Alice's Curve25519 identity key (used to assert the server rewrote
/// `sender_key` from the authenticated session).
async fn alice_curve25519(low: &LockNetLowAgent) -> String {
    let acc = low.store().account().await;
    let a = acc.lock().await;
    a.curve25519_public_b64()
}

/// Full happy path: create → share group key → encrypt → send → decrypt on
/// both ends.
///
/// Verifies:
/// - the server rewrites `sender_key` to Alice's Curve25519 identity key;
/// - the server rewrites `sender_session_id` to Alice's authenticated
///   session;
/// - `decrypt_group_key` accepts the payload delivered as an Olm `to_device`;
/// - Bob can decrypt the Megolm ciphertext;
/// - Alice can decrypt her own message (she has the inbound session locally
///   because `create` installs it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_full_flow() {
    let alice = common::register_new("mg_full_a").await;
    let bob = common::register_new("mg_full_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;
    let alice_sid = alice.session.session_id;

    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmFull").await;

    let info = alice_low
        .megolm()
        .create(group_id)
        .await
        .expect("create megolm");
    assert!(!info.session_key.is_empty());
    assert!(!info.megolm_session_id.is_empty());

    let mut bob_rx = bob_low.subscribe();
    alice_low
        .megolm()
        .share_group_key(group_id, bob_uid, bob_sid)
        .await
        .expect("share group_key");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(td) = evt else { unreachable!() };

    let alice_curve = alice_curve25519(&alice_low).await;
    assert_eq!(td.algorithm, "ln.encryption.olm.v1");
    assert_eq!(td.sender_key, alice_curve);
    assert_eq!(td.sender_session_id, alice_sid);

    let pt = bob_low
        .olm()
        .decrypt(td)
        .wait()
        .await
        .expect("olm decrypt")
        .expect("no plaintext");

    let is_group_key = bob_low
        .megolm()
        .decrypt_group_key(&pt)
        .await
        .expect("import group key");
    assert!(is_group_key, "expected ln.encryption.group_key");

    let encrypted = alice_low
        .megolm()
        .encrypt(group_id, "hello megolm")
        .await
        .expect("megolm encrypt");
    assert_eq!(encrypted.megolm_session_id, info.megolm_session_id);
    assert_eq!(encrypted.algorithm, "ln.encryption.megolm.v1");
    assert_eq!(encrypted.sender_session_id, alice_sid);

    let ack = alice_low
        .messages()
        .send(group_id, encrypted.clone())
        .await
        .expect("send_message");

    let evt = common::wait_event(
        &mut bob_rx,
        |e| matches!(e, Event::MessageCreate(m) if m.message_id == ack.message_id),
    )
    .await;
    let Event::MessageCreate(mc) = evt else { unreachable!() };

    let pt = bob_low
        .megolm()
        .decrypt(group_id, &mc.encrypted)
        .await
        .expect("bob megolm decrypt")
        .expect("no plaintext");
    assert_eq!(pt, "hello megolm");

    let page = alice_low
        .messages()
        .get(group_id, None, 20)
        .await
        .expect("get");
    let own = page
        .messages
        .iter()
        .find(|m| m.message_id == ack.message_id)
        .unwrap();
    let own_pt = alice_low
        .megolm()
        .decrypt(group_id, own.encrypted.as_ref().unwrap())
        .await
        .expect("alice decrypt")
        .expect("no plaintext");
    assert_eq!(own_pt, "hello megolm");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// A recipient without the group key cannot decrypt a Megolm ciphertext.
///
/// `decrypt` must return `Ok(None)` rather than an error: the message is
/// structurally valid, the receiver simply does not have the session. This
/// is what allows the high layer to fall back to a `key_request` instead of
/// surfacing a hard error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_no_key_cannot_decrypt() {
    let alice = common::register_new("mg_nok_a").await;
    let bob = common::register_new("mg_nok_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmNoKey").await;

    alice_low.megolm().create(group_id).await.expect("create");
    let encrypted = alice_low
        .megolm()
        .encrypt(group_id, "secret")
        .await
        .expect("encrypt");
    let _ack = alice_low
        .messages()
        .send(group_id, encrypted.clone())
        .await
        .expect("send");

    let pt = bob_low
        .megolm()
        .decrypt(group_id, &encrypted)
        .await
        .expect("decrypt attempt");
    assert!(pt.is_none(), "bob must not decrypt without the key, got {pt:?}");

    // Unknown chat_id also yields None rather than an error.
    let pt_unknown = bob_low
        .megolm()
        .decrypt(999_999_999, &encrypted)
        .await
        .expect("decrypt unknown");
    assert!(pt_unknown.is_none());

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// After rotation, the old session cannot decrypt new ciphertext but still
/// decrypts its own history.
///
/// Verifies:
/// - `rotate()` returns a different `megolm_session_id`;
/// - the recipient who has not received the new key sees `None` for new
///   messages;
/// - the recipient's old inbound session keeps decrypting pre-rotation
///   messages;
/// - the sender (who has both inbound sessions locally) can decrypt
///   everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_rotation_isolates() {
    let alice = common::register_new("mg_rot_a").await;
    let bob = common::register_new("mg_rot_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmRot").await;

    let info1 = alice_low.megolm().create(group_id).await.expect("create #1");
    let mut bob_rx = bob_low.subscribe();
    alice_low
        .megolm()
        .share_group_key(group_id, bob_uid, bob_sid)
        .await
        .expect("share #1");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(td) = evt else { unreachable!() };
    let pt = bob_low.olm().decrypt(td).wait().await.unwrap().unwrap();
    bob_low.megolm().decrypt_group_key(&pt).await.expect("import #1");

    let enc1 = alice_low.megolm().encrypt(group_id, "msg1").await.unwrap();
    assert_eq!(enc1.megolm_session_id, info1.megolm_session_id);
    let _ack1 = alice_low.messages().send(group_id, enc1.clone()).await.unwrap();

    let pt1 = bob_low.megolm().decrypt(group_id, &enc1).await.unwrap().unwrap();
    assert_eq!(pt1, "msg1");

    let info2 = alice_low.megolm().rotate(group_id).await.expect("rotate");
    assert_ne!(info1.megolm_session_id, info2.megolm_session_id);

    let enc2 = alice_low.megolm().encrypt(group_id, "msg2").await.unwrap();
    assert_eq!(enc2.megolm_session_id, info2.megolm_session_id);

    // Bob never received session #2, so decryption yields None.
    let pt2 = bob_low.megolm().decrypt(group_id, &enc2).await.unwrap();
    assert!(pt2.is_none(), "bob must not decrypt msg2 without session #2");

    // Old session still decrypts old messages.
    let pt1_again = bob_low.megolm().decrypt(group_id, &enc1).await.unwrap();
    assert_eq!(pt1_again.as_deref(), Some("msg1"));

    // Alice holds both inbound sessions and can decrypt everything.
    assert_eq!(
        alice_low.megolm().decrypt(group_id, &enc1).await.unwrap().as_deref(),
        Some("msg1")
    );
    assert_eq!(
        alice_low.megolm().decrypt(group_id, &enc2).await.unwrap().as_deref(),
        Some("msg2")
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `ensure_session()` is idempotent until rotation is triggered.
///
/// Without auto-rotation (or membership changes), repeated calls must return
/// the same session, and `encrypt()` must use that session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_ensure_session_idempotent() {
    let alice = common::register_new("mg_ens_a").await;
    let bob = common::register_new("mg_ens_b").await;
    let alice_low = alice.low();
    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmEns").await;

    let (s1, _) = alice_low.megolm().ensure_session(group_id).await.expect("ensure 1");
    let (s2, _) = alice_low.megolm().ensure_session(group_id).await.expect("ensure 2");
    assert_eq!(s1.megolm_session_id, s2.megolm_session_id);
    assert_eq!(s1.session_key, s2.session_key);

    let a = alice_low.megolm().encrypt(group_id, "text").await.unwrap();
    assert_eq!(a.megolm_session_id, s1.megolm_session_id);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `decrypt_group_key` returns `false` for non-JSON input or for a payload
/// whose `type` field is not `ln.encryption.group_key`.
///
/// This lets the caller distinguish "not a group-key message, ignore it" from
/// "group-key message, but malformed" (the latter surfaces as an error when
/// `content` is missing).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_decrypt_group_key_wrong_type_returns_false() {
    let bob = common::register_new("mg_wt_b").await;
    let bob_low = bob.low();

    let pt_not_json = "not json at all";
    assert!(!bob_low.megolm().decrypt_group_key(pt_not_json).await.unwrap());

    let pt_wrong_type = r#"{"type":"ln.something.else","content":{}}"#;
    assert!(!bob_low.megolm().decrypt_group_key(pt_wrong_type).await.unwrap());

    // Wrong shape (missing content) is an error, not a silent false.
    let pt_missing_content = r#"{"type":"ln.encryption.group_key"}"#;
    let res = bob_low.megolm().decrypt_group_key(pt_missing_content).await;
    assert!(res.is_err(), "expected error for missing content, got {res:?}");

    let mut b = bob;
    b.client.disconnect().await.ok();
}

/// A ciphertext whose `algorithm` is not `ln.encryption.megolm.v1` yields
/// `Ok(None)` — the helper silently ignores non-Megolm payloads rather than
/// attempting to decrypt them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_decrypt_wrong_algorithm_returns_none() {
    let bob = common::register_new("mg_wa_b").await;
    let bob_low = bob.low();

    let bogus = Encrypted {
        algorithm: "not.megolm".into(),
        sender_key: "x".into(),
        sender_session_id: 1,
        megolm_session_id: "x".into(),
        ciphertext: "x".into(),
    };
    let pt = bob_low.megolm().decrypt(1, &bogus).await.unwrap();
    assert!(pt.is_none());

    let mut b = bob;
    b.client.disconnect().await.ok();
}

/// `import()` round-trips an outbound `(session_id, session_key)` pair without
/// going through Olm.
///
/// This is the primitive used by key backup / key request flows where the
/// raw key is delivered by other means (backup blob, another session, etc.).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_import_roundtrip() {
    let alice = common::register_new("mg_imp_a").await;
    let bob = common::register_new("mg_imp_b").await;
    let alice_low = alice.low();
    let bob_low = bob.low();
    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmImp").await;

    let info = alice_low.megolm().create(group_id).await.expect("create");
    bob_low
        .megolm()
        .import(group_id, info.megolm_session_id.clone(), info.session_key.clone())
        .await
        .expect("import");

    let enc = alice_low.megolm().encrypt(group_id, "imported-ok").await.unwrap();
    let pt = bob_low.megolm().decrypt(group_id, &enc).await.unwrap().unwrap();
    assert_eq!(pt, "imported-ok");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// `share_group_key()` uses the pre-established Olm session (type=1) rather
/// than performing a pre-key handshake (type=0).
///
/// This matters because every Megolm fan-out uses `share_group_key`; if each
/// fan-out performed a pre-key handshake, it would consume one-time keys and
/// be much slower. The test sets up the Olm session first, then asserts the
/// Olm message is type=1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_share_group_key_via_olm_session() {
    let alice = common::register_new("mg_sgt_a").await;
    let bob = common::register_new("mg_sgt_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmSGT").await;

    alice_low.megolm().create(group_id).await.expect("create");

    let mut bob_rx = bob_low.subscribe();
    alice_low
        .megolm()
        .share_group_key(group_id, bob_uid, bob_sid)
        .await
        .expect("share");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(td) = evt else { unreachable!() };

    let bob_curve = {
        let acc = bob_low.store().account().await;
        let a = acc.lock().await;
        a.curve25519_public_b64()
    };
    let inner = td.ciphertext.get(&bob_curve).expect("ciphertext");
    assert_eq!(
        inner.ciphertext_type, 1,
        "expected normal Olm message (type=1) since the session is pre-established"
    );

    let pt = bob_low.olm().decrypt(td).wait().await.unwrap().unwrap();
    assert!(bob_low.megolm().decrypt_group_key(&pt).await.unwrap());

    let _ = Duration::from_millis(10);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}