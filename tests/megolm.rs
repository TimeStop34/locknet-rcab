mod common;

use std::time::Duration;

use locknet_rcab::{models::Encrypted, Event, LockNetLowAgent};

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

async fn alice_curve25519(low: &LockNetLowAgent) -> String {
    let acc = low.store().account().await;
    let a = acc.lock().await;
    a.curve25519_public_b64()
}

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
    assert!(pt.is_none(), "bob shouldn't decrypt without key, got {pt:?}");

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

    let pt2 = bob_low.megolm().decrypt(group_id, &enc2).await.unwrap();
    assert!(pt2.is_none(), "bob shouldn't decrypt msg2");

    let pt1_again = bob_low.megolm().decrypt(group_id, &enc1).await.unwrap();
    assert_eq!(pt1_again.as_deref(), Some("msg1"));

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_ensure_session_idempotent() {
    let alice = common::register_new("mg_ens_a").await;
    let bob = common::register_new("mg_ens_b").await;
    let alice_low = alice.low();
    let group_id = common::setup_group_with_two(&alice, &bob, "MegolmEns").await;

    let s1 = alice_low.megolm().ensure_session(group_id).await.expect("ensure 1");
    let s2 = alice_low.megolm().ensure_session(group_id).await.expect("ensure 2");
    assert_eq!(s1.megolm_session_id, s2.megolm_session_id);
    assert_eq!(s1.session_key, s2.session_key);

    let a = alice_low.megolm().encrypt(group_id, "text").await.unwrap();
    assert_eq!(a.megolm_session_id, s1.megolm_session_id);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_decrypt_group_key_wrong_type_returns_false() {
    let bob = common::register_new("mg_wt_b").await;
    let bob_low = bob.low();

    let pt_not_json = "not json at all";
    assert!(!bob_low.megolm().decrypt_group_key(pt_not_json).await.unwrap());

    let pt_wrong_type = r#"{"type":"ln.something.else","content":{}}"#;
    assert!(!bob_low.megolm().decrypt_group_key(pt_wrong_type).await.unwrap());

    let pt_missing_content = r#"{"type":"ln.encryption.group_key"}"#;
    let res = bob_low.megolm().decrypt_group_key(pt_missing_content).await;
    assert!(res.is_err(), "expected error for missing content, got {res:?}");

    let mut b = bob;
    b.client.disconnect().await.ok();
}

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
        "expected normal olm message (type=1) since olm session pre-established"
    );

    let pt = bob_low.olm().decrypt(td).wait().await.unwrap().unwrap();
    assert!(bob_low.megolm().decrypt_group_key(&pt).await.unwrap());

    let _ = Duration::from_millis(10);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}