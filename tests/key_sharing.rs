mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::api::low::helpers::key_sharing::KeyRequestStep;
use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, DeviceKeys, Signatures};
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
        master_key: CrossSigningKey { key: msk_pub, signatures: HashMap::new() },
        self_signing_key: CrossSigningKey { key: ssk_pub, signatures: ssk_sigs },
        user_signing_key: CrossSigningKey { key: usk_pub, signatures: usk_sigs },
    }
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
        .expect("upload device signature");

    keys
}

async fn upload_keys_for_low(low: &LockNetLowAgent) {
    let keys = {
        let account = low.store().account().await;
        let mut acc = account.lock().await;
        acc.generate_one_time_keys(50);
        let otks = acc.one_time_keys_b64();
        let keys = DeviceKeys {
            curve25519_key: acc.curve25519_public_b64(),
            ed25519_key: acc.ed25519_public_b64(),
            one_time_keys: otks,
            signatures: HashMap::new(),
        };
        acc.mark_keys_as_published();
        keys
    };
    low.keys().upload(keys).await.expect("upload_keys");
}

async fn setup_olm(
    a_low: &LockNetLowAgent,
    b_low: &LockNetLowAgent,
    b_uid: i64,
    b_sid: i64,
) {
    let mut rx = b_low.subscribe();
    a_low
        .olm()
        .send(b_uid, b_sid, "setup")
        .wait()
        .await
        .expect("olm forward setup");
    let evt = common::wait_event(&mut rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    b_low.olm().decrypt(p).wait().await.expect("forward setup decrypt");

    let mut rx2 = a_low.subscribe();
    b_low
        .olm()
        .send(a_low.user_id(), a_low.session_id(), "setup-rev")
        .wait()
        .await
        .expect("olm reverse setup");
    let evt = common::wait_event(&mut rx2, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    a_low.olm().decrypt(p).wait().await.expect("reverse setup decrypt");
}

// ---- tests ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_sharing_full_flow() {
    let alice = common::register_new("ks_full_a").await;
    let bob = common::register_new("ks_full_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_full(&alice).await;
    setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "KSFull").await;

    let info1 = alice_low.megolm().create(group_id).await.expect("create 1");
    let enc1 = alice_low.megolm().encrypt(group_id, "msg1").await.unwrap();
    let ack1 = alice_low.messages().send(group_id, enc1.clone()).await.unwrap();

    let info2 = alice_low.megolm().rotate(group_id).await.expect("rotate");
    let enc2 = alice_low.megolm().encrypt(group_id, "msg2").await.unwrap();
    let ack2 = alice_low.messages().send(group_id, enc2.clone()).await.unwrap();

    assert!(bob_low.megolm().decrypt(group_id, &enc1).await.unwrap().is_none());
    assert!(bob_low.megolm().decrypt(group_id, &enc2).await.unwrap().is_none());

    // Bob подписывается на alice перед request
    let mut alice_rx = alice_low.subscribe();
    let mut bob_flow = bob_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group_id])
        .await
        .expect("bob request");
    let txid = bob_flow.transaction_id().to_string();

    let incoming = alice_low
        .key_sharing()
        .wait_request(&mut alice_rx, Duration::from_secs(5))
        .await
        .expect("alice wait_request");

    assert_eq!(incoming.transaction_id, txid);
    assert_eq!(incoming.chat_ids, vec![group_id]);
    assert!(incoming.have.is_empty(), "bob не имел ключей — have пустой");

    alice_low
        .key_sharing()
        .send_group_key(
            bob_uid,
            incoming.from_session,
            txid.clone(),
            group_id,
            info1.megolm_session_id.clone(),
            info1.session_key.clone(),
        )
        .await
        .unwrap();
    alice_low
        .key_sharing()
        .send_group_key(
            bob_uid,
            incoming.from_session,
            txid.clone(),
            group_id,
            info2.megolm_session_id.clone(),
            info2.session_key.clone(),
        )
        .await
        .unwrap();
    alice_low
        .key_sharing()
        .send_done(bob_uid, incoming.from_session, txid.clone(), 2)
        .await
        .unwrap();

    let mut imported = Vec::new();
    let mut total = 0u32;
    for _ in 0..10 {
        let step = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
            .await
            .expect("bob next timeout")
            .expect("bob next");
        match step {
            KeyRequestStep::GroupKeyImported { chat_id, megolm_session_id } => {
                assert_eq!(chat_id, group_id);
                imported.push(megolm_session_id);
            }
            KeyRequestStep::Done { total_imported } => {
                total = total_imported;
                break;
            }
            other => panic!("unexpected step: {other:?}"),
        }
    }
    assert_eq!(total, 2);
    assert_eq!(bob_flow.imported_count(), 2);
    assert_eq!(imported.len(), 2);

    let pt1 = bob_low.megolm().decrypt(group_id, &enc1).await.unwrap().unwrap();
    assert_eq!(pt1, "msg1");
    let pt2 = bob_low.megolm().decrypt(group_id, &enc2).await.unwrap().unwrap();
    assert_eq!(pt2, "msg2");

    let again = bob_flow.next().await.expect("bob next again");
    assert!(matches!(again, KeyRequestStep::Done { total_imported: 2 }));

    let _ = (ack1, ack2);
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_sharing_have_filters() {
    let alice = common::register_new("ks_have_a").await;
    let bob = common::register_new("ks_have_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_full(&alice).await;
    setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "KSHave").await;

    let info1 = alice_low.megolm().create(group_id).await.expect("create 1");
    let info2 = alice_low.megolm().rotate(group_id).await.expect("rotate");

    bob_low
        .megolm()
        .import(group_id, info1.megolm_session_id.clone(), info1.session_key.clone())
        .await
        .expect("bob pre-import session1");

    let mut alice_rx = alice_low.subscribe();
    let mut bob_flow = bob_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group_id])
        .await
        .expect("bob request");
    let txid = bob_flow.transaction_id().to_string();

    let incoming = alice_low
        .key_sharing()
        .wait_request(&mut alice_rx, Duration::from_secs(5))
        .await
        .expect("alice wait_request");

    assert_eq!(incoming.transaction_id, txid);
    assert_eq!(incoming.have.len(), 1);
    let expected_item = format!("{}:{}", group_id, info1.megolm_session_id);
    assert_eq!(incoming.have[0], expected_item);

    let have_set: std::collections::HashSet<String> = incoming.have.iter().cloned().collect();
    let mut sent = 0u32;
    if !have_set.contains(&format!("{}:{}", group_id, info1.megolm_session_id)) {
        alice_low.key_sharing().send_group_key(
            bob_uid, incoming.from_session, txid.clone(), group_id,
            info1.megolm_session_id.clone(), info1.session_key.clone(),
        ).await.unwrap();
        sent += 1;
    }
    if !have_set.contains(&format!("{}:{}", group_id, info2.megolm_session_id)) {
        alice_low.key_sharing().send_group_key(
            bob_uid, incoming.from_session, txid.clone(), group_id,
            info2.megolm_session_id.clone(), info2.session_key.clone(),
        ).await.unwrap();
        sent += 1;
    }
    assert_eq!(sent, 1);

    alice_low
        .key_sharing()
        .send_done(bob_uid, incoming.from_session, txid, sent)
        .await
        .unwrap();

    let mut imported_count = 0u32;
    let mut total = 0u32;
    for _ in 0..10 {
        let step = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
            .await
            .expect("timeout")
            .expect("next");
        match step {
            KeyRequestStep::GroupKeyImported { megolm_session_id, .. } => {
                imported_count += 1;
                assert_eq!(megolm_session_id, info2.megolm_session_id);
            }
            KeyRequestStep::Done { total_imported } => {
                total = total_imported;
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(imported_count, 1);
    assert_eq!(total, 1);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_sharing_denied() {
    let alice = common::register_new("ks_den_a").await;
    let bob = common::register_new("ks_den_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_full(&alice).await;
    setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "KSDen").await;
    alice_low.megolm().create(group_id).await.expect("create");

    let mut alice_rx = alice_low.subscribe();
    let mut bob_flow = bob_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group_id])
        .await
        .expect("bob request");
    let txid = bob_flow.transaction_id().to_string();

    let incoming = alice_low
        .key_sharing()
        .wait_request(&mut alice_rx, Duration::from_secs(5))
        .await
        .expect("wait_request");
    assert_eq!(incoming.transaction_id, txid);

    alice_low
        .key_sharing()
        .send_denied(bob_uid, incoming.from_session, txid, "not trusted".to_string())
        .await
        .expect("send_denied");

    let step = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
        .await
        .expect("bob next timeout")
        .expect("bob next");
    match step {
        KeyRequestStep::Denied { reason } => assert_eq!(reason, "not trusted"),
        other => panic!("expected Denied, got {other:?}"),
    }

    let again = bob_flow.next().await.expect("bob next again");
    assert!(matches!(again, KeyRequestStep::Denied { .. }));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_sharing_cancel_before_response() {
    let alice = common::register_new("ks_cnc_a").await;
    let bob = common::register_new("ks_cnc_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_full(&alice).await;
    setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "KSCnc").await;
    alice_low.megolm().create(group_id).await.expect("create");

    let mut bob_flow = bob_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group_id])
        .await
        .expect("bob request");

    bob_flow.cancel().await.expect("cancel");

    let step = bob_flow.next().await.expect("bob next after cancel");
    match step {
        KeyRequestStep::Cancelled(reason) => assert_eq!(reason, "cancelled by user"),
        other => panic!("expected Cancelled, got {other:?}"),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_sharing_done_with_zero() {
    let alice = common::register_new("ks_zero_a").await;
    let bob = common::register_new("ks_zero_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    setup_full(&alice).await;
    setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "KSZero").await;

    let mut alice_rx = alice_low.subscribe();
    let mut bob_flow = bob_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group_id])
        .await
        .expect("bob request");
    let txid = bob_flow.transaction_id().to_string();

    let incoming = alice_low
        .key_sharing()
        .wait_request(&mut alice_rx, Duration::from_secs(5))
        .await
        .expect("wait_request");

    alice_low
        .key_sharing()
        .send_done(bob_uid, incoming.from_session, txid, 0)
        .await
        .unwrap();

    let step = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
        .await
        .expect("timeout")
        .expect("next");
    match step {
        KeyRequestStep::Done { total_imported } => assert_eq!(total_imported, 0),
        other => panic!("expected Done(0), got {other:?}"),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_sharing_second_device_recovers_history() {
    let alice = common::register_new("ks_dev_a").await;
    let bob = common::register_new("ks_dev_b").await;

    let bob_uid = bob.session.user_id;
    let bob_rjwt = bob.session.rjwt.clone();

    let alice_low = alice.low();
    let bob1_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob1_sid = bob.session.session_id;

    setup_full(&alice).await;
    setup_full(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "KSDev").await;

    setup_olm(&alice_low, &bob1_low, bob_uid, bob1_sid).await;
    let info = alice_low.megolm().create(group_id).await.expect("create");
    let enc = alice_low.megolm().encrypt(group_id, "for history").await.unwrap();
    let _ack = alice_low.messages().send(group_id, enc.clone()).await.unwrap();

    let mut bob1_rx = bob1_low.subscribe();
    alice_low
        .megolm()
        .share_group_key(group_id, bob_uid, bob1_sid)
        .await
        .expect("share");
    let evt = common::wait_event(&mut bob1_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(td) = evt else { unreachable!() };
    let pt = bob1_low.olm().decrypt(td).wait().await.unwrap().unwrap();
    bob1_low.megolm().decrypt_group_key(&pt).await.expect("import");
    assert_eq!(
        bob1_low.megolm().decrypt(group_id, &enc).await.unwrap().unwrap(),
        "for history"
    );

    // Bob1 offline
    let mut bob1 = bob;
    bob1.client.disconnect().await.ok();

    // Bob2 reconnect (Session credentials)
    let mut bob2_client = LockNetClient::new(common::test_config());
    let bob2_session = bob2_client
        .connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("bob2 reconnect");
    assert_eq!(bob2_session.user_id, bob_uid);
    let bob2_low = bob2_client.get_low_agent().expect("bob2 low");
    let bob2_sid = bob2_session.session_id;

    // ВАЖНО: Session credentials не вызывают upload_keys в client.rs,
    // и на сервере session.curve25519_key остаётся от bob1.
    // Нужно вручную загрузить ключи bob2, чтобы сервер перезаписал их.
    upload_keys_for_low(&bob2_low).await;

    setup_olm(&alice_low, &bob2_low, bob_uid, bob2_sid).await;

    assert!(bob2_low.megolm().decrypt(group_id, &enc).await.unwrap().is_none());

    let mut alice_rx = alice_low.subscribe();
    let mut bob2_flow = bob2_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group_id])
        .await
        .expect("bob2 request");
    let txid = bob2_flow.transaction_id().to_string();

    let incoming = alice_low
        .key_sharing()
        .wait_request(&mut alice_rx, Duration::from_secs(5))
        .await
        .expect("alice wait_request");
    assert_eq!(incoming.transaction_id, txid);

    let (alice_session_key, _) = alice_low.megolm().ensure_session(group_id).await.expect("ensure");
    assert_eq!(alice_session_key.megolm_session_id, info.megolm_session_id);

    alice_low
        .key_sharing()
        .send_group_key(
            bob_uid,
            incoming.from_session,
            txid.clone(),
            group_id,
            alice_session_key.megolm_session_id.clone(),
            alice_session_key.session_key.clone(),
        )
        .await
        .unwrap();
    alice_low
        .key_sharing()
        .send_done(bob_uid, incoming.from_session, txid, 1)
        .await
        .unwrap();

    let mut imported = 0u32;
    for _ in 0..10 {
        let step = tokio::time::timeout(Duration::from_secs(10), bob2_flow.next())
            .await
            .expect("timeout")
            .expect("next");
        match step {
            KeyRequestStep::GroupKeyImported { .. } => imported += 1,
            KeyRequestStep::Done { total_imported } => {
                assert_eq!(total_imported, 1);
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(imported, 1);

    // Фикс: key_request теперь передаёт group_data — у Bob2 должна появиться policy
    assert!(
        bob2_low.store().group_data_state(group_id).await.is_some(),
        "Bob2 должен получить group_data через key_request"
    );

    let pt = bob2_low.megolm().decrypt(group_id, &enc).await.unwrap().unwrap();
    assert_eq!(pt, "for history");

    bob2_client.disconnect().await.ok();
    let mut a = alice;
    a.client.disconnect().await.ok();
}