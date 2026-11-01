mod common;

use locknet_rcab::Event;

async fn olm_setup_warm(alice_low: &locknet_rcab::LockNetLowAgent, bob_low: &locknet_rcab::LockNetLowAgent,
                         bob_uid: i64, bob_sid: i64) {
    let mut rx = bob_low.subscribe();
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "warmup")
        .wait()
        .await
        .expect("olm warmup send");

    let evt = common::wait_event(&mut rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    bob_low
        .olm()
        .decrypt(p)
        .wait()
        .await
        .expect("olm warmup decrypt");
}

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
    let Event::ToDevice(payload) = evt else { unreachable!() };

    // Сервер должен перезаписать sender_key/sender_session_id
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

    // Alice → Bob
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "hi bob")
        .wait()
        .await
        .expect("alice send");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    let pt = bob_low.olm().decrypt(p).wait().await.expect("bob decrypt").unwrap();
    assert_eq!(pt, "hi bob");

    // Bob → Alice (должна использоваться установленная inbound-сессия)
    bob_low
        .olm()
        .send(alice_uid, alice_sid, "hi alice")
        .wait()
        .await
        .expect("bob send");

    let evt = common::wait_event(&mut alice_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    let pt = alice_low.olm().decrypt(p).wait().await.expect("alice decrypt").unwrap();
    assert_eq!(pt, "hi alice");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

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

    // 1. Alice → Bob: "first" (prekey, type=0)
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "first")
        .wait()
        .await
        .expect("send #1");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p1) = evt else { unreachable!() };

    // Проверяем, что первое сообщение действительно prekey (type=0)
    let bob_curve = {
        let acc = bob_low.store().account();
        let a = acc.lock().await;
        a.curve25519_public_b64()
    };
    let inner1 = p1.ciphertext.get(&bob_curve).expect("ciphertext for bob");
    assert_eq!(inner1.ciphertext_type, 0, "first message must be prekey (type=0)");

    let pt1 = bob_low.olm().decrypt(p1).wait().await.expect("decrypt #1").unwrap();
    assert_eq!(pt1, "first");

    // 2. Bob → Alice: "ack" (устанавливает сессию на обеих сторонах)
    bob_low
        .olm()
        .send(alice_uid, alice_sid, "ack")
        .wait()
        .await
        .expect("send ack");

    let evt = common::wait_event(&mut alice_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(pa) = evt else { unreachable!() };
    let pta = alice_low.olm().decrypt(pa).wait().await.expect("decrypt ack").unwrap();
    assert_eq!(pta, "ack");

    // 3. Alice → Bob: "second" — должен быть type=1 (normal), не prekey
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "second")
        .wait()
        .await
        .expect("send #2");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p2) = evt else { unreachable!() };
    let inner2 = p2.ciphertext.get(&bob_curve).expect("ciphertext");
    assert_eq!(
        inner2.ciphertext_type, 1,
        "second message must be normal (type=1), got {}",
        inner2.ciphertext_type
    );

    let pt2 = bob_low.olm().decrypt(p2).wait().await.expect("decrypt #2").unwrap();
    assert_eq!(pt2, "second");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_decrypt_returns_none_without_session() {
    // Сценарий: Bob получает type=1 (normal) сообщение от Alice, но не имеет сессии —
    // не prekey → decrypt_impl вернёт Ok(None)
    let alice = common::register_new("olm_none_a").await;
    let bob = common::register_new("olm_none_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;

    let bob_curve = {
        let acc = bob_low.store().account();
        let a = acc.lock().await;
        a.curve25519_public_b64()
    };
    let _ = bob_uid;

    // Формируем "фейковое" normal-сообщение: type=1, тело — невалидный base64-olmsgs
    // но decrypt_impl сначала ищет сессии, не находит, а затем для type!=0 → None
    let mut ciphertext = std::collections::HashMap::new();
    ciphertext.insert(
        bob_curve,
        locknet_rcab::models::ToDeviceCiphertext {
            ciphertext_type: 1,
            body: "AAAA".to_string(), // мусор — но не prekey, значит не парсится в prekey
        },
    );
    let payload = locknet_rcab::models::ToDevicePayload {
        algorithm: "ln.encryption.olm.v1".into(),
        sender_key: "some_fake_curve".into(),
        sender_session_id: alice_sid,
        ciphertext,
    };

    let result = bob_low.olm().decrypt(payload).wait().await;
    assert!(matches!(result, Ok(None)), "expected Ok(None), got {result:?}");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_decrypt_wrong_algorithm_fails() {
    let bob = common::register_new("olm_alg_b").await;
    let bob_low = bob.low();
    let bob_curve = {
        let acc = bob_low.store().account();
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