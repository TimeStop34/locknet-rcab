mod common;

use std::time::Duration;

use locknet_rcab::{Credentials, Event, LockNetClient, LockNetError};

// ---- manual reconnect ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_reconnect_preserves_session_and_works() {
    let alice = common::register_new("rc_alice").await;
    let bob = common::register_new("rc_bob").await;

    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let alice_rjwt = alice.session.rjwt.clone();

    let group_id = common::setup_group_with_two(&alice, &bob, "RC").await;

    // Alice шлёт сообщение ДО disconnect
    let alice_low = alice.low();
    let ack1 = alice_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice_sid, "before reconnect"),
        )
        .await
        .expect("send before");
    assert!(ack1.message_id > 0);

    // Alice disconnect
    let mut alice = alice;
    alice.client.disconnect().await.expect("disconnect");

    // Alice reconnect через Session credentials
    let mut alice2 = LockNetClient::new(common::test_config());
    let s2 = alice2
        .connection_request(Credentials::Session {
            refresh_jwt: alice_rjwt,
        })
        .await
        .expect("reconnect");

    assert_eq!(s2.user_id, alice_uid, "same user");
    assert_eq!(s2.session_id, alice_sid, "refresh keeps session_id");
    assert!(alice2.get_low_agent().is_some(), "runner started");
    assert!(alice2.get_agent().is_some(), "agent available");

    // Отправляем новое сообщение — работает
    let alice2_low = alice2.get_low_agent().expect("low");
    let ack2 = alice2_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice_sid, "after reconnect"),
        )
        .await
        .expect("send after");
    assert!(ack2.message_id > ack1.message_id);

    // Bob видит оба сообщения в истории
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let history = bob_chat.messages(None, 20).await.expect("bob history");
    assert!(
        history.iter().any(|m| m.id == ack1.message_id),
        "msg before reconnect in history"
    );
    assert!(
        history.iter().any(|m| m.id == ack2.message_id),
        "msg after reconnect in history"
    );

    alice2.disconnect().await.ok();
    let mut b = bob;
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_with_invalid_refresh_jwt_fails() {
    let mut c = LockNetClient::new(common::test_config());
    let err = c
        .connection_request(Credentials::Session {
            refresh_jwt: "not.a.valid.jwt".into(),
        })
        .await
        .unwrap_err();

    // HTTP 401 от сервера → http::refresh мапит в SessionExpired.
    // Но сначала может упасть на decode (если сервер вернул 200 с битым токеном).
    // Ожидаем любой из вариантов, не панику.
    assert!(
        matches!(
            err,
            LockNetError::SessionExpired
                | LockNetError::InvalidCredentials
                | LockNetError::InvalidResponse(_)
        ),
        "expected SessionExpired/InvalidCredentials/InvalidResponse, got {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_drains_offline_events() {
    // Bob offline → Alice шлёт 2 сообщения → Bob reconnects через Session →
    // event_sync находит накопленные message_create.
    let alice = common::register_new("rc_drain_a").await;
    let bob = common::register_new("rc_drain_b").await;

    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;
    let bob_rjwt = bob.session.rjwt.clone();

    let group_id = common::setup_group_with_two(&alice, &bob, "RCDrain").await;

    let alice_low = alice.low();

    // Bob offline
    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Alice шлёт 2 сообщения
    let mut msg_ids = Vec::new();
    for i in 0..2 {
        let ack = alice_low
            .messages()
            .send(
                group_id,
                common::fake_encrypted(alice.session.session_id, &format!("off{i}")),
            )
            .await
            .expect("send");
        msg_ids.push(ack.message_id);
    }

    // Bob reconnects
    let mut bob2 = LockNetClient::new(common::test_config());
    let s2 = bob2
        .connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("reconnect");
    assert_eq!(s2.user_id, bob_uid);
    assert_eq!(s2.session_id, bob_sid);

    let bob2_low = bob2.get_low_agent().expect("low");
    let mut bob2_rx = bob2_low.subscribe();

    let ack = bob2_low.events().sync().await.expect("sync");
    assert!(ack.sent >= 2, "expected >=2 events, got {}", ack.sent);

    // Проверяем, что subscriber получил message_create для наших id
    let mut received = Vec::new();
    for _ in 0..60 {
        match tokio::time::timeout(Duration::from_millis(80), bob2_rx.recv()).await {
            Ok(Ok(Event::MessageCreate(m))) => {
                if msg_ids.contains(&m.message_id) {
                    received.push(m.message_id);
                    if received.len() == 2 {
                        break;
                    }
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(received.len(), 2, "2 message_create events drained");

    bob2.disconnect().await.ok();
    let mut a = alice;
    a.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_idempotent_when_already_connected() {
    // connection_request на активном client сначала вызывает disconnect() —
    // новый runner стартует, старый гасится. Никаких утечек/паник.
    let mut alice = common::register_new("rc_idem").await;
    let rjwt = alice.session.rjwt.clone();

    // Reconnect через тот же client
    let s2 = alice
        .client
        .connection_request(Credentials::Session { refresh_jwt: rjwt })
        .await
        .expect("reconnect on same client");
    assert_eq!(s2.session_id, alice.session.session_id);

    let low = alice.client.get_low_agent().expect("low still available");
    assert_eq!(low.user_id(), alice.session.user_id);

    alice.client.disconnect().await.ok();
}