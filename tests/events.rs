mod common;

use std::time::Duration;

use locknet_rcab::{Credentials, Event, LockNetClient};

#[tokio::test]
async fn events_offline_drain_and_reconnect() {
    let alice = common::register_new("ev_drain_a").await;
    let bob = common::register_new("ev_drain_b").await;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;
    let bob_rjwt = bob.session.rjwt.clone();
    let alice_low = alice.low();

    // Bob offline
    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Alice создаёт 3 группы с Bob → 3 group_invite_created в очередь
    let mut created_ids = Vec::new();
    for i in 0..3 {
        let g = alice_low
            .groups()
            .create(&format!("EvDrain{i}"), false, None, vec![bob_uid])
            .await
            .expect("create");
        created_ids.push(g.id);
    }

    // Bob reconnects через rjwt — session_id должен сохраниться
    let mut bob2 = LockNetClient::new(common::test_config());
    let s2 = bob2
        .connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("reconnect");
    assert_eq!(s2.user_id, bob_uid);
    assert_eq!(s2.session_id, bob_sid, "refresh preserves session_id");

    let bob2_low = bob2.get_low_agent().expect("low agent");
    let mut bob_rx = bob2_low.subscribe();

    // Sync — события должны прийти push'ами во время обработки
    let ack = bob2_low.events().sync().await.expect("sync");
    assert!(ack.sent >= 3, "expected >=3 events, got {}", ack.sent);
    assert!(!ack.more, "3 events < 200 → more должен быть false");

    // Проверяем, что subscriber получил 3 group_invite_created
    let mut invite_count = 0;
    for _ in 0..60 {
        match tokio::time::timeout(Duration::from_millis(80), bob_rx.recv()).await {
            Ok(Ok(Event::GroupInviteCreated(e))) => {
                assert!(
                    created_ids.contains(&e.group_id),
                    "unexpected group_id {}",
                    e.group_id
                );
                invite_count += 1;
                if invite_count == 3 {
                    break;
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(invite_count, 3, "expected 3 group_invite_created events");

    // API видит 3 приглашения
    let invites = bob2_low.groups().invites().await.expect("invites");
    let bob_invites: Vec<_> = invites
        .iter()
        .filter(|i| created_ids.contains(&i.group_id))
        .collect();
    assert_eq!(bob_invites.len(), 3);

    // Повторный sync — пусто
    let ack2 = bob2_low.events().sync().await.expect("sync2");
    assert_eq!(ack2.sent, 0);
    assert!(!ack2.more);

    bob2.disconnect().await.ok();
    let mut alice = alice;
    alice.client.disconnect().await.ok();
}

#[tokio::test]
async fn events_sync_until_empty_helper() {
    let alice = common::register_new("ev_sue_a").await;
    let bob = common::register_new("ev_sue_b").await;
    let bob_uid = bob.session.user_id;
    let bob_rjwt = bob.session.rjwt.clone();
    let alice_low = alice.low();

    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    for i in 0..2 {
        alice_low
            .groups()
            .create(&format!("EvSUE{i}"), false, None, vec![bob_uid])
            .await
            .expect("create");
    }

    let mut bob2 = LockNetClient::new(common::test_config());
    bob2.connection_request(Credentials::Session {
        refresh_jwt: bob_rjwt,
    })
    .await
    .expect("reconnect");

    let bob2_low = bob2.get_low_agent().expect("low agent");

    let total = bob2_low
        .events()
        .sync_until_empty(10)
        .await
        .expect("sync_until_empty");
    assert!(total >= 2, "expected >=2 events total, got {}", total);

    let total2 = bob2_low
        .events()
        .sync_until_empty(10)
        .await
        .expect("sync2");
    assert_eq!(total2, 0, "second sync_until_empty must be empty");

    bob2.disconnect().await.ok();
    let mut alice = alice;
    alice.client.disconnect().await.ok();
}

#[tokio::test]
async fn events_message_queue_offline() {
    let alice = common::register_new("ev_msg_a").await;
    let bob = common::register_new("ev_msg_b").await;
    let bob_rjwt = bob.session.rjwt.clone();

    // Bob онлайн, принимает invite
    let group_id = common::setup_group_with_two(&alice, &bob, "EvMsg").await;

    let alice_low = alice.low();

    // Bob offline
    let mut bob = bob;
    bob.client.disconnect().await.ok();
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Alice шлёт 2 сообщения — они должны попасть в очередь для Bob
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

    // Bob reconnects и синкает
    let mut bob2 = LockNetClient::new(common::test_config());
    bob2.connection_request(Credentials::Session {
        refresh_jwt: bob_rjwt,
    })
    .await
    .expect("reconnect");

    let bob2_low = bob2.get_low_agent().expect("low agent");
    let mut bob_rx = bob2_low.subscribe();

    let ack = bob2_low.events().sync().await.expect("sync");
    assert!(ack.sent >= 2, "expected >=2 events, got {}", ack.sent);

    // Проверяем, что subscriber получил message_create для наших id
    let mut received = Vec::new();
    for _ in 0..60 {
        match tokio::time::timeout(Duration::from_millis(80), bob_rx.recv()).await {
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
    assert_eq!(received.len(), 2, "expected 2 message_create events");

    // Сообщения видны в истории
    let page = bob2_low
        .messages()
        .get(group_id, None, 20)
        .await
        .expect("get");
    for id in &msg_ids {
        assert!(
            page.messages.iter().any(|m| m.message_id == *id),
            "message {id} not in history"
        );
    }

    bob2.disconnect().await.ok();
    let mut alice = alice;
    alice.client.disconnect().await.ok();
}