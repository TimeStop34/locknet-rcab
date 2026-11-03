mod common;

use std::time::Duration;

use locknet_rcab::HighEvent;
use tokio::sync::broadcast;

async fn wait_high_event<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
where
    F: Fn(&HighEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!("timeout waiting for HighEvent");
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(evt)) if pred(&evt) => return evt,
            Ok(Ok(_)) => continue,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => panic!("channel closed"),
            Err(_) => panic!("timeout waiting for HighEvent"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_sends_bob_decrypts_via_high() {
    let alice = common::register_new("hs_ab_a").await;
    let bob = common::register_new("hs_ab_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");

    // Olm-сессии не нужны напрямую — high сам сделает fan-out через send_group_key
    let group_id = common::setup_group_with_two(&alice, &bob, "HS_AB").await;

    // Bob подписывается ДО отправки
    let mut bob_rx = bob_agent.subscribe();

    // Alice через Chat::send
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let sent = alice_chat.send("hello through high").await.expect("send");

    assert!(sent.encrypted);
    assert_eq!(sent.text.as_deref(), Some("hello through high"));

    // Bob получает HighEvent::NewMessage — текст должен расшифроваться в process_event
    let evt = wait_high_event(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;

    match evt {
        HighEvent::NewMessage { chat, message } => {
            assert_eq!(chat.id(), group_id);
            assert_eq!(message.id, sent.id);
            assert_eq!(message.text.as_deref(), Some("hello through high"));
            assert!(message.encrypted);
        }
        _ => unreachable!(),
    }

    // И в истории через Chat::messages
    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let history = bob_chat.messages(None, 20).await.expect("messages");
    let found = history
        .iter()
        .find(|m| m.id == sent.id)
        .expect("message in history");
    assert_eq!(found.text.as_deref(), Some("hello through high"));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_sends_to_three_participants() {
    let alice = common::register_new("hs3_a").await;
    let bob = common::register_new("hs3_b").await;
    let charlie = common::register_new("hs3_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let charlie_agent = charlie.client.get_agent().expect("charlie agent");

    // Alice создаёт приватную группу с Bob и Charlie
    let group = alice_agent
        .create_group(
            "HS3",
            false,
            None,
            vec![bob.session.user_id, charlie.session.user_id],
        )
        .await
        .expect("create");

    // Bob и Charlie принимают
    let bob_invites = bob_agent.invites().await.expect("bob invites");
    let bob_inv = bob_invites
        .iter()
        .find(|i| i.group.id == group.id())
        .expect("bob inv");
    bob_agent
        .accept_invite(bob_inv.id)
        .await
        .expect("bob accept");

    let charlie_invites = charlie_agent.invites().await.expect("charlie invites");
    let charlie_inv = charlie_invites
        .iter()
        .find(|i| i.group.id == group.id())
        .expect("charlie inv");
    charlie_agent
        .accept_invite(charlie_inv.id)
        .await
        .expect("charlie accept");

    // Alice берёт свежий чат с полным составом
    let alice_chat = alice_agent.chat(group.id()).await.expect("alice chat fresh");

    let mut bob_rx = bob_agent.subscribe();
    let mut charlie_rx = charlie_agent.subscribe();

    let sent = alice_chat.send("to everyone").await.expect("send");
    assert!(sent.encrypted);

    let evt_b = wait_high_event(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_b {
        assert_eq!(message.text.as_deref(), Some("to everyone"));
    }

    let evt_c = wait_high_event(&mut charlie_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_c {
        assert_eq!(message.text.as_deref(), Some("to everyone"));
    }

    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_change_rotates_megolm() {
    let alice = common::register_new("hs_rot_a").await;
    let bob = common::register_new("hs_rot_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let _alice_low = alice.low();
    let bob_low = bob.low();

    let group_id = common::setup_group_with_two(&alice, &bob, "HS_Rot").await;

    // Первое сообщение — S1
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");

    // Подписка ДО send — иначе пропустим NewMessage
    let mut bob_rx = bob_agent.subscribe();

    let first = alice_chat.send("msg1 pre-bob-leave").await.expect("send1");
    let first_enc = first.encrypted_payload.clone().expect("first enc");
    let s1 = first_enc.megolm_session_id.clone();

    // Ждём, пока Bob получит и обработает msg1 (значит group_key уже импортирован)
    let _ = wait_high_event(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == first.id)
    })
    .await;

    // Bob успешно расшифровывает msg1 и имеет S1
    let pt1 = bob_low
        .megolm()
        .decrypt(group_id, &first_enc)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pt1, "msg1 pre-bob-leave");
    assert!(
        bob_low.store().megolm_inbound(group_id, &s1).is_some(),
        "у Bob должен быть S1"
    );

    // Bob leaves. Подписка ДО — чтобы поймать событие ротации на Alice
    let mut alice_rx = alice_agent.subscribe();
    bob_agent.leave_chat(group_id).await.expect("bob leave");

    // Ждём GroupMembershipChanged(Left) на Alice — к этому моменту ротация уже сделана
    // (в process_event ротация происходит ДО event_tx.send)
    let _ = wait_high_event(&mut alice_rx, |e| {
        matches!(
            e,
            HighEvent::GroupMembershipChanged {
                change: locknet_rcab::api::low::models::MembershipChange::Left,
                ..
            }
        )
    })
    .await;

    // Alice в свежем Chat шлёт msg2 — сессия должна отличаться
    let alice_chat2 = alice_agent.chat(group_id).await.expect("alice chat fresh");
    let second = alice_chat2.send("msg2 post-bob").await.expect("send2");
    let second_enc = second.encrypted_payload.clone().expect("second enc");
    let s2 = second_enc.megolm_session_id.clone();

    assert_ne!(s1, s2, "megolm должна ротироваться после leave");

    // Bob: S2 нет, S1 остался
    assert!(
        bob_low.store().megolm_inbound(group_id, &s2).is_none(),
        "у Bob НЕ должно быть S2"
    );
    assert!(
        bob_low.store().megolm_inbound(group_id, &s1).is_some(),
        "у Bob должен остаться S1"
    );

    // Bob не может расшифровать msg2 (нет S2), но msg1 — может
    let pt2 = bob_low
        .megolm()
        .decrypt(group_id, &second_enc)
        .await
        .unwrap();
    assert!(pt2.is_none(), "Bob не должен расшифровать msg2");

    let pt1_again = bob_low
        .megolm()
        .decrypt(group_id, &first_enc)
        .await
        .unwrap();
    assert_eq!(pt1_again.as_deref(), Some("msg1 pre-bob-leave"));

    // Alice видит оба сообщения в истории
    let alice_hist = alice_chat2
        .messages(None, 20)
        .await
        .expect("alice history");
    assert!(alice_hist
        .iter()
        .any(|m| m.text.as_deref() == Some("msg1 pre-bob-leave")));
    assert!(alice_hist
        .iter()
        .any(|m| m.text.as_deref() == Some("msg2 post-bob")));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_group_uses_plaintext() {
    let alice = common::register_new("hs_pub_a").await;
    let bob = common::register_new("hs_pub_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");

    let public_id = format!("&hspub{}", common::unique_suffix());
    let group = alice_agent
        .create_group("HS_Pub", true, Some(public_id.clone()), vec![])
        .await
        .expect("create public");

    bob_agent
        .join_group(public_id)
        .await
        .expect("bob join");

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group.id()).await.expect("alice chat");
    let sent = alice_chat.send("plaintext hello").await.expect("send");

    assert!(!sent.encrypted, "public groups use plaintext");

    let evt = wait_high_event(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;

    match evt {
        HighEvent::NewMessage { message, .. } => {
            assert_eq!(message.text.as_deref(), Some("plaintext hello"));
            assert!(!message.encrypted);
        }
        _ => unreachable!(),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}