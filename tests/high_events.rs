mod common;

use std::time::Duration;

use locknet_rcab::api::low::models::MembershipChange;
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
async fn bob_receives_new_message_high_event() {
    let alice = common::register_new("he_new_a").await;
    let bob = common::register_new("he_new_b").await;

    let alice_low = alice.low();
    let bob_agent = bob.client.get_agent().expect("bob high agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HENew").await;

    let mut bob_rx = bob_agent.subscribe();

    let enc = common::fake_encrypted(alice.session.session_id, "hello via high");
    let ack = alice_low
        .messages()
        .send(group_id, enc)
        .await
        .expect("send");

    let evt = wait_high_event(&mut bob_rx, |e| matches!(e, HighEvent::NewMessage { .. })).await;

    match evt {
        HighEvent::NewMessage { chat, message } => {
            assert_eq!(chat.id(), group_id);
            assert_eq!(message.id, ack.message_id);
            assert_eq!(message.chat_id, group_id);
            assert_eq!(message.author.id, alice.session.user_id);
            assert_eq!(message.author_session_id, alice.session.session_id);
            assert!(message.encrypted);
            assert!(message.encrypted_payload.is_some());
            assert!(!message.deleted);
        }
        _ => unreachable!(),
    }

    let cached = bob_agent
        .cached_message(ack.message_id)
        .expect("message cached in state");
    assert_eq!(cached.id, ack.message_id);
    assert_eq!(cached.chat_id, group_id);
    assert!(!cached.deleted);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bob_receives_message_updated() {
    let alice = common::register_new("he_upd_a").await;
    let bob = common::register_new("he_upd_b").await;

    let alice_low = alice.low();
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HEUpd").await;

    // Подписка ДО send — иначе NewMessage улетит мимо
    let mut rx = bob_agent.subscribe();

    let ack = alice_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice.session.session_id, "original"),
        )
        .await
        .expect("send");

    // Дожидаемся NewMessage, чтобы state точно пополнился (process_event уже сработал)
    let _ = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == ack.message_id)
    })
    .await;

    // edit — ждём MessageUpdated на той же подписке
    alice_low
        .messages()
        .edit(
            ack.message_id,
            common::fake_encrypted(alice.session.session_id, "edited"),
        )
        .await
        .expect("edit");

    let evt = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::MessageUpdated { message, .. } if message.id == ack.message_id)
    })
    .await;

    match evt {
        HighEvent::MessageUpdated { chat, message } => {
            assert_eq!(chat.id(), group_id);
            assert!(message.edited_at.is_some());
        }
        _ => unreachable!(),
    }

    let cached = bob_agent.cached_message(ack.message_id).expect("cached");
    assert!(cached.edited_at.is_some());

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bob_receives_message_deleted() {
    let alice = common::register_new("he_del_a").await;
    let bob = common::register_new("he_del_b").await;

    let alice_low = alice.low();
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HEDel").await;

    let mut rx = bob_agent.subscribe();

    let ack = alice_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice.session.session_id, "to delete"),
        )
        .await
        .expect("send");

    let _ = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == ack.message_id)
    })
    .await;

    alice_low
        .messages()
        .delete(ack.message_id)
        .await
        .expect("delete");

    let evt = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::MessageDeleted { message_id, .. } if *message_id == ack.message_id)
    })
    .await;

    match evt {
        HighEvent::MessageDeleted { chat_id, message_id } => {
            assert_eq!(chat_id, group_id);
            assert_eq!(message_id, ack.message_id);
        }
        _ => unreachable!(),
    }

    let cached = bob_agent.cached_message(ack.message_id).expect("cached");
    assert!(cached.deleted);
    assert!(cached.encrypted_payload.is_none());
    assert!(cached.text.is_none());

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_receives_reaction_added() {
    let alice = common::register_new("he_radd_a").await;
    let bob = common::register_new("he_radd_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_agent = alice.client.get_agent().expect("alice agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HERAdd").await;

    let ack = alice_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice.session.session_id, "react to me"),
        )
        .await
        .expect("send");

    let mut alice_rx = alice_agent.subscribe();
    bob_low
        .messages()
        .add_reaction(ack.message_id, "👍")
        .await
        .expect("add reaction");

    let evt = wait_high_event(&mut alice_rx, |e| {
        matches!(e, HighEvent::ReactionAdded { message_id, .. } if *message_id == ack.message_id)
    })
    .await;

    match evt {
        HighEvent::ReactionAdded { chat_id, message_id, user, emoji } => {
            assert_eq!(chat_id, group_id);
            assert_eq!(message_id, ack.message_id);
            assert_eq!(user.id, bob.session.user_id);
            assert_eq!(emoji, "👍");
        }
        _ => unreachable!(),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bob_state_reaction_added_and_removed() {
    let alice = common::register_new("he_rst_a").await;
    let bob = common::register_new("he_rst_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HERst").await;

    // Подписка ДО send
    let mut rx = bob_agent.subscribe();

    let ack = alice_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice.session.session_id, "react state"),
        )
        .await
        .expect("send");

    let _ = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == ack.message_id)
    })
    .await;

    // Bob добавляет реакцию
    bob_low
        .messages()
        .add_reaction(ack.message_id, "🎉")
        .await
        .expect("add");

    let _ = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::ReactionAdded { message_id, .. } if *message_id == ack.message_id)
    })
    .await;

    let cached = bob_agent.cached_message(ack.message_id).expect("cached");
    assert_eq!(cached.reactions.len(), 1);
    assert_eq!(cached.reactions[0].emoji, "🎉");
    assert_eq!(cached.reactions[0].count, 1);
    assert_eq!(cached.reactions[0].user_ids, vec![bob.session.user_id]);

    // Remove — реакция исчезает полностью
    bob_low
        .messages()
        .remove_reaction(ack.message_id, "🎉")
        .await
        .expect("remove");

    let _ = wait_high_event(&mut rx, |e| {
        matches!(e, HighEvent::ReactionRemoved { message_id, .. } if *message_id == ack.message_id)
    })
    .await;

    let cached = bob_agent.cached_message(ack.message_id).expect("cached");
    assert!(cached.reactions.is_empty(), "reaction removed полностью");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bob_receives_invite_via_high_event() {
    let alice = common::register_new("he_inv_a").await;
    let bob = common::register_new("he_inv_b").await;

    let alice_low = alice.low();
    let bob_agent = bob.client.get_agent().expect("bob agent");

    let mut bob_rx = bob_agent.subscribe();

    let group = alice_low
        .groups()
        .create("HEInv", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    let evt = wait_high_event(&mut bob_rx, |e| {
        matches!(e, HighEvent::InviteReceived { .. })
    })
    .await;

    match evt {
        HighEvent::InviteReceived { invite } => {
            assert_eq!(invite.group.id, group.id);
            assert_eq!(invite.inviter.id, alice.session.user_id);
            assert_eq!(invite.group.name, "HEInv");
        }
        _ => unreachable!(),
    }

    let invites = bob_agent.invites().await.expect("invites");
    assert!(invites.iter().any(|i| i.group.id == group.id));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_receives_membership_added_and_left() {
    let alice = common::register_new("he_mc_a").await;
    let bob = common::register_new("he_mc_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_agent = alice.client.get_agent().expect("alice agent");

    let public_id = format!("&hem{}", common::unique_suffix());
    let group = alice_low
        .groups()
        .create("HEMC", true, Some(public_id.clone()), vec![])
        .await
        .expect("create");

    // Подписка ДО join
    let mut alice_rx = alice_agent.subscribe();

    bob_low
        .groups()
        .join(public_id.clone())
        .await
        .expect("join");

    let evt = wait_high_event(&mut alice_rx, |e| {
        matches!(
            e,
            HighEvent::GroupMembershipChanged { change: MembershipChange::Added, .. }
        )
    })
    .await;

    match evt {
        HighEvent::GroupMembershipChanged { group_id, change, user } => {
            assert_eq!(group_id, group.id);
            assert_eq!(change, MembershipChange::Added);
            assert_eq!(user.id, bob.session.user_id);
        }
        _ => unreachable!(),
    }

    // leave — та же подписка, дождёмся следующего события
    bob_low
        .groups()
        .leave(group.id)
        .await
        .expect("leave");

    let evt = wait_high_event(&mut alice_rx, |e| {
        matches!(
            e,
            HighEvent::GroupMembershipChanged { change: MembershipChange::Left, .. }
        )
    })
    .await;

    match evt {
        HighEvent::GroupMembershipChanged { group_id, change, user } => {
            assert_eq!(group_id, group.id);
            assert_eq!(change, MembershipChange::Left);
            assert_eq!(user.id, bob.session.user_id);
        }
        _ => unreachable!(),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn high_event_fires_for_uncached_chat() {
    let alice = common::register_new("he_unc_a").await;
    let bob = common::register_new("he_unc_b").await;

    let alice_low = alice.low();
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HEUnc").await;

    assert!(
        bob_agent.cached_chats().is_empty(),
        "Bob не вызывал agent.chat() — кэш должен быть пуст"
    );

    let mut bob_rx = bob_agent.subscribe();
    alice_low
        .messages()
        .send(
            group_id,
            common::fake_encrypted(alice.session.session_id, "uncached"),
        )
        .await
        .expect("send");

    let evt = wait_high_event(&mut bob_rx, |e| matches!(e, HighEvent::NewMessage { .. })).await;
    match evt {
        HighEvent::NewMessage { chat, .. } => {
            assert_eq!(chat.id(), group_id);
        }
        _ => unreachable!(),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}