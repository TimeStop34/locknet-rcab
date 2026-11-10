mod common;

use locknet_rcab::{models::Encrypted, Event};

fn fake_enc(session_id: i64, plaintext: &str) -> Encrypted {
    common::fake_encrypted(session_id, plaintext)
}

#[tokio::test]
async fn send_and_get_messages() {
    let alice = common::register_new("msg_sg_a").await;
    let bob = common::register_new("msg_sg_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgGet").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let ack = alice_low
        .messages()
        .send(group_id, fake_enc(alice.session.session_id, "hello bob"))
        .await
        .expect("send");
    assert!(ack.message_id > 0);

    let page = bob_low
        .messages()
        .get(group_id, None, 20)
        .await
        .expect("get");
    let found = page
        .messages
        .iter()
        .find(|m| m.message_id == ack.message_id)
        .expect("message visible to bob");

    assert_eq!(found.chat_id, group_id);
    assert_eq!(found.author_id, alice.session.user_id);
    assert_eq!(found.author_session_id, alice.session.session_id);
    assert!(!found.deleted);
    let enc = found.encrypted.as_ref().expect("encrypted present");
    assert_eq!(common::decode_fake(&enc.ciphertext), "hello bob");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn get_messages_has_more() {
    let alice = common::register_new("msg_hm_a").await;
    let bob = common::register_new("msg_hm_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgHM").await;

    let alice_low = alice.low();

    for i in 0..3 {
        alice_low
            .messages()
            .send(group_id, fake_enc(alice.session.session_id, &format!("m{i}")))
            .await
            .expect("send");
    }

    let page = alice_low
        .messages()
        .get(group_id, None, 1)
        .await
        .expect("get limit=1");

    assert_eq!(page.messages.len(), 1);
    assert!(page.has_more, "expected has_more=true");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn bob_receives_message_create_push() {
    let alice = common::register_new("msg_push_a").await;
    let bob = common::register_new("msg_push_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgPush").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let mut bob_rx = bob_low.subscribe();

    let ack = alice_low
        .messages()
        .send(group_id, fake_enc(alice.session.session_id, "push to bob"))
        .await
        .expect("send");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::MessageCreate(_))).await;
    match evt {
        Event::MessageCreate(m) => {
            assert_eq!(m.message_id, ack.message_id);
            assert_eq!(m.chat_id, group_id);
            assert_eq!(m.author_id, alice.session.user_id);
            assert_eq!(m.author_session_id, alice.session.session_id);
            assert_eq!(common::decode_fake(&m.encrypted.ciphertext), "push to bob");
        }
        _ => unreachable!(),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn edit_by_author_succeeds() {
    let alice = common::register_new("msg_edit_a").await;
    let bob = common::register_new("msg_edit_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgEdit").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let ack = alice_low
        .messages()
        .send(group_id, fake_enc(alice.session.session_id, "original"))
        .await
        .expect("send");

    let mut bob_rx = bob_low.subscribe();

    alice_low
        .messages()
        .edit(ack.message_id, fake_enc(alice.session.session_id, "edited"))
        .await
        .expect("edit");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::MessageUpdate(_))).await;
    match evt {
        Event::MessageUpdate(u) => {
            assert_eq!(u.message_id, ack.message_id);
            assert_eq!(u.chat_id, group_id);
            assert_eq!(common::decode_fake(&u.encrypted.ciphertext), "edited");
        }
        _ => unreachable!(),
    }

    let page = bob_low.messages().get(group_id, None, 20).await.expect("get");
    let found = page.messages.iter().find(|m| m.message_id == ack.message_id).unwrap();
    assert!(found.edited_at.is_some(), "edited_at must be set");
    assert_eq!(
        common::decode_fake(&found.encrypted.as_ref().unwrap().ciphertext),
        "edited"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn edit_by_non_author_fails() {
    let alice = common::register_new("msg_edna_a").await;
    let bob = common::register_new("msg_edna_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgEdNA").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let ack = alice_low
        .messages()
        .send(group_id, fake_enc(alice.session.session_id, "original"))
        .await
        .expect("send");

    let err = bob_low
        .messages()
        .edit(ack.message_id, fake_enc(bob.session.session_id, "hacked"))
        .await
        .unwrap_err();
    common::assert_server_code(err, "not_author");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn delete_marks_message_deleted() {
    let alice = common::register_new("msg_del_a").await;
    let bob = common::register_new("msg_del_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgDel").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let ack = alice_low
        .messages()
        .send(group_id, fake_enc(alice.session.session_id, "to delete"))
        .await
        .expect("send");

    let mut bob_rx = bob_low.subscribe();

    alice_low.messages().delete(ack.message_id).await.expect("delete");

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::MessageDelete(_))).await;
    match evt {
        Event::MessageDelete(d) => {
            assert_eq!(d.message_id, ack.message_id);
            assert_eq!(d.chat_id, group_id);
        }
        _ => unreachable!(),
    }

    let page = bob_low.messages().get(group_id, None, 20).await.expect("get");
    let found = page.messages.iter().find(|m| m.message_id == ack.message_id).unwrap();
    assert!(found.deleted, "deleted flag must be true");
    assert!(found.encrypted.is_none(), "encrypted must be cleared on delete");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn reactions_full_flow() {
    let alice = common::register_new("msg_rx_a").await;
    let bob = common::register_new("msg_rx_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgRx").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let ack = alice_low
        .messages()
        .send(group_id, fake_enc(alice.session.session_id, "react to me"))
        .await
        .expect("send");

    let mut alice_rx = alice_low.subscribe();

    bob_low
        .messages()
        .add_reaction(ack.message_id, "👍")
        .await
        .expect("add reaction");

    let evt = common::wait_event(&mut alice_rx, |e| matches!(e, Event::ReactionAdd(_))).await;
    match evt {
        Event::ReactionAdd(r) => {
            assert_eq!(r.message_id, ack.message_id);
            assert_eq!(r.chat_id, group_id);
            assert_eq!(r.user_id, bob.session.user_id);
            assert_eq!(r.emoji, "👍");
        }
        _ => unreachable!(),
    }

    bob_low
        .messages()
        .add_reaction(ack.message_id, "👍")
        .await
        .expect("dup add reaction");

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let page = alice_low.messages().get(group_id, None, 20).await.expect("get");
    let found = page.messages.iter().find(|m| m.message_id == ack.message_id).unwrap();
    assert_eq!(found.reactions.len(), 1);
    assert_eq!(found.reactions[0].emoji, "👍");
    assert_eq!(found.reactions[0].count, 1);
    assert_eq!(found.reactions[0].user_ids, vec![bob.session.user_id]);

    let mut alice_rx2 = alice_low.subscribe();
    bob_low
        .messages()
        .remove_reaction(ack.message_id, "👍")
        .await
        .expect("remove reaction");

    let evt = common::wait_event(&mut alice_rx2, |e| matches!(e, Event::ReactionRemove(_))).await;
    match evt {
        Event::ReactionRemove(r) => {
            assert_eq!(r.message_id, ack.message_id);
            assert_eq!(r.user_id, bob.session.user_id);
            assert_eq!(r.emoji, "👍");
        }
        _ => unreachable!(),
    }

    let err = bob_low
        .messages()
        .remove_reaction(ack.message_id, "👍")
        .await
        .unwrap_err();
    common::assert_server_code(err, "reaction_not_found");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn session_mismatch_fails() {
    let alice = common::register_new("msg_sm_a").await;
    let bob = common::register_new("msg_sm_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgSM").await;

    let alice_low = alice.low();

    let enc = fake_enc(999_999_999, "bad session");
    let err = alice_low
        .messages()
        .send(group_id, enc)
        .await
        .unwrap_err();
    common::assert_server_code(err, "session_mismatch");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn message_too_large_fails() {
    let alice = common::register_new("msg_big_a").await;
    let bob = common::register_new("msg_big_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgBig").await;

    let alice_low = alice.low();

    let big = "A".repeat(70_000);
    let enc = Encrypted {
        algorithm: "test.algorithm".into(),
        sender_key: "k".into(),
        sender_session_id: alice.session.session_id,
        megolm_session_id: "m".into(),
        ciphertext: big,
    };
    let err = alice_low.messages().send(group_id, enc).await.unwrap_err();
    common::assert_server_code(err, "message_too_large");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test]
async fn not_a_member_cannot_send() {
    let alice = common::register_new("msg_nm_a").await;
    let bob = common::register_new("msg_nm_b").await;
    let charlie = common::register_new("msg_nm_c").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgNM").await;

    let charlie_low = charlie.low();

    let enc = fake_enc(charlie.session.session_id, "intruder");
    let err = charlie_low.messages().send(group_id, enc).await.unwrap_err();
    common::assert_server_code(err, "not_a_member");

    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}

#[tokio::test]
async fn rate_limit_hits_after_30_messages() {
    let alice = common::register_new("msg_rl_a").await;
    let bob = common::register_new("msg_rl_b").await;
    let group_id = common::setup_group_with_two(&alice, &bob, "MsgRL").await;

    let bob_low = bob.low();
    let enc = fake_enc(bob.session.session_id, "spam");

    for i in 0..30 {
        bob_low
            .messages()
            .send(group_id, enc.clone())
            .await
            .unwrap_or_else(|e| panic!("send #{i} failed: {e:?}"));
    }

    let err = bob_low.messages().send(group_id, enc).await.unwrap_err();
    common::assert_server_code(err, "rate_limited");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}