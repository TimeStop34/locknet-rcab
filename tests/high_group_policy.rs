mod common;

use std::time::Duration;

use locknet_rcab::LockNetError;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creator_can_send_in_brand_new_group() {
    let alice = common::register_new("gp_creator_a").await;
    let bob = common::register_new("gp_creator_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_low = alice_agent.low();

    let group = alice_agent
        .create_group("GPNew", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    assert!(alice_low.store().group_data_state(group.id()).await.is_none());

    let alice_chat = alice_agent.chat(group.id()).await.expect("chat");
    let sent = alice_chat.send("first message").await.expect("send");

    assert!(alice_low.store().group_data_state(group.id()).await.is_some());
    assert!(sent.encrypted);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_creator_cannot_send_without_policy() {
    let alice = common::register_new("gp_non_a").await;
    let bob = common::register_new("gp_non_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_low = bob_agent.low();

    let group = alice_agent
        .create_group("GPNon", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("bob invite");
    bob_agent.accept_invite(inv.id).await.expect("bob accept");

    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let _ = alice_chat.send("hello").await.expect("alice send");

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        bob_low.store().group_data_state(group_id).await.is_some(),
        "Bob получил policy через fan-out"
    );

    bob_low.store().group_data_state_remove(group_id).await;
    assert!(bob_low.store().group_data_state(group_id).await.is_none());

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let err = bob_chat.send("unauthorized").await.unwrap_err();
    match err {
        LockNetError::InvalidArgument(msg) => {
            assert!(
                msg.contains("policy unknown"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    let alice_low = alice_agent.low();
    let info = alice_low
        .megolm()
        .ensure_session(group_id)
        .await
        .expect("ensure session");
    alice_low
        .megolm()
        .share_group_key_with_session_key(
            group_id,
            bob.session.user_id,
            bob.session.session_id,
            info.megolm_session_id,
            info.session_key,
        )
        .await
        .expect("share again");

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        bob_low.store().group_data_state(group_id).await.is_some(),
        "Bob восстановил policy"
    );

    let _ = bob_chat.send("now ok").await.expect("send after recovery");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_also_requires_policy() {
    let alice = common::register_new("gp_edit_a").await;
    let bob = common::register_new("gp_edit_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_low = bob_agent.low();

    let group = alice_agent
        .create_group("GPEdit", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("inv");
    bob_agent.accept_invite(inv.id).await.expect("accept");

    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let sent = alice_chat.send("to edit").await.expect("send");
    tokio::time::sleep(Duration::from_millis(500)).await;

    bob_low.store().group_data_state_remove(group_id).await;

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let err = bob_chat.edit(sent.id, "hacked").await.unwrap_err();
    assert!(matches!(err, LockNetError::InvalidArgument(_)));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}