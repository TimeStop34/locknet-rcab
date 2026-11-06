mod common;

use std::time::Duration;

use locknet_rcab::LockNetError;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creator_can_send_in_brand_new_group() {
    // Создатель без local policy может отправлять в новый чат
    // (creation case — сервер ещё не имеет blob).
    let alice = common::register_new("gp_creator_a").await;
    let bob = common::register_new("gp_creator_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_low = alice_agent.low();

    let group = alice_agent
        .create_group("GPNew", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    assert!(alice_low.store().group_data_state(group.id()).is_none());

    let alice_chat = alice_agent.chat(group.id()).await.expect("chat");
    let sent = alice_chat.send("first message").await.expect("send");

    // После отправки policy создалась
    assert!(alice_low.store().group_data_state(group.id()).is_some());
    assert!(sent.encrypted);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_creator_cannot_send_without_policy() {
    // Bob — member, но потерял policy (например, восстановление без ключа).
    // Он НЕ создатель → не может создать новую policy → отказ.
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

    // Bob accepts ПЕРЕД тем как Alice шлёт — избегаем race
    // `publish_to_group` vs `db.commit` на сервере.
    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("bob invite");
    bob_agent.accept_invite(inv.id).await.expect("bob accept");

    // Alice шлёт — Bob уже в group (committed на сервере).
    // `Chat::send` делает `info()` → видит [alice, bob] → fan-out на Bob.
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let _ = alice_chat.send("hello").await.expect("alice send");

    // Даём время на fan-out (Alice -> Bob).
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        bob_low.store().group_data_state(group_id).is_some(),
        "Bob получил policy через fan-out"
    );

    // Симулируем recovery: Bob потерял policy (но у него остались Olm+Megolm)
    bob_low.store().group_data_state_remove(group_id);
    assert!(bob_low.store().group_data_state(group_id).is_none());

    // Bob пытается отправить → отказ
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

    // После восстановления policy (через share_group_key от Alice)
    // Bob снова может отправлять
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
        bob_low.store().group_data_state(group_id).is_some(),
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

    // Bob accepts ПЕРВЫМ
    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("inv");
    bob_agent.accept_invite(inv.id).await.expect("accept");

    // Alice шлёт после accept
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let sent = alice_chat.send("to edit").await.expect("send");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Очищаем policy у Bob (вне зависимости от race — гарантируем отсутствие)
    bob_low.store().group_data_state_remove(group_id);

    // Bob пытается edit — тоже должен получить InvalidArgument
    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let err = bob_chat.edit(sent.id, "hacked").await.unwrap_err();
    assert!(matches!(err, LockNetError::InvalidArgument(_)));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}