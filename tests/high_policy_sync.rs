mod common;

use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn creator_uploads_policy_after_first_send() {
    let alice = common::register_new("ps_upload_a").await;
    let bob = common::register_new("ps_upload_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_low = alice_agent.low();

    let group = alice_agent
        .create_group("PSUpload", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    // До первого send серверного blob нет
    let info_before = alice_low.groups().info(group_id).await.expect("info");
    assert!(info_before.encrypted_group_data.is_none());

    // Отправляем первое сообщение
    let alice_chat = alice_agent.chat(group_id).await.expect("chat");
    let _ = alice_chat.send("hello").await.expect("send");

    // Даём время на upload
    tokio::time::sleep(Duration::from_millis(300)).await;

    // После send сервер должен знать blob
    let info_after = alice_low.groups().info(group_id).await.expect("info");
    assert!(
        info_after.encrypted_group_data.is_some(),
        "creator должен загрузить encrypted_group_data после первого send"
    );

    // Локальный blob совпадает с серверным
    let local_state = alice_low.store().group_data_state(group_id).expect("state");
    assert_eq!(
        info_after.encrypted_group_data.as_deref(),
        Some(local_state.blob.as_str())
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_device_cannot_create_policy_when_server_has_blob() {
    let alice = common::register_new("ps_newdev_a").await;
    let bob = common::register_new("ps_newdev_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");

    let group = alice_agent
        .create_group("PSNewDev", false, None, vec![bob.session.user_id])
        .await
        .expect("create");
    let group_id = group.id();

    // Bob accepts
    let inv = bob_agent
        .invites()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.group.id == group_id)
        .expect("inv");
    bob_agent.accept_invite(inv.id).await.expect("accept");

    // Alice шлёт первое сообщение — blob уходит на сервер
    let alice_chat = alice_agent.chat(group_id).await.expect("chat");
    let _ = alice_chat.send("hello").await.expect("send");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Симулируем: новое устройство Alice (Login, свежий store)
    let mut alice2_client = locknet_rcab::LockNetClient::new(common::test_config());
    let alice2_session = alice2_client
        .connection_request(locknet_rcab::Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    assert_eq!(alice2_session.user_id, alice.session.user_id);

    let alice2_agent = alice2_client.get_agent().expect("alice2 agent");
    let alice2_chat = alice2_agent.chat(group_id).await.expect("chat");

    // У alice2 нет local policy, но на сервере blob уже есть.
    // Она — создатель, но `ensure_policy_known` должен отвергнуть send.
    let err = alice2_chat.send("hacked").await.unwrap_err();
    match err {
        locknet_rcab::LockNetError::InvalidArgument(msg) => {
            assert!(
                msg.contains("server has group policy blob") || msg.contains("policy unknown"),
                "unexpected: {msg}"
            );
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_creator_can_update_policy_blob() {
    let alice = common::register_new("ps_upd_a").await;
    let bob = common::register_new("ps_upd_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let bob_low = bob_agent.low();

    let group = alice_agent
        .create_group("PSUpd", false, None, vec![bob.session.user_id])
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

    // Bob пытается обновить blob — сервер должен отклонить
    let err = bob_low
        .groups()
        .update_group_data(group_id, "AAAA")
        .await
        .unwrap_err();
    common::assert_server_code(err, "not_creator");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}