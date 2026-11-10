mod common;

use std::time::Duration;

use locknet_rcab::{Credentials, LockNetClient, LockNetConfig, LockNetSessionContext};

// ---- helpers ----

fn cfg_with_rotation(count: u64, ttl_secs: u64) -> LockNetConfig {
    let mut cfg = common::test_config();
    cfg.megolm_rotation_message_count = count;
    cfg.megolm_rotation_ttl_secs = ttl_secs;
    cfg
}

struct RotUser {
    client: LockNetClient,
    session: LockNetSessionContext,
}

impl RotUser {
    fn low(&self) -> std::sync::Arc<locknet_rcab::LockNetLowAgent> {
        self.client.get_low_agent().expect("low agent")
    }
}

async fn register_with_rotation(
    prefix: &str,
    count: u64,
    ttl_secs: u64,
) -> RotUser {
    let username = format!("{}_{}", prefix, common::unique_suffix());
    let mut client = LockNetClient::new(cfg_with_rotation(count, ttl_secs));
    let session = client
        .connection_request(Credentials::Register {
            username,
            password: "pw".into(),
            display_name: None,
        })
        .await
        .expect("register");
    RotUser { client, session }
}

async fn create_group_with(alice: &RotUser, bob_uid: i64, name: &str) -> i64 {
    let group = alice
        .low()
        .groups()
        .create(name, false, None, vec![bob_uid])
        .await
        .expect("create group");
    group.id
}

async fn accept_own_invite(bob: &RotUser, group_id: i64) {
    let invites = bob.low().groups().invites().await.expect("invites");
    let inv = invites
        .iter()
        .find(|i| i.group_id == group_id)
        .expect("invite");
    bob.low()
        .groups()
        .accept_invite(inv.id)
        .await
        .expect("accept");
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_by_message_count() {
    let alice = register_with_rotation("rot_cnt_a", 3, 0).await;
    let bob = register_with_rotation("rot_cnt_b", 0, 0).await;

    let group_id = create_group_with(&alice, bob.session.user_id, "RotCnt").await;
    accept_own_invite(&bob, group_id).await;

    let alice_low = alice.low();

    let info1 = alice_low.megolm().create(group_id).await.expect("create");
    let s1 = info1.megolm_session_id.clone();

    let mut enc_ids = Vec::new();
    for i in 0..3 {
        let (info, rotated) = alice_low.megolm().ensure_session(group_id).await.expect("ensure");
        assert!(!rotated, "no rotation before threshold, iter {i}");
        assert_eq!(info.megolm_session_id, s1, "same session for {i}");
        let enc = alice_low.megolm().encrypt(group_id, &format!("m{i}")).await.expect("encrypt");
        enc_ids.push(enc.megolm_session_id.clone());
    }
    assert!(enc_ids.iter().all(|id| id == &s1), "all 3 in S1");

    let (info_new, rotated) = alice_low.megolm().ensure_session(group_id).await.expect("ensure #4");
    assert!(rotated, "rotation must trigger on 4th ensure");
    assert_ne!(info_new.megolm_session_id, s1, "new session_id after rotation");

    let enc4 = alice_low.megolm().encrypt(group_id, "m3").await.expect("encrypt 4");
    assert_eq!(enc4.megolm_session_id, info_new.megolm_session_id, "4th in new session");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_by_ttl() {
    let alice = register_with_rotation("rot_ttl_a", 0, 1).await;
    let bob = register_with_rotation("rot_ttl_b", 0, 0).await;

    let group_id = create_group_with(&alice, bob.session.user_id, "RotTtl").await;
    accept_own_invite(&bob, group_id).await;

    let alice_low = alice.low();
    let info1 = alice_low.megolm().create(group_id).await.expect("create");
    let s1 = info1.megolm_session_id.clone();

    let (info_now, rotated_now) = alice_low.megolm().ensure_session(group_id).await.expect("ensure now");
    assert!(!rotated_now, "no rotation immediately");
    assert_eq!(info_now.megolm_session_id, s1);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let (info_after, rotated_after) = alice_low.megolm().ensure_session(group_id).await.expect("ensure after");
    assert!(rotated_after, "rotation after ttl");
    assert_ne!(info_after.megolm_session_id, s1);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_rotation_when_disabled() {
    let alice = register_with_rotation("rot_off_a", 0, 0).await;
    let bob = register_with_rotation("rot_off_b", 0, 0).await;

    let group_id = create_group_with(&alice, bob.session.user_id, "RotOff").await;
    accept_own_invite(&bob, group_id).await;

    let alice_low = alice.low();
    let info1 = alice_low.megolm().create(group_id).await.expect("create");
    let s1 = info1.megolm_session_id.clone();

    for i in 0..10 {
        let (info, rotated) = alice_low.megolm().ensure_session(group_id).await.expect("ensure");
        assert!(!rotated, "no rotation when disabled, iter {i}");
        assert_eq!(info.megolm_session_id, s1);
        let _ = alice_low.megolm().encrypt(group_id, &format!("msg{i}")).await.expect("encrypt");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    let (info_final, rotated_final) = alice_low.megolm().ensure_session(group_id).await.expect("ensure final");
    assert!(!rotated_final, "no rotation even after time when ttl=0");
    assert_eq!(info_final.megolm_session_id, s1);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_after_auto_rotation() {
    let alice = register_with_rotation("rot_fo_a", 2, 0).await;
    let bob = register_with_rotation("rot_fo_b", 2, 0).await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");

    let group = alice_agent
        .create_group("RotFanout", false, None, vec![bob.session.user_id])
        .await
        .expect("create");

    let bob_inv = bob_agent
        .invites()
        .await
        .expect("invites")
        .into_iter()
        .find(|i| i.group.id == group.id())
        .expect("invite");
    bob_agent.accept_invite(bob_inv.id).await.expect("accept");

    let alice_chat = alice_agent.chat(group.id()).await.expect("chat");

    let m1 = alice_chat.send("m1").await.expect("m1");
    let s1 = m1.encrypted_payload.as_ref().unwrap().megolm_session_id.clone();

    let m2 = alice_chat.send("m2").await.expect("m2");
    let s2 = m2.encrypted_payload.as_ref().unwrap().megolm_session_id.clone();
    assert_eq!(s1, s2, "msg2 in same session");

    tokio::time::sleep(Duration::from_millis(300)).await;

    let bob_chat = bob_agent.chat(group.id()).await.expect("bob chat");
    let history_before = bob_chat.messages(None, 20).await.expect("msgs before");
    assert_eq!(
        history_before.iter().find(|m| m.id == m1.id).unwrap().text.as_deref(),
        Some("m1")
    );
    assert_eq!(
        history_before.iter().find(|m| m.id == m2.id).unwrap().text.as_deref(),
        Some("m2")
    );

    let m3 = alice_chat.send("m3").await.expect("m3");
    let s3 = m3.encrypted_payload.as_ref().unwrap().megolm_session_id.clone();
    assert_ne!(s3, s1, "3rd message must rotate");

    tokio::time::sleep(Duration::from_millis(500)).await;
    let history_after = bob_chat.messages(None, 20).await.expect("msgs after");
    let m3_after = history_after.iter().find(|m| m.id == m3.id).expect("m3");
    assert_eq!(
        m3_after.text.as_deref(),
        Some("m3"),
        "bob decrypts msg from rotated session after fan-out"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}