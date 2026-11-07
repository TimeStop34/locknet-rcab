mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::core::policies::HistoryVisibility;
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{LockNetError, LockNetLowAgent};

fn build_cs_payload(user_id: i64, keys: &CrossSigningKeysPrivate) -> CrossSigningKeys {
    let msk_pub = keys.msk_pub_b64();
    let ssk_pub = keys.ssk_pub_b64();
    let usk_pub = keys.usk_pub_b64();
    let ssk_sig = sign_b64(&keys.msk, &ssk_pub).expect("ssk sig");
    let usk_sig = sign_b64(&keys.msk, &usk_pub).expect("usk sig");

    let mut ssk_inner = HashMap::new();
    ssk_inner.insert("master".to_string(), ssk_sig);
    let mut ssk_sigs = HashMap::new();
    ssk_sigs.insert(user_id.to_string(), ssk_inner);

    let mut usk_inner = HashMap::new();
    usk_inner.insert("master".to_string(), usk_sig);
    let mut usk_sigs = HashMap::new();
    usk_sigs.insert(user_id.to_string(), usk_inner);

    CrossSigningKeys {
        master_key: CrossSigningKey { key: msk_pub, signatures: HashMap::new() },
        self_signing_key: CrossSigningKey { key: ssk_pub, signatures: ssk_sigs },
        user_signing_key: CrossSigningKey { key: usk_pub, signatures: usk_sigs },
    }
}

async fn setup_high(user: &common::TestUser) -> CrossSigningKeysPrivate {
    let agent = user.client.get_agent().expect("agent");
    let low = agent.low();
    let uid = user.session.user_id;
    let sid = user.session.session_id;

    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(uid, &keys))
        .await
        .expect("upload cs");

    let own_ed = {
        let acc = low.store().account().await;
        let acc = acc.lock().await;
        acc.ed25519_public_b64()
    };
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(sid, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload dev sig");

    keys
}

async fn sign_msk(
    signer_agent: &locknet_rcab::LockNetAgent,
    signer_keys: &CrossSigningKeysPrivate,
    target_uid: i64,
) {
    let low = signer_agent.low();
    let query = low.crypto().query_cross_signing_keys(vec![target_uid]).await.unwrap();
    let target_msk = query.get(&target_uid).map(|u| u.master_key.key.clone()).unwrap();
    let sig = sign_b64(&signer_keys.usk, &target_msk).unwrap();

    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: [(target_uid, sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .expect("upload sig");

    signer_agent.security().invalidate_trust_cache().await;
}

async fn set_history_visibility(low: &LockNetLowAgent, chat_id: i64, vis: HistoryVisibility) {
    use locknet_rcab::core::crypto::group_data::encrypt_group_data;
    use locknet_rcab::core::policies::GroupDataState;

    let state = low.store().group_data_state(chat_id).await.expect("group_data");
    let mut data = state.data.clone();
    data.version += 1;
    data.history_visibility = vis;
    let blob = encrypt_group_data(&data, &state.key).expect("re-encrypt");
    low.store().group_data_state_put(
        chat_id,
        GroupDataState { key: state.key, data, blob },
    ).await;
}

async fn alice_send_no_fanout(low: &LockNetLowAgent, chat_id: i64, text: &str) -> i64 {
    low.megolm().create(chat_id).await.expect("create");
    let enc = low.megolm().encrypt(chat_id, text).await.expect("encrypt");
    low.messages().send(chat_id, enc).await.expect("send").message_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_join_denies_all() {
    let alice = common::register_new("hv_aj_a").await;
    let bob = common::register_new("hv_aj_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_uid = bob.session.user_id;

    setup_high(&alice).await;
    setup_high(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "HVAfterJoin").await;

    let msg_id = alice_send_no_fanout(&alice_low, group_id, "secret").await;

    set_history_visibility(&alice_low, group_id, HistoryVisibility::AfterJoin).await;

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let history = bob_chat.messages(None, 20).await.expect("messages");
    let msg = history.iter().find(|m| m.id == msg_id).expect("msg in history");
    assert_eq!(msg.text, None, "Bob без ключа не может читать");

    let err = bob_chat.request_missing_keys().await.unwrap_err();
    match err {
        LockNetError::Server { code, message } => {
            assert_eq!(code, "key_denied");
            assert!(message.contains("history_visibility"), "reason: {message}");
        }
        other => panic!("expected Server(key_denied), got {other:?}"),
    }

    let _ = bob_uid;
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_verified_sessions_accepts_any_session_with_cs() {
    let alice = common::register_new("hv_avs_a").await;
    let bob = common::register_new("hv_avs_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();

    setup_high(&alice).await;
    setup_high(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "HVAllSess").await;
    let msg_id = alice_send_no_fanout(&alice_low, group_id, "history").await;

    set_history_visibility(&alice_low, group_id, HistoryVisibility::AllVerifiedSessions).await;

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let _ = bob_chat.messages(None, 20).await.expect("messages");

    let (pending, imported) = bob_chat
        .request_missing_keys()
        .await
        .expect("request_missing_keys");
    assert!(pending >= 1);
    assert!(imported >= 1, "Bob (session-verified) должен получить ключ");

    let history = bob_chat.messages(None, 20).await.expect("messages");
    let msg = history.iter().find(|m| m.id == msg_id).expect("msg");
    assert_eq!(msg.text.as_deref(), Some("history"));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_verified_users_requires_user_trust() {
    let alice = common::register_new("hv_avu_a").await;
    let bob = common::register_new("hv_avu_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_uid = bob.session.user_id;

    let alice_keys = setup_high(&alice).await;
    setup_high(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "HVAllUsers").await;
    let msg_id = alice_send_no_fanout(&alice_low, group_id, "secret").await;

    let _ = alice_agent.user_info(bob_uid).await;

    set_history_visibility(&alice_low, group_id, HistoryVisibility::AllVerifiedUsers).await;

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let _ = bob_chat.messages(None, 20).await.expect("messages");

    let err = bob_chat.request_missing_keys().await.unwrap_err();
    match err {
        LockNetError::Server { code, .. } => assert_eq!(code, "key_denied"),
        other => panic!("expected Server(key_denied), got {other:?}"),
    }

    sign_msk(&alice_agent, &alice_keys, bob_uid).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let history = bob_chat.messages(None, 20).await.expect("messages");
    let msg = history.iter().find(|m| m.id == msg_id).expect("msg");
    assert_eq!(msg.text, None);

    let (pending, imported) = bob_chat
        .request_missing_keys()
        .await
        .expect("second request_missing_keys");
    assert!(pending >= 1);
    assert!(imported >= 1, "после USK-подписи Bob получает ключ");

    let history = bob_chat.messages(None, 20).await.expect("messages");
    let msg = history.iter().find(|m| m.id == msg_id).expect("msg");
    assert_eq!(msg.text.as_deref(), Some("secret"));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_verified_users_accepts_after_sas() {
    let alice = common::register_new("hv_avu_sas_a").await;
    let bob = common::register_new("hv_avu_sas_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_uid = bob.session.user_id;

    let alice_keys = setup_high(&alice).await;
    setup_high(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "HVASAS").await;
    let msg_id = alice_send_no_fanout(&alice_low, group_id, "after sas").await;

    let _ = alice_agent.user_info(bob_uid).await;
    sign_msk(&alice_agent, &alice_keys, bob_uid).await;

    set_history_visibility(&alice_low, group_id, HistoryVisibility::AllVerifiedUsers).await;

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let _ = bob_chat.messages(None, 20).await.expect("messages");

    let (_, imported) = bob_chat
        .request_missing_keys()
        .await
        .expect("request_missing_keys");
    assert!(imported >= 1);

    let history = bob_chat.messages(None, 20).await.expect("messages");
    let msg = history.iter().find(|m| m.id == msg_id).expect("msg");
    assert_eq!(msg.text.as_deref(), Some("after sas"));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}