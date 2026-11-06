mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::core::policies::MegolmRotationVisibility;
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{HighEvent, LockNetLowAgent};
use tokio::sync::broadcast;

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

async fn setup_cs(low: &LockNetLowAgent) -> CrossSigningKeysPrivate {
    let uid = low.user_id();
    let sid = low.session_id();
    let keys = CrossSigningKeysPrivate::generate();
    low.crypto().upload_cross_signing_keys(build_cs_payload(uid, &keys)).await.expect("upload cs");
    let own_ed = { let acc = low.store().account(); let acc = acc.lock().await; acc.ed25519_public_b64() };
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto().upload_signatures(Signatures {
        user_signatures: HashMap::new(),
        device_signatures: [(sid, dev_sig)].into_iter().collect(),
    }).await.expect("upload device sig");
    keys
}

async fn sign_msk(signer_low: &LockNetLowAgent, signer_keys: &CrossSigningKeysPrivate, target_uid: i64) {
    let query = signer_low.crypto().query_cross_signing_keys(vec![target_uid]).await.unwrap();
    let target_msk = query.get(&target_uid).map(|u| u.master_key.key.clone()).unwrap();
    let sig = sign_b64(&signer_keys.usk, &target_msk).unwrap();
    signer_low.crypto().upload_signatures(Signatures {
        user_signatures: [(target_uid, sig)].into_iter().collect(),
        device_signatures: HashMap::new(),
    }).await.unwrap();
}

async fn set_megolm_visibility(low: &LockNetLowAgent, chat_id: i64, vis: MegolmRotationVisibility) {
    use locknet_rcab::core::policies::GroupDataState;
    use locknet_rcab::core::crypto::group_data::encrypt_group_data;

    let state = low.store().group_data_state(chat_id).expect("group_data");
    let mut data = state.data.clone();
    data.version += 1;
    data.megolm_rotation_visibility = vis;
    let blob = encrypt_group_data(&data, &state.key).expect("re-encrypt");
    low.store().group_data_state_put(chat_id, GroupDataState {
        key: state.key,
        data,
        blob,
    });
}

async fn wait_high<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
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
            Err(_) => panic!("timeout"),
        }
    }
}

// ---- tests ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_members_reaches_everyone() {
    let alice = common::register_new("mv_all_a").await;
    let bob = common::register_new("mv_all_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();

    let group_id = common::setup_group_with_two(&alice, &bob, "MVAll").await;

    // Политика AllMembers (даже без CS у Bob и Alice)
    // Create session первым, чтобы group_data появилось
    alice_low.megolm().create(group_id).await.expect("create");
    set_megolm_visibility(&alice_low, group_id, MegolmRotationVisibility::AllMembers).await;

    // Bob подписан
    let mut bob_rx = bob_agent.subscribe();

    // Alice отправляет сообщение — fan-out должен произойти без CS
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let sent = alice_chat.send("hello all").await.expect("send");

    // Bob должен получить и расшифровать
    let evt = wait_high(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;

    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(message.text.as_deref(), Some("hello all"));
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_verified_sessions_skips_unverified() {
    let alice = common::register_new("mv_ovs_a").await;
    let bob = common::register_new("mv_ovs_b").await;
    let charlie = common::register_new("mv_ovs_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let charlie_agent = charlie.client.get_agent().expect("charlie agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    // Bob с CS + device signed; Charlie — без CS
    setup_cs(&bob_low).await;

    // Создаём группу с Bob и Charlie
    let group = alice_agent
        .create_group("MVOVS", false, None, vec![bob.session.user_id, charlie.session.user_id])
        .await
        .expect("create");

    // Принимаем приглашения
    let bob_inv = bob_agent.invites().await.unwrap().into_iter().find(|i| i.group.id == group.id()).unwrap();
    bob_agent.accept_invite(bob_inv.id).await.unwrap();

    let charlie_low = charlie.low();
    let charlie_inv = charlie_low.groups().invites().await.unwrap().into_iter().find(|i| i.group_id == group.id()).unwrap();
    charlie_low.groups().accept_invite(charlie_inv.id).await.unwrap();

    // Создаём сессию, устанавливаем политику
    alice_low.megolm().create(group.id()).await.unwrap();
    set_megolm_visibility(&alice_low, group.id(), MegolmRotationVisibility::OnlyVerifiedSessions).await;

    // Bob и Charlie подписаны на push
    let mut bob_rx = bob_agent.subscribe();
    let mut charlie_rx = charlie_agent.subscribe();

    let alice_chat = alice_agent.chat(group.id()).await.unwrap();
    let sent = alice_chat.send("secret").await.unwrap();

    // Bob получает и расшифровывает
    let evt_b = wait_high(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_b {
        assert_eq!(message.text.as_deref(), Some("secret"), "Bob должен расшифровать");
    }

    // Charlie — получает push, но НЕ может расшифровать (нет ключа)
    let evt_c = wait_high(&mut charlie_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;
    if let HighEvent::NewMessage { message, .. } = evt_c {
        assert_eq!(message.text, None, "Charlie не должен расшифровать (без CS)");
    }

    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_verified_users_skips_untrusted() {
    let alice = common::register_new("mv_ovu_a").await;
    let bob = common::register_new("mv_ovu_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    // У Bob есть CS, но Alice его не верифицировала
    setup_cs(&bob_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MVOVU").await;

    // Создаём сессию, политика OnlyVerifiedUsers
    alice_low.megolm().create(group_id).await.unwrap();
    set_megolm_visibility(&alice_low, group_id, MegolmRotationVisibility::OnlyVerifiedUsers).await;

    // Заставляем Alice знать про Bob (но не доверять)
    let _ = alice_agent.user_info(bob.session.user_id).await;

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group_id).await.unwrap();
    let sent = alice_chat.send("super secret").await.unwrap();

    // Bob получает push, но text = None
    let evt = wait_high(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;

    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(message.text, None, "Bob не user-verified → не расшифрует");
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_verified_users_reaches_after_usk_signature() {
    let alice = common::register_new("mv_ovu_usk_a").await;
    let bob = common::register_new("mv_ovu_usk_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    let alice_cs = setup_cs(&alice_low).await;
    setup_cs(&bob_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MVOVUUSK").await;

    // Политика OnlyVerifiedUsers
    alice_low.megolm().create(group_id).await.unwrap();
    set_megolm_visibility(&alice_low, group_id, MegolmRotationVisibility::OnlyVerifiedUsers).await;

    // Alice USK подписывает Bob
    let _ = alice_agent.user_info(bob.session.user_id).await;
    sign_msk(&alice_low, &alice_cs, bob.session.user_id).await;

    // Даём время event'у обновить кэш
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut bob_rx = bob_agent.subscribe();

    let alice_chat = alice_agent.chat(group_id).await.unwrap();
    let sent = alice_chat.send("after usk").await.unwrap();

    let evt = wait_high(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;

    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(message.text.as_deref(), Some("after usk"), "Bob теперь user-verified");
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_on_membership_respects_policy() {
    let alice = common::register_new("mv_rot_a").await;
    let bob = common::register_new("mv_rot_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();

    setup_cs(&bob_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "MVRot").await;

    // Создаём сессию + политика OnlyVerifiedSessions
    alice_low.megolm().create(group_id).await.unwrap();
    set_megolm_visibility(&alice_low, group_id, MegolmRotationVisibility::OnlyVerifiedSessions).await;

    // Bob получает первое сообщение (fan-out с AllMembers до установки политики? — нет, политика уже установлена)
    // Проверим что при membership_changed Bob НЕ получает новый ключ, если он leave
    // (тут Bob уже member с CS+device — должен получать)

    let mut bob_rx = bob_agent.subscribe();
    let alice_chat = alice_agent.chat(group_id).await.unwrap();
    let sent = alice_chat.send("pre-leave").await.unwrap();
    let evt = wait_high(&mut bob_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == sent.id)
    })
    .await;
    if let HighEvent::NewMessage { message, .. } = evt {
        assert_eq!(message.text.as_deref(), Some("pre-leave"), "Bob может читать");
    }

    // Bob leaves → ротация; Bob не должен получить новый ключ
    let mut alice_rx = alice_agent.subscribe();
    bob_agent.leave_chat(group_id).await.unwrap();
    let _ = wait_high(&mut alice_rx, |e| {
        matches!(e, HighEvent::GroupMembershipChanged { .. })
    }).await;

    let alice_chat2 = alice_agent.chat(group_id).await.unwrap();
    let sent2 = alice_chat2.send("post-leave").await.unwrap();
    let s2 = sent2.encrypted_payload.as_ref().unwrap().megolm_session_id.clone();

    // Bob не должен иметь s2 (fan-out не включил — Bob не member)
    assert!(
        bob_low.store().megolm_inbound(group_id, &s2).is_none(),
        "Bob не должен иметь ключ для post-leave сообщения"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}