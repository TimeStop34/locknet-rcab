mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{Credentials, HighEvent, LockNetClient, LockNetLowAgent};
use tokio::sync::broadcast;

// ---- helpers ----

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

/// Создаёт cross-signing для low (MSK/SSK/USK) и подписывает ed25519
/// **текущей** сессии своим SSK. Возвращает приватные ключи.
async fn setup_cross_signing(low: &LockNetLowAgent) -> CrossSigningKeysPrivate {
    let user_id = low.user_id();
    let session_id = low.session_id();

    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(user_id, &keys))
        .await
        .expect("upload cross-signing");

    let own_ed = {
        let acc = low.store().account().await;
        let acc = acc.lock().await;
        acc.ed25519_public_b64()
    };
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(session_id, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload device signature");

    keys
}

/// Подписывает ed25519 target_session SSK этого low и загружает сигнатуру.
async fn sign_other_session(
    low: &LockNetLowAgent,
    keys: &CrossSigningKeysPrivate,
    target_user_id: i64,
    target_session_id: i64,
) {
    let sessions = low
        .keys()
        .query(vec![target_user_id])
        .await
        .expect("query_keys");
    let target_ed = sessions
        .get(&target_user_id)
        .and_then(|m| m.get(&target_session_id))
        .map(|d| d.ed25519_key.clone())
        .expect("target session ed25519 in query_keys");

    let sig = sign_b64(&keys.ssk, &target_ed).expect("sign target ed25519");

    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(target_session_id, sig)].into_iter().collect(),
        })
        .await
        .expect("upload target device signature");
}

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

// ---- tests ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_device_recovers_history_from_sibling_device() {
    let alice = common::register_new("hkr_a").await;
    let bob = common::register_new("hkr_b").await;

    let bob_uid = bob.session.user_id;
    let bob1_sid = bob.session.session_id;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob1_agent = bob.client.get_agent().expect("bob agent");
    let bob1_low = bob1_agent.low();

    // 1. Cross-signing для Bob1: SSK создан, ed25519 Bob1 подписан
    let bob_cs = setup_cross_signing(&bob1_low).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "HKR").await;

    // 2. Alice шлёт 2 сообщения — fan-out на Bob1
    let alice_chat = alice_agent.chat(group_id).await.expect("alice chat");
    let mut bob1_rx = bob1_agent.subscribe();

    let m1 = alice_chat.send("history-1").await.expect("send1");
    let _ = wait_high_event(&mut bob1_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == m1.id)
    })
    .await;

    let m2 = alice_chat.send("history-2").await.expect("send2");
    let _ = wait_high_event(&mut bob1_rx, |e| {
        matches!(e, HighEvent::NewMessage { message, .. } if message.id == m2.id)
    })
    .await;

    let bob1_chat = bob1_agent.chat(group_id).await.expect("bob1 chat");
    let bob1_history = bob1_chat.messages(None, 20).await.expect("bob1 messages");
    assert_eq!(
        bob1_history.iter().find(|m| m.id == m1.id).unwrap().text.as_deref(),
        Some("history-1")
    );

    // 3. Bob2 — новое устройство через Login (новый session_id)
    let mut bob2_client = LockNetClient::new(common::test_config());
    let bob2_session = bob2_client
        .connection_request(Credentials::Login {
            username: bob.username.clone(),
            password: bob.password.clone(),
        })
        .await
        .expect("bob2 login");
    assert_eq!(bob2_session.user_id, bob_uid);
    let bob2_sid = bob2_session.session_id;
    assert_ne!(bob2_sid, bob1_sid, "Login должен создать новую сессию");
    let bob2_low = bob2_client.get_low_agent().expect("bob2 low");
    // client.rs для Login сам делает upload_keys — вручную не нужно

    // 4. Bob1 подписывает ed25519 Bob2 своим SSK (кросс-верификация устройства)
    sign_other_session(&bob1_low, &bob_cs, bob_uid, bob2_sid).await;

    let bob2_agent = bob2_client.get_agent().expect("bob2 high");

    // 5. Bob2 видит историю, но с text=None
    let bob2_chat = bob2_agent.chat(group_id).await.expect("bob2 chat");
    let history_unread = bob2_chat.messages(None, 20).await.expect("bob2 messages");
    let m1_unread = history_unread.iter().find(|m| m.id == m1.id).expect("m1 in history");
    let m2_unread = history_unread.iter().find(|m| m.id == m2.id).expect("m2 in history");
    assert_eq!(m1_unread.text, None, "у Bob2 нет ключа для m1");
    assert_eq!(m2_unread.text, None, "у Bob2 нет ключа для m2");

    // 6. Запрашиваем у Bob1 (sibling device, verified через SSK)
    let (pending_count, imported) = bob2_chat
        .request_missing_keys()
        .await
        .expect("request_missing_keys");
    assert!(pending_count >= 2, "pending_count={pending_count}");
    assert!(imported >= 1, "imported={imported}");

    // Фикс: sibling-recovery через key_request передаёт group_data — Bob2
    // должен получить policy. Без этого Chat::ensure_policy_known откажет
    // на send после recovery (read работает, write — нет).
    assert!(
        bob2_low.store().group_data_state(group_id).await.is_some(),
        "Bob2 должен получить group_data через key_request"
    );

    // 7. Повторно читаем — расшифровывается
    let history_read = bob2_chat.messages(None, 20).await.expect("bob2 messages #2");
    let m1_read = history_read.iter().find(|m| m.id == m1.id).expect("m1 #2");
    let m2_read = history_read.iter().find(|m| m.id == m2.id).expect("m2 #2");
    assert_eq!(m1_read.text.as_deref(), Some("history-1"));
    assert_eq!(m2_read.text.as_deref(), Some("history-2"));

    let _ = bob2_low;
    bob2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_missing_keys_no_pending_is_noop() {
    let alice = common::register_new("hkr_noop_a").await;
    let bob = common::register_new("hkr_noop_b").await;

    let bob_agent = bob.client.get_agent().expect("bob agent");
    let group_id = common::setup_group_with_two(&alice, &bob, "HKRNoop").await;

    let bob_chat = bob_agent.chat(group_id).await.expect("bob chat");
    let (pending, imported) = bob_chat
        .request_missing_keys()
        .await
        .expect("request_missing_keys");
    assert_eq!(pending, 0);
    assert_eq!(imported, 0);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_member_is_denied() {
    let alice = common::register_new("hkr_dn_a").await;
    let bob = common::register_new("hkr_dn_b").await;
    let charlie = common::register_new("hkr_dn_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_agent = bob.client.get_agent().expect("bob agent");
    // Charlie — через low, чтобы не создавать agent (иначе race за Olm-сессию)
    let charlie_low = charlie.low();

    let group = alice_agent
        .create_group(
            "HKRDeny",
            false,
            None,
            vec![bob.session.user_id, charlie.session.user_id],
        )
        .await
        .expect("create");

    let bob_invites = bob_agent.invites().await.expect("bob invites");
    let bob_inv = bob_invites.iter().find(|i| i.group.id == group.id()).unwrap();
    bob_agent.accept_invite(bob_inv.id).await.expect("bob accept");

    let charlie_invites = charlie_low.groups().invites().await.expect("charlie invites");
    let charlie_inv = charlie_invites.iter().find(|i| i.group_id == group.id()).unwrap();
    charlie_low.groups().accept_invite(charlie_inv.id).await.expect("charlie accept");

    let alice_chat = alice_agent.chat(group.id()).await.expect("alice chat");
    let _m = alice_chat.send("private").await.expect("send");

    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let charlie_low = charlie.low();

    let mut flow = charlie_low
        .key_sharing()
        .request(alice_uid, alice_sid, vec![group.id()])
        .await
        .expect("charlie request");

    let deadline = tokio::time::timeout(Duration::from_secs(10), async {
        for _ in 0..64 {
            match flow.next().await {
                Ok(locknet_rcab::api::low::helpers::key_sharing::KeyRequestStep::Denied { reason }) => {
                    return Some(reason);
                }
                Ok(locknet_rcab::api::low::helpers::key_sharing::KeyRequestStep::Done { total_imported }) => {
                    panic!("unexpected Done({total_imported}) — Alice shouldn't share with unverified");
                }
                Ok(_) => continue,
                Err(e) => panic!("flow error: {e:?}"),
            }
        }
        None
    })
    .await
    .expect("timeout");

    let reason = deadline.expect("Charlie должен был получить Denied");
    assert!(
        reason.contains("not verified"),
        "unexpected deny reason: {reason}"
    );

    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}