//! E2E тесты `SqliteStore` с реальным сервером.
//!
//! **Литеральный** рестарт: setup в блоке `{}`, всё дропается, затем
//! **новый блок** открывает `SqliteStore` на тех же путях и проверяет,
//! что состояние восстановилось из БД.
//!
//! Эти тесты **падают** с `InMemoryStore` (state в памяти) и **проходят**
//! только с `SqliteStore` — что и есть цель тестов.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use locknet_rcab::{
    Credentials, Event, HighEvent, LockNetClient, LockNetLowAgent, SqliteStore,
};
use tokio::sync::broadcast;

// ---- helpers ----

fn tmp_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locknet-e2e.db");
    (dir, path)
}

fn sqlite_client(db: &std::path::Path, passphrase: &str) -> LockNetClient {
    let store = Arc::new(SqliteStore::open(db, passphrase).expect("sqlite open"));
    LockNetClient::with_store(common::test_config(), store)
}

async fn wait_high<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
where
    F: Fn(&HighEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
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

async fn warmup_olm(
    a_low: &Arc<LockNetLowAgent>,
    b_low: &Arc<LockNetLowAgent>,
    b_uid: i64,
    b_sid: i64,
) {
    let mut rx = b_low.subscribe();
    a_low.olm().send(b_uid, b_sid, "warmup").wait().await.expect("send");
    let evt = common::wait_event(&mut rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    b_low.olm().decrypt(p).wait().await.expect("decrypt");

    let mut rx2 = a_low.subscribe();
    b_low
        .olm()
        .send(a_low.user_id(), a_low.session_id(), "warmup-rev")
        .wait()
        .await
        .expect("send-rev");
    let evt = common::wait_event(&mut rx2, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    a_low.olm().decrypt(p).wait().await.expect("decrypt-rev");
}

// ============ tests ============

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_identity_survives_literal_restart() {
    let (_dir, db) = tmp_db();
    let pw = "pw";

    let (alice_uid, alice_sid, alice_rjwt, ed_before) = {
        let mut alice = sqlite_client(&db, pw);
        let s = alice
            .connection_request(Credentials::Register {
                username: format!("acc_e2e_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("register");

        let ed = {
            let acc = alice.get_low_agent().unwrap().store().account().await;
            let a = acc.lock().await;
            a.ed25519_public_b64()
        };

        alice.disconnect().await.ok();
        (s.user_id, s.session_id, s.rjwt, ed)
    };
    // BLOCK 1 ENDS — client, low_agent, store all dropped.

    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let mut alice = sqlite_client(&db, pw);
        let s = alice
            .connection_request(Credentials::Session {
                refresh_jwt: alice_rjwt,
            })
            .await
            .expect("reconnect");
        assert_eq!(s.user_id, alice_uid);
        assert_eq!(s.session_id, alice_sid);

        let ed_after = {
            let acc = alice.get_low_agent().unwrap().store().account().await;
            let a = acc.lock().await;
            a.ed25519_public_b64()
        };
        assert_eq!(
            ed_before, ed_after,
            "ed25519 must be the same Account after literal restart"
        );

        alice.disconnect().await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_signing_keys_survive_literal_restart() {
    let (_dir, db) = tmp_db();
    let pw = "pw";

    let (alice_rjwt, msk_before, ssk_before, usk_before) = {
        let mut alice = sqlite_client(&db, pw);
        let a_sess = alice
            .connection_request(Credentials::Register {
                username: format!("cs_e2e_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("register");

        let agent = alice.get_agent().expect("agent");
        agent
            .security()
            .setup_cross_signing()
            .await
            .expect("setup cross-signing");

        let keys = alice
            .get_low_agent()
            .unwrap()
            .store()
            .cross_signing_keys()
            .await
            .expect("keys");

        alice.disconnect().await.ok();
        (
            a_sess.rjwt,
            keys.msk_pub_b64(),
            keys.ssk_pub_b64(),
            keys.usk_pub_b64(),
        )
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let mut alice = sqlite_client(&db, pw);
        alice
            .connection_request(Credentials::Session {
                refresh_jwt: alice_rjwt,
            })
            .await
            .expect("reconnect");

        let keys = alice
            .get_low_agent()
            .unwrap()
            .store()
            .cross_signing_keys()
            .await
            .expect("keys must survive restart");
        assert_eq!(keys.msk_pub_b64(), msk_before);
        assert_eq!(keys.ssk_pub_b64(), ssk_before);
        assert_eq!(keys.usk_pub_b64(), usk_before);

        alice.disconnect().await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_outbound_survives_literal_restart() {
    let (_adir, alice_db) = tmp_db();
    let (_bdir, bob_db) = tmp_db();
    let pw = "pw";

    let (alice_rjwt, bob_rjwt, group_id, s1) = {
        let mut alice = sqlite_client(&alice_db, pw);
        let alice_s = alice
            .connection_request(Credentials::Register {
                username: format!("out_a_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("alice reg");
        let mut bob = sqlite_client(&bob_db, pw);
        let bob_s = bob
            .connection_request(Credentials::Register {
                username: format!("out_b_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("bob reg");

        let alice_agent = alice.get_agent().expect("alice agent");
        let bob_agent = bob.get_agent().expect("bob agent");

        let group = alice_agent
            .create_group("E2EOut", false, None, vec![bob_s.user_id])
            .await
            .expect("create");
        let gid = group.id();

        let bob_inv = bob_agent
            .invites()
            .await
            .expect("inv")
            .into_iter()
            .find(|i| i.group.id == gid)
            .expect("bob inv");
        bob_agent.accept_invite(bob_inv.id).await.expect("accept");

        let alice_chat = alice_agent.chat(gid).await.expect("chat");
        let m1 = alice_chat.send("first").await.expect("send m1");
        let s1 = m1.encrypted_payload.as_ref().unwrap().megolm_session_id.clone();

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();
        (alice_s.rjwt, bob_s.rjwt, gid, s1)
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let mut alice = sqlite_client(&alice_db, pw);
        alice
            .connection_request(Credentials::Session {
                refresh_jwt: alice_rjwt,
            })
            .await
            .expect("alice reconnect");
        let mut bob = sqlite_client(&bob_db, pw);
        bob.connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("bob reconnect");

        let alice_agent = alice.get_agent().expect("alice agent 2");
        let alice_chat = alice_agent.chat(group_id).await.expect("chat 2");
        let m2 = alice_chat.send("second").await.expect("send m2");
        let s2 = m2.encrypted_payload.as_ref().unwrap().megolm_session_id.clone();

        assert_eq!(
            s1, s2,
            "megolm outbound session must be preserved (same session_id)"
        );

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_inbound_survives_literal_restart() {
    let (_adir, alice_db) = tmp_db();
    let (_bdir, bob_db) = tmp_db();
    let pw = "pw";

    let (alice_rjwt, bob_rjwt, group_id, m1_id, m2_id) = {
        let mut alice = sqlite_client(&alice_db, pw);
        let a_sess = alice
            .connection_request(Credentials::Register {
                username: format!("in_a_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("alice reg");
        let mut bob = sqlite_client(&bob_db, pw);
        let b_sess = bob
            .connection_request(Credentials::Register {
                username: format!("in_b_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("bob reg");

        let alice_agent = alice.get_agent().expect("alice agent");
        let bob_agent = bob.get_agent().expect("bob agent");

        let group = alice_agent
            .create_group("E2EIn", false, None, vec![b_sess.user_id])
            .await
            .expect("create");
        let gid = group.id();

        let bob_inv = bob_agent
            .invites()
            .await
            .expect("inv")
            .into_iter()
            .find(|i| i.group.id == gid)
            .expect("bob inv");
        bob_agent.accept_invite(bob_inv.id).await.expect("accept");

        let mut bob_rx = bob_agent.subscribe();
        let alice_chat = alice_agent.chat(gid).await.expect("chat");
        let m1 = alice_chat.send("history-1").await.expect("m1");
        let _ = wait_high(&mut bob_rx, |e| {
            matches!(e, HighEvent::NewMessage { message, .. } if message.id == m1.id)
        })
        .await;
        let m2 = alice_chat.send("history-2").await.expect("m2");
        let _ = wait_high(&mut bob_rx, |e| {
            matches!(e, HighEvent::NewMessage { message, .. } if message.id == m2.id)
        })
        .await;

        // Sanity: bob расшифровывает до restart
        let bob_chat = bob_agent.chat(gid).await.expect("bob chat");
        let h = bob_chat.messages(None, 20).await.expect("msgs");
        assert_eq!(
            h.iter().find(|m| m.id == m1.id).unwrap().text.as_deref(),
            Some("history-1")
        );

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();

        (a_sess.rjwt, b_sess.rjwt, gid, m1.id, m2.id)
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let mut alice = sqlite_client(&alice_db, pw);
        alice
            .connection_request(Credentials::Session {
                refresh_jwt: alice_rjwt,
            })
            .await
            .expect("alice reconnect");
        let mut bob = sqlite_client(&bob_db, pw);
        bob.connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("bob reconnect");

        // Bob после literal restart должен расшифровать историю
        let bob_agent = bob.get_agent().expect("bob agent 2");
        let bob_chat = bob_agent.chat(group_id).await.expect("bob chat 2");
        let history = bob_chat.messages(None, 20).await.expect("msgs 2");

        let m1_after = history.iter().find(|m| m.id == m1_id).expect("m1");
        let m2_after = history.iter().find(|m| m.id == m2_id).expect("m2");
        assert_eq!(
            m1_after.text.as_deref(),
            Some("history-1"),
            "m1 decrypts after literal restart"
        );
        assert_eq!(
            m2_after.text.as_deref(),
            Some("history-2"),
            "m2 decrypts after literal restart"
        );

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn olm_session_survives_literal_restart() {
    let (_adir, alice_db) = tmp_db();
    let (_bdir, bob_db) = tmp_db();
    let pw = "pw";

    let (alice_rjwt, bob_rjwt, bob_uid, bob_sid) = {
        let mut alice = sqlite_client(&alice_db, pw);
        let a_sess = alice
            .connection_request(Credentials::Register {
                username: format!("olm_a_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("alice reg");
        let mut bob = sqlite_client(&bob_db, pw);
        let bob_s = bob
            .connection_request(Credentials::Register {
                username: format!("olm_b_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("bob reg");

        // Полный warmup (forward + reverse). После reverse Alice получает
        // Normal-сообщение, её Outbound-сессия становится established
        // (`has_received_message = true`), и последующие encrypt дают
        // NormalMessage (type=1), а не PreKey.
        let alice_low = alice.get_low_agent().expect("alice low");
        let bob_low = bob.get_low_agent().expect("bob low");
        warmup_olm(&alice_low, &bob_low, bob_s.user_id, bob_s.session_id).await;

        // Sanity: у Alice одна Outbound-entry к Bob'у (reverse warmup
        // создаёт Inbound-entry только у Bob'а, не у Alice).
        let pre = alice_low.store().olm_sessions(bob_s.session_id).await;
        assert_eq!(
            pre.len(),
            1,
            "alice should have exactly one olm entry (established outbound) after warmup"
        );

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();

        (a_sess.rjwt, bob_s.rjwt, bob_s.user_id, bob_s.session_id)
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let mut alice = sqlite_client(&alice_db, pw);
        alice
            .connection_request(Credentials::Session {
                refresh_jwt: alice_rjwt,
            })
            .await
            .expect("alice reconnect");
        let mut bob = sqlite_client(&bob_db, pw);
        bob.connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("bob reconnect");

        let alice_low = alice.get_low_agent().expect("alice low 2");
        let bob_low = bob.get_low_agent().expect("bob low 2");

        // Sanity: после literal restart olm-сессия должна быть в БД.
        let post = alice_low.store().olm_sessions(bob_sid).await;
        assert!(
            !post.is_empty(),
            "BUG: alice's olm session with bob not restored from SqliteStore after literal restart"
        );

        let bob_curve = {
            let acc = bob_low.store().account().await;
            let a = acc.lock().await;
            a.curve25519_public_b64()
        };

        let mut bob_rx = bob_low.subscribe();
        alice_low
            .olm()
            .send(bob_uid, bob_sid, "after literal restart")
            .wait()
            .await
            .expect("send");

        let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::ToDevice(_))).await;
        let Event::ToDevice(payload) = evt else { unreachable!() };
        let inner = payload
            .ciphertext
            .get(&bob_curve)
            .expect("ciphertext for bob");

        assert_eq!(
            inner.ciphertext_type, 1,
            "type=1 expected (established outbound preserved), got type={}. \
             If type=0 — either session lost after restart, or inbound shadowed outbound",
            inner.ciphertext_type
        );

        let pt = bob_low
            .olm()
            .decrypt(payload)
            .wait()
            .await
            .expect("decrypt")
            .expect("plaintext");
        assert_eq!(pt, "after literal restart");

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn megolm_rotation_meta_survives_literal_restart() {
    let (_adir, alice_db) = tmp_db();
    let (_bdir, bob_db) = tmp_db();
    let pw = "pw";

    let (alice_rjwt, bob_rjwt, group_id, s1) = {
        let mut alice_cfg = common::test_config();
        alice_cfg.megolm_rotation_message_count = 100; // не триггерим
        alice_cfg.megolm_rotation_ttl_secs = 0;        // не триггерим
        let mut alice = {
            let store = Arc::new(SqliteStore::open(&alice_db, pw).expect("sqlite open"));
            LockNetClient::with_store(alice_cfg, store)
        };
        let a_sess = alice
            .connection_request(Credentials::Register {
                username: format!("rot_meta_a_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("alice reg");

        let mut bob = sqlite_client(&bob_db, pw);
        let b_sess = bob
            .connection_request(Credentials::Register {
                username: format!("rot_meta_b_{}", common::unique_suffix()),
                password: "pw".into(),
                display_name: None,
            })
            .await
            .expect("bob reg");

        let alice_low = alice.get_low_agent().expect("alice low");
        let bob_low = bob.get_low_agent().expect("bob low");

        let group = alice_low
            .groups()
            .create("RotMeta", false, None, vec![b_sess.user_id])
            .await
            .expect("create");
        let gid = group.id;

        let bob_inv = bob_low
            .groups()
            .invites()
            .await
            .expect("inv")
            .into_iter()
            .find(|i| i.group_id == gid)
            .expect("bob inv");
        bob_low
            .groups()
            .accept_invite(bob_inv.id)
            .await
            .expect("accept");

        // Создаём сессию и шлём 3 сообщения (meta.messages_sent = 3)
        let info = alice_low.megolm().create(gid).await.expect("create mg");
        let s1 = info.megolm_session_id.clone();

        for i in 0..3 {
            alice_low
                .megolm()
                .encrypt(gid, &format!("m{i}"))
                .await
                .expect("encrypt");
        }

        // Sanity: meta существует, messages_sent = 3
        let meta = alice_low
            .store()
            .megolm_outbound_meta(gid)
            .await
            .expect("meta");
        assert_eq!(meta.messages_sent, 3, "3 messages before restart");
        assert_eq!(meta.session_id, s1);

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();

        (a_sess.rjwt, b_sess.rjwt, gid, s1)
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    {
        let mut alice_cfg = common::test_config();
        alice_cfg.megolm_rotation_message_count = 100;
        alice_cfg.megolm_rotation_ttl_secs = 0;
        let mut alice = {
            let store = Arc::new(SqliteStore::open(&alice_db, pw).expect("sqlite reopen"));
            LockNetClient::with_store(alice_cfg, store)
        };
        alice
            .connection_request(Credentials::Session {
                refresh_jwt: alice_rjwt,
            })
            .await
            .expect("alice reconnect");
        let mut bob = sqlite_client(&bob_db, pw);
        bob.connection_request(Credentials::Session {
            refresh_jwt: bob_rjwt,
        })
        .await
        .expect("bob reconnect");

        let alice_low = alice.get_low_agent().expect("alice low 2");

        // Meta должна пережить restart: messages_sent = 3, session_id = s1
        let meta_after = alice_low
            .store()
            .megolm_outbound_meta(group_id)
            .await
            .expect("meta after restart");
        assert_eq!(meta_after.messages_sent, 3, "counter preserved");
        assert_eq!(meta_after.session_id, s1, "session_id preserved");

        // ensure_session не должен ротировать (count=100, ttl=0)
        let (info, rotated) = alice_low
            .megolm()
            .ensure_session(group_id)
            .await
            .expect("ensure");
        assert!(!rotated, "no rotation after restart with count=100");
        assert_eq!(info.megolm_session_id, s1);

        alice.disconnect().await.ok();
        bob.disconnect().await.ok();
    }
}