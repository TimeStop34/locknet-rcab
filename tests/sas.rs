mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::api::low::helpers::verification::{SasStatus, SasStep};
use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{Event, LockNetError, LockNetLowAgent};
use serde_json::Value;

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

async fn own_ed25519(low: &LockNetLowAgent) -> String {
    let acc = low.store().account().await;
    let acc = acc.lock().await;
    acc.ed25519_public_b64()
}

async fn setup_full(user: &common::TestUser) -> CrossSigningKeysPrivate {
    let low = user.low();
    let uid = user.session.user_id;
    let sid = user.session.session_id;

    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(uid, &keys))
        .await
        .expect("upload cross-signing");

    let own_ed = own_ed25519(&low).await;
    let dev_sig = sign_b64(&keys.ssk, &own_ed).expect("sign device");
    low.crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(sid, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload device signature");

    keys
}

async fn setup_olm(
    alice_low: &LockNetLowAgent,
    bob_low: &LockNetLowAgent,
    bob_uid: i64,
    bob_sid: i64,
) {
    let mut rx = bob_low.subscribe();
    alice_low
        .olm()
        .send(bob_uid, bob_sid, "setup")
        .wait()
        .await
        .expect("olm forward setup");
    let evt = common::wait_event(&mut rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    bob_low.olm().decrypt(p).wait().await.expect("forward setup decrypt");

    let mut rx2 = alice_low.subscribe();
    bob_low
        .olm()
        .send(alice_low.user_id(), alice_low.session_id(), "setup-rev")
        .wait()
        .await
        .expect("olm reverse setup");
    let evt = common::wait_event(&mut rx2, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    alice_low.olm().decrypt(p).wait().await.expect("reverse setup decrypt");
}

async fn peer_keys(
    observer: &LockNetLowAgent,
    peer_uid: i64,
    peer_sid: i64,
) -> (String, String) {
    let sessions = observer
        .keys()
        .query(vec![peer_uid])
        .await
        .expect("query_keys");
    let ed = sessions
        .get(&peer_uid)
        .and_then(|m| m.get(&peer_sid))
        .map(|d| d.ed25519_key.clone())
        .expect("peer session ed25519 in query_keys");

    let cs = observer
        .crypto()
        .query_cross_signing_keys(vec![peer_uid])
        .await
        .expect("query_cross_signing_keys");
    let msk = cs
        .get(&peer_uid)
        .map(|u| u.master_key.key.clone())
        .expect("peer msk in query_cross_signing_keys");

    (ed, msk)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_full_flow_with_peer_verification() {
    let alice = common::register_new("sas_ok_a").await;
    let bob = common::register_new("sas_ok_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_ed = own_ed25519(&alice_low).await;
    let b_ed = own_ed25519(&bob_low).await;
    let a_msk = a_keys.msk_pub_b64();
    let b_msk = b_keys.msk_pub_b64();

    let (peer_ed_a, peer_msk_a) = peer_keys(&alice_low, bob_uid, bob_sid).await;
    let (peer_ed_b, peer_msk_b) = peer_keys(&bob_low, alice_uid, alice_sid).await;

    assert_eq!(b_ed, peer_ed_a, "Alice должна видеть тот же ed25519 Bob'а");
    assert_eq!(b_msk, peer_msk_a, "Alice должна видеть тот же MSK Bob'а");
    assert_eq!(a_ed, peer_ed_b, "Bob должен видеть тот же ed25519 Alice");
    assert_eq!(a_msk, peer_msk_b, "Bob должен видеть тот же MSK Alice");

    let mut bob_setup_rx = bob_low.subscribe();
    let mut alice_flow = alice_low
        .verification()
        .sas_start(bob_uid, bob_sid, a_msk.clone(), a_ed.clone())
        .await
        .expect("alice sas_start");

    let evt = common::wait_event(&mut bob_setup_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(start_payload) = evt else { unreachable!() };
    let pt = bob_low
        .olm()
        .decrypt(start_payload)
        .wait()
        .await
        .expect("start decrypt")
        .expect("no plaintext");
    let start_val: Value = serde_json::from_str(&pt).expect("start json");
    assert_eq!(
        start_val.get("type").and_then(|v| v.as_str()),
        Some("ln.encryption.key.verification.start")
    );
    let txid = start_val
        .pointer("/content/transaction_id")
        .and_then(|v| v.as_str())
        .expect("txid present")
        .to_string();

    let mut bob_flow = bob_low
        .verification()
        .sas_start_responder(alice_uid, alice_sid, txid.clone(), b_msk.clone(), b_ed.clone())
        .await
        .expect("bob responder");

    let step_alice = tokio::time::timeout(Duration::from_secs(10), alice_flow.next())
        .await
        .expect("alice next timeout")
        .expect("alice next");
    let emoji_alice = match step_alice {
        SasStep::Emoji(e) => e,
        other => panic!("alice expected Emoji, got {other:?}"),
    };

    let step_bob = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
        .await
        .expect("bob next timeout")
        .expect("bob next");
    let emoji_bob = match step_bob {
        SasStep::Emoji(e) => e,
        other => panic!("bob expected Emoji, got {other:?}"),
    };

    assert_eq!(emoji_alice.len(), 7);
    assert_eq!(emoji_bob.len(), 7);
    for (i, (a, b)) in emoji_alice.iter().zip(emoji_bob.iter()).enumerate() {
        assert_eq!(a.symbol, b.symbol, "emoji[{i}] mismatch: {} vs {}", a.symbol, b.symbol);
    }

    alice_flow.set_peer_keys(peer_ed_a, peer_msk_a);
    bob_flow.set_peer_keys(peer_ed_b, peer_msk_b);

    alice_flow.confirm_emoji(true).await.expect("alice confirm");
    bob_flow.confirm_emoji(true).await.expect("bob confirm");

    let final_alice = tokio::time::timeout(Duration::from_secs(10), alice_flow.next())
        .await
        .expect("alice final timeout")
        .expect("alice final");
    assert!(
        matches!(final_alice, SasStep::Verified),
        "alice final: {final_alice:?}"
    );

    let final_bob = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
        .await
        .expect("bob final timeout")
        .expect("bob final");
    assert!(
        matches!(final_bob, SasStep::Verified),
        "bob final: {final_bob:?}"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_confirm_without_peer_keys_fails() {
    let alice = common::register_new("sas_npk_a").await;
    let bob = common::register_new("sas_npk_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_ed = own_ed25519(&alice_low).await;
    let b_ed = own_ed25519(&bob_low).await;

    let mut bob_setup_rx = bob_low.subscribe();
    let mut alice_flow = alice_low
        .verification()
        .sas_start(bob_uid, bob_sid, a_keys.msk_pub_b64(), a_ed)
        .await
        .expect("alice start");

    let evt = common::wait_event(&mut bob_setup_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    let pt = bob_low.olm().decrypt(p).wait().await.unwrap().unwrap();
    let val: Value = serde_json::from_str(&pt).unwrap();
    let txid = val
        .pointer("/content/transaction_id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    let mut bob_flow = bob_low
        .verification()
        .sas_start_responder(alice_uid, alice_sid, txid, b_keys.msk_pub_b64(), b_ed)
        .await
        .expect("bob responder");

    let _ = alice_flow.next().await.expect("alice next");
    let _ = bob_flow.next().await.expect("bob next");

    let err = alice_flow.confirm_emoji(true).await.unwrap_err();
    match err {
        LockNetError::InvalidArgument(msg) => {
            assert!(msg.contains("set_peer_keys"), "got msg: {msg}");
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    assert!(matches!(
        alice_flow.check_status(),
        SasStatus::NeedUserConfirmation { .. }
    ));

    alice_flow.confirm_emoji(false).await.expect("alice reject");
    let step = alice_flow.next().await.expect("alice next after reject");
    assert!(matches!(step, SasStep::Cancelled(_)));

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_mac_mismatch_cancels() {
    let alice = common::register_new("sas_mm_a").await;
    let bob = common::register_new("sas_mm_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_ed = own_ed25519(&alice_low).await;
    let b_ed = own_ed25519(&bob_low).await;

    let mut bob_setup_rx = bob_low.subscribe();
    let mut alice_flow = alice_low
        .verification()
        .sas_start(bob_uid, bob_sid, a_keys.msk_pub_b64(), a_ed.clone())
        .await
        .expect("alice start");

    let evt = common::wait_event(&mut bob_setup_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    let pt = bob_low.olm().decrypt(p).wait().await.unwrap().unwrap();
    let val: Value = serde_json::from_str(&pt).unwrap();
    let txid = val
        .pointer("/content/transaction_id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    let mut bob_flow = bob_low
        .verification()
        .sas_start_responder(alice_uid, alice_sid, txid, b_keys.msk_pub_b64(), b_ed.clone())
        .await
        .expect("bob responder");

    let _ = alice_flow.next().await.expect("alice next");
    let _ = bob_flow.next().await.expect("bob next");

    alice_flow.set_peer_keys(a_ed.clone(), a_keys.msk_pub_b64());

    let (peer_ed_a_for_bob, peer_msk_a_for_bob) = peer_keys(&bob_low, alice_uid, alice_sid).await;
    bob_flow.set_peer_keys(peer_ed_a_for_bob, peer_msk_a_for_bob);

    alice_flow.confirm_emoji(true).await.expect("alice confirm");
    bob_flow.confirm_emoji(true).await.expect("bob confirm");

    let final_alice = tokio::time::timeout(Duration::from_secs(10), alice_flow.next())
        .await
        .expect("alice timeout")
        .expect("alice final");
    match final_alice {
        SasStep::Cancelled(reason) => {
            assert_eq!(reason, "MAC mismatch");
        }
        other => panic!("alice expected Cancelled(MAC mismatch), got {other:?}"),
    }

    let final_bob = tokio::time::timeout(Duration::from_secs(10), bob_flow.next())
        .await
        .expect("bob timeout")
        .expect("bob final");
    assert!(
        matches!(final_bob, SasStep::Verified),
        "bob final: {final_bob:?}"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sas_rejection_cancels() {
    let alice = common::register_new("sas_rej_a").await;
    let bob = common::register_new("sas_rej_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;
    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;

    let a_keys = setup_full(&alice).await;
    let b_keys = setup_full(&bob).await;
    setup_olm(&alice_low, &bob_low, bob_uid, bob_sid).await;

    let a_ed = own_ed25519(&alice_low).await;
    let b_ed = own_ed25519(&bob_low).await;

    let mut bob_setup_rx = bob_low.subscribe();
    let mut alice_flow = alice_low
        .verification()
        .sas_start(bob_uid, bob_sid, a_keys.msk_pub_b64(), a_ed)
        .await
        .expect("alice start");

    let evt = common::wait_event(&mut bob_setup_rx, |e| matches!(e, Event::ToDevice(_))).await;
    let Event::ToDevice(p) = evt else { unreachable!() };
    let pt = bob_low.olm().decrypt(p).wait().await.unwrap().unwrap();
    let val: Value = serde_json::from_str(&pt).unwrap();
    let txid = val
        .pointer("/content/transaction_id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    let mut bob_flow = bob_low
        .verification()
        .sas_start_responder(alice_uid, alice_sid, txid, b_keys.msk_pub_b64(), b_ed)
        .await
        .expect("bob responder");

    let _ = alice_flow.next().await.expect("alice next");
    let _ = bob_flow.next().await.expect("bob next");

    alice_flow.confirm_emoji(false).await.expect("alice reject");
    let final_alice = alice_flow.next().await.expect("alice final");
    match final_alice {
        SasStep::Cancelled(reason) => {
            assert_eq!(reason, "user rejected");
        }
        other => panic!("alice expected Cancelled(user rejected), got {other:?}"),
    }

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}