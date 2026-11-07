mod common;

use std::collections::HashMap;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{
    CrossSigningKey, CrossSigningKeys, CrossSigningSignatureAdded, Signatures,
};
use locknet_rcab::Event;

fn build_cross_signing_payload(user_id: i64, keys: &CrossSigningKeysPrivate) -> CrossSigningKeys {
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
        master_key: CrossSigningKey {
            key: msk_pub,
            signatures: HashMap::new(),
        },
        self_signing_key: CrossSigningKey {
            key: ssk_pub,
            signatures: ssk_sigs,
        },
        user_signing_key: CrossSigningKey {
            key: usk_pub,
            signatures: usk_sigs,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_cross_signing_then_reupload_fails() {
    let alice = common::register_new("cs_up_a").await;
    let alice_low = alice.low();
    let uid = alice.session.user_id;

    let keys = CrossSigningKeysPrivate::generate();
    let payload = build_cross_signing_payload(uid, &keys);

    alice_low
        .crypto()
        .upload_cross_signing_keys(payload.clone())
        .await
        .expect("first upload");

    let err = alice_low
        .crypto()
        .upload_cross_signing_keys(payload)
        .await
        .unwrap_err();
    common::assert_server_code(err, "cross_signing_already_exists");

    let mut a = alice;
    a.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_returns_three_keys() {
    let alice = common::register_new("cs_q_a").await;
    let bob = common::register_new("cs_q_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let uid = alice.session.user_id;

    let keys = CrossSigningKeysPrivate::generate();
    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(uid, &keys))
        .await
        .expect("upload");

    let result = bob_low
        .crypto()
        .query_cross_signing_keys(vec![uid])
        .await
        .expect("query");

    let entry = result.get(&uid).expect("alice present");
    assert_eq!(entry.master_key.key, keys.msk_pub_b64());
    assert_eq!(
        entry.self_signing_key.as_ref().map(|k| k.key.as_str()),
        Some(keys.ssk_pub_b64().as_str())
    );
    assert_eq!(
        entry.user_signing_key.as_ref().map(|k| k.key.as_str()),
        Some(keys.usk_pub_b64().as_str())
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usk_signs_other_msk() {
    let alice = common::register_new("cs_sig_a").await;
    let bob = common::register_new("cs_sig_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let a_uid = alice.session.user_id;
    let b_uid = bob.session.user_id;

    let a_keys = CrossSigningKeysPrivate::generate();
    let b_keys = CrossSigningKeysPrivate::generate();

    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &a_keys))
        .await
        .expect("alice upload");
    bob_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(b_uid, &b_keys))
        .await
        .expect("bob upload");

    let b_query = alice_low
        .crypto()
        .query_cross_signing_keys(vec![b_uid])
        .await
        .expect("query bob");
    let b_msk_pub = b_query.get(&b_uid).unwrap().master_key.key.clone();

    let sig = sign_b64(&a_keys.usk, &b_msk_pub).expect("sign b_msk");

    let mut bob_rx = bob_low.subscribe();
    let ack = alice_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(b_uid, sig.clone())].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .expect("upload sig");
    assert_eq!(ack.users_updated, 1);
    assert_eq!(ack.devices_updated, 0);

    let evt = common::wait_event(&mut bob_rx, |e| {
        matches!(e, Event::CrossSigningSignatureAdded(_))
    })
    .await;
    let Event::CrossSigningSignatureAdded(CrossSigningSignatureAdded {
        signer_user_id,
        key_type,
        target,
        signature,
    }) = evt
    else {
        unreachable!()
    };
    assert_eq!(signer_user_id, a_uid);
    assert_eq!(key_type, "user_signing");
    assert_eq!(target, "master");
    assert_eq!(signature, sig);

    let result = bob_low
        .crypto()
        .query_cross_signing_keys(vec![b_uid])
        .await
        .expect("bob query");
    let msk_sigs = &result.get(&b_uid).unwrap().master_key.signatures;
    assert_eq!(
        msk_sigs.get(&a_uid.to_string()).and_then(|m| m.get("user_signing")),
        Some(&sig)
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_signature_rejected() {
    let alice = common::register_new("cs_bad_a").await;
    let bob = common::register_new("cs_bad_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let a_uid = alice.session.user_id;
    let b_uid = bob.session.user_id;

    let a_keys = CrossSigningKeysPrivate::generate();
    let b_keys = CrossSigningKeysPrivate::generate();

    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &a_keys))
        .await
        .expect("alice upload");
    bob_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(b_uid, &b_keys))
        .await
        .expect("bob upload");

    let err = alice_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(b_uid, "AAAA".to_string())].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .unwrap_err();
    common::assert_server_code(err, "invalid_signature");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_signature_by_own_ssk() {
    let alice = common::register_new("cs_dev_a").await;
    let alice_low = alice.low();
    let a_uid = alice.session.user_id;
    let a_sid = alice.session.session_id;

    let a_keys = CrossSigningKeysPrivate::generate();
    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &a_keys))
        .await
        .expect("upload cs");

    let own_ed_b64 = {
        let acc = alice_low.store().account().await;
        let acc = acc.lock().await;
        acc.ed25519_public_b64()
    };
    let device_sig = sign_b64(&a_keys.ssk, &own_ed_b64).expect("sign device");

    let ack = alice_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: HashMap::new(),
            device_signatures: [(a_sid, device_sig.clone())].into_iter().collect(),
        })
        .await
        .expect("upload device sig");
    assert_eq!(ack.devices_updated, 1);

    let result = alice_low
        .crypto()
        .query_cross_signing_keys(vec![a_uid])
        .await
        .expect("query");
    let entry = result.get(&a_uid).unwrap();
    let dev = entry.devices.get(&a_sid).expect("device present");
    assert_eq!(dev.ed25519_key, own_ed_b64);
    assert_eq!(
        dev.signatures
            .get(&a_uid.to_string())
            .and_then(|m| m.get("self_signing")),
        Some(&device_sig)
    );

    let mut a = alice;
    a.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_wrong_password_fails() {
    let alice = common::register_new("cs_rpw_a").await;
    let alice_low = alice.low();
    let a_uid = alice.session.user_id;

    let a_keys = CrossSigningKeysPrivate::generate();
    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &a_keys))
        .await
        .expect("upload");

    let err = alice_low
        .crypto()
        .reset_cross_signing_keys("definitely-wrong")
        .await
        .unwrap_err();
    common::assert_server_code(err, "invalid_password");

    let mut a = alice;
    a.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_clears_keys_and_affected_signers_notified() {
    let alice = common::register_new("cs_rst_a").await;
    let bob = common::register_new("cs_rst_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let a_uid = alice.session.user_id;
    let b_uid = bob.session.user_id;
    let a_pw = alice.password.clone();

    let a_keys = CrossSigningKeysPrivate::generate();
    let b_keys = CrossSigningKeysPrivate::generate();

    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &a_keys))
        .await
        .expect("alice upload");
    bob_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(b_uid, &b_keys))
        .await
        .expect("bob upload");

    let b_msk = bob_low
        .crypto()
        .query_cross_signing_keys(vec![b_uid])
        .await
        .unwrap()
        .get(&b_uid)
        .unwrap()
        .master_key
        .key
        .clone();
    let a_sig = sign_b64(&a_keys.usk, &b_msk).unwrap();
    alice_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(b_uid, a_sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .expect("a signs b msk");

    let a_msk = alice_low
        .crypto()
        .query_cross_signing_keys(vec![a_uid])
        .await
        .unwrap()
        .get(&a_uid)
        .unwrap()
        .master_key
        .key
        .clone();
    let b_sig = sign_b64(&b_keys.usk, &a_msk).unwrap();
    bob_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(a_uid, b_sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .expect("b signs a msk");

    let mut bob_rx = bob_low.subscribe();
    let result = alice_low
        .crypto()
        .reset_cross_signing_keys(&a_pw)
        .await
        .expect("reset");
    assert!(
        result.affected_users.contains(&b_uid),
        "bob должен быть в affected_users (он подписал MSK alice), got {:?}",
        result.affected_users
    );

    let evt = common::wait_event(&mut bob_rx, |e| matches!(e, Event::CrossSigningReset(_))).await;
    let Event::CrossSigningReset(r) = evt else { unreachable!() };
    assert_eq!(r.user_id, a_uid);

    let after = alice_low
        .crypto()
        .query_cross_signing_keys(vec![a_uid])
        .await
        .expect("query after reset");
    assert!(
        !after.contains_key(&a_uid),
        "alice's cross-signing must be gone, got {:?}",
        after.keys().collect::<Vec<_>>()
    );

    let b_after = bob_low
        .crypto()
        .query_cross_signing_keys(vec![b_uid])
        .await
        .expect("query bob after");
    let msk_sigs = &b_after.get(&b_uid).unwrap().master_key.signatures;
    assert!(
        msk_sigs.get(&a_uid.to_string()).is_none(),
        "alice's USK signature must be removed from bob's MSK"
    );

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn can_reupload_after_reset() {
    let alice = common::register_new("cs_reup_a").await;
    let alice_low = alice.low();
    let a_uid = alice.session.user_id;
    let a_pw = alice.password.clone();

    let keys1 = CrossSigningKeysPrivate::generate();
    let msk1 = keys1.msk_pub_b64();
    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &keys1))
        .await
        .expect("upload #1");

    alice_low
        .crypto()
        .reset_cross_signing_keys(&a_pw)
        .await
        .expect("reset");

    let keys2 = CrossSigningKeysPrivate::generate();
    let msk2 = keys2.msk_pub_b64();
    alice_low
        .crypto()
        .upload_cross_signing_keys(build_cross_signing_payload(a_uid, &keys2))
        .await
        .expect("upload #2");

    let result = alice_low
        .crypto()
        .query_cross_signing_keys(vec![a_uid])
        .await
        .expect("query");
    let new_msk = result.get(&a_uid).unwrap().master_key.key.clone();
    assert_eq!(new_msk, msk2);
    assert_ne!(new_msk, msk1);

    let mut a = alice;
    a.client.disconnect().await.ok();
}