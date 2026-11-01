mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_keys_returns_own_session() {
    let alice = common::register_new("keys_q_a").await;
    let bob = common::register_new("keys_q_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    // Считываем identity keys из локального Account
    let (own_curve, own_ed) = {
        let acc = alice_low.store().account();
        let a = acc.lock().await;
        (a.curve25519_public_b64(), a.ed25519_public_b64())
    };

    let result = bob_low
        .keys()
        .query(vec![alice.session.user_id])
        .await
        .expect("query_keys");

    let sessions = result
        .get(&alice.session.user_id)
        .expect("alice's session map present");
    assert!(
        sessions.contains_key(&alice.session.session_id),
        "expected session {} in query_keys, got {:?}",
        alice.session.session_id,
        sessions.keys().collect::<Vec<_>>()
    );

    let dev = &sessions[&alice.session.session_id];
    assert_eq!(dev.curve25519_key, own_curve);
    assert_eq!(dev.ed25519_key, own_ed);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_keys_unknown_user_returns_no_entry() {
    let bob = common::register_new("keys_unk_b").await;
    let bob_low = bob.low();

    let result = bob_low
        .keys()
        .query(vec![999_999_999_999])
        .await
        .expect("query_keys");

    assert!(
        !result.contains_key(&999_999_999_999),
        "unknown user should not appear in query_keys result"
    );

    let mut b = bob;
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_one_time_key_returns_distinct_keys() {
    let alice = common::register_new("keys_claim_a").await;
    let bob = common::register_new("keys_claim_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;

    let otk1 = bob_low
        .keys()
        .claim_one_time_key(alice_uid, alice_sid, None)
        .await
        .expect("claim #1");
    assert!(!otk1.key_id.is_empty());
    assert!(!otk1.key.is_empty());
    assert!(
        otk1.key_id.starts_with("curve25519:"),
        "expected curve25519 key_id, got {}",
        otk1.key_id
    );

    let otk2 = bob_low
        .keys()
        .claim_one_time_key(alice_uid, alice_sid, None)
        .await
        .expect("claim #2");
    assert_ne!(otk1.key_id, otk2.key_id, "each claim consumes distinct OTK");
    assert_ne!(otk1.key, otk2.key);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_one_time_key_session_not_found() {
    let alice = common::register_new("keys_snf_a").await;
    let bob = common::register_new("keys_snf_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();
    let alice_sid = alice.session.session_id;

    // Неверный user_id для этой сессии → session_not_found
    let err = bob_low
        .keys()
        .claim_one_time_key(alice.session.user_id + 1, alice_sid, None)
        .await
        .unwrap_err();
    common::assert_server_code(err, "session_not_found");

    // Несуществующий session_id → session_not_found
    let err = bob_low
        .keys()
        .claim_one_time_key(alice.session.user_id, 999_999_999_999, None)
        .await
        .unwrap_err();
    common::assert_server_code(err, "session_not_found");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_one_time_key_exhausts_after_50() {
    let alice = common::register_new("keys_empty_a").await;
    let bob = common::register_new("keys_empty_b").await;

    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;

    // client.rs при register вызывает upload_keys с generate_one_time_keys(50)
    // → на сервере ровно 50 OTK. Выжигаем их все.
    let mut claimed = 0u32;
    loop {
        match bob_low
            .keys()
            .claim_one_time_key(alice_uid, alice_sid, None)
            .await
        {
            Ok(_) => {
                claimed += 1;
                assert!(claimed <= 100, "sanity: too many OTKs claimed, something is off");
            }
            Err(e) => {
                common::assert_server_code(e, "no_one_time_keys");
                break;
            }
        }
    }
    assert_eq!(claimed, 50, "expected exactly 50 OTKs uploaded on register");

    // Ещё один claim — снова no_one_time_keys
    let err = bob_low
        .keys()
        .claim_one_time_key(alice_uid, alice_sid, None)
        .await
        .unwrap_err();
    common::assert_server_code(err, "no_one_time_keys");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_uses_one_time_keys_under_chosen_algorithm() {
    let alice = common::register_new("keys_alg_a").await;
    let bob = common::register_new("keys_alg_b").await;

    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;

    // Явный algorithm="curve25519" — должно работать
    let otk = bob_low
        .keys()
        .claim_one_time_key(alice_uid, alice_sid, Some("curve25519".to_string()))
        .await
        .expect("claim curve25519");
    assert!(otk.key_id.starts_with("curve25519:"));

    // Неизвестный algorithm → no_one_time_keys (других алгоритмов нет)
    let err = bob_low
        .keys()
        .claim_one_time_key(alice_uid, alice_sid, Some("signed_curve25519".to_string()))
        .await
        .unwrap_err();
    common::assert_server_code(err, "no_one_time_keys");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}