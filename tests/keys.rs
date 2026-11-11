//! Olm key management: `query_keys` and `claim_one_time_key`.
//!
//! Covers the low-level `LockNetKeysHelper` over the real server:
//!
//! - `query_keys` returns the identity keys and one-time keys for the
//!   requested users.
//! - `query_keys` for an unknown user returns no entry (not an error).
//! - `claim_one_time_key` returns a one-time key and removes it from the
//!   server; subsequent claims return different keys.
//! - Claiming a key for a session that does not belong to the requested user
//!   fails with `session_not_found`.
//! - After 50 claims (the number uploaded by `client.rs` during
//!   registration), the next claim fails with `no_one_time_keys`.
//! - The `algorithm` parameter is honored: `curve25519` finds keys,
//!   unknown algorithms do not.
//!
//! Requirements:
//!
//! - A fresh user (via `register_new`) — this uploads 50 OTKs as a side
//!   effect, which the exhaustion test relies on.
//!
//! Not covered here: full Olm session establishment (`tests/olm.rs`),
//! `upload_keys` itself (implicitly tested via `register_new`).

mod common;

/// `query_keys` returns the current session's identity keys exactly as they
/// are in the local account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn query_keys_returns_own_session() {
    let alice = common::register_new("keys_q_a").await;
    let bob = common::register_new("keys_q_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let (own_curve, own_ed) = {
        let acc = alice_low.store().account().await;
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
        .expect("alice's session map is present");
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

/// Querying an unknown user returns an empty map (not an error, not a
/// placeholder).
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
        "an unknown user must not appear in query_keys"
    );

    let mut b = bob;
    b.client.disconnect().await.ok();
}

/// `claim_one_time_key` returns distinct keys: each claim removes the
/// claimed key from the server-side OTK set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_one_time_key_returns_distinct_keys() {
    let alice = common::register_new("keys_claim_a").await;
    let bob = common::register_new("keys_claim_b").await;

    let _alice_low = alice.low();
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
    assert_ne!(
        otk1.key_id, otk2.key_id,
        "each claim consumes a distinct OTK"
    );
    assert_ne!(otk1.key, otk2.key);

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Claiming a key for a mismatched `(user_id, session_id)` pair fails with
/// `session_not_found`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_one_time_key_session_not_found() {
    let alice = common::register_new("keys_snf_a").await;
    let bob = common::register_new("keys_snf_b").await;

    let _alice_low = alice.low();
    let bob_low = bob.low();
    let alice_sid = alice.session.session_id;

    // Wrong user_id for this session.
    let err = bob_low
        .keys()
        .claim_one_time_key(alice.session.user_id + 1, alice_sid, None)
        .await
        .unwrap_err();
    common::assert_server_code(err, "session_not_found");

    // Non-existent session_id.
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

/// After 50 claims (the number uploaded by `client.rs` during
/// registration), the next claim fails with `no_one_time_keys`.
///
/// This verifies both the OTK exhaustion path and the assumption that
/// registration uploads exactly 50 OTKs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_one_time_key_exhausts_after_50() {
    let alice = common::register_new("keys_empty_a").await;
    let bob = common::register_new("keys_empty_b").await;

    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;

    let mut claimed = 0u32;
    loop {
        match bob_low
            .keys()
            .claim_one_time_key(alice_uid, alice_sid, None)
            .await
        {
            Ok(_) => {
                claimed += 1;
                assert!(
                    claimed <= 100,
                    "sanity: too many OTKs claimed, something is off"
                );
            }
            Err(e) => {
                common::assert_server_code(e, "no_one_time_keys");
                break;
            }
        }
    }
    assert_eq!(claimed, 50, "expected exactly 50 OTKs uploaded on register");

    // A further claim hits the same wall.
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

/// The `algorithm` parameter is honored: `curve25519` finds keys, unknown
/// algorithms do not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_uses_one_time_keys_under_chosen_algorithm() {
    let alice = common::register_new("keys_alg_a").await;
    let bob = common::register_new("keys_alg_b").await;

    let bob_low = bob.low();
    let alice_uid = alice.session.user_id;
    let alice_sid = alice.session.session_id;

    let otk = bob_low
        .keys()
        .claim_one_time_key(alice_uid, alice_sid, Some("curve25519".to_string()))
        .await
        .expect("claim curve25519");
    assert!(otk.key_id.starts_with("curve25519:"));

    // No OTKs of an unknown algorithm exist, so the server returns
    // `no_one_time_keys`.
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
