//! Web of Trust (transitive cross-signing trust).
//!
//! `SecurityHelper::is_user_verified(uid)` implements **transitive** trust:
//! it builds a directed graph where an edge `A -> B` means "A's `user_signing`
//! key signed B's `master_key`", then runs BFS from the local user. Any node
//! reachable from the local user is considered trusted.
//!
//! Self is always trusted (BFS starts there).
//!
//! Signatures are **verified** during graph construction (Ed25519 check),
//! so the server cannot inject fake edges — a bad signature is silently
//! ignored. The graph is cached in `ClientState.reachable_users` and
//! invalidated on `CrossSigningSignatureAdded` / `CrossSigningReset`.
//!
//! What is verified:
//!
//! - Self is always verified.
//! - A user with no `USK -> MSK` signature is not verified.
//! - A direct signature (`Alice -> Bob`) establishes trust.
//! - A transitive chain (`Alice -> Bob -> Charlie`) makes Charlie trusted
//!   from Alice's perspective.
//! - After Charlie resets his cross-signing, the chain breaks; a fresh client
//!   rebuilding the graph from scratch sees the broken state.
//!
//! Requirements:
//!
//! - `setup_cs()` for every participant (only the signer's and the target's
//!   CS keys matter; intermediate nodes in a chain need CS because they
//!   appear as both signer and target).
//!
//! Not covered here: which sessions receive keys based on trust
//! (`tests/history_visibility.rs`, `tests/megolm_visibility.rs`).

mod common;

use std::collections::HashMap;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, Signatures};
use locknet_rcab::{Credentials, LockNetClient, LockNetLowAgent};

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

async fn setup_cs(low: &LockNetLowAgent) -> CrossSigningKeysPrivate {
    let uid = low.user_id();
    let sid = low.session_id();

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
        .expect("upload device sig");

    keys
}

/// Sign the target user's MSK with the signer's USK.
async fn sign_msk(
    signer_low: &LockNetLowAgent,
    signer_keys: &CrossSigningKeysPrivate,
    target_uid: i64,
) -> Result<(), String> {
    let query = signer_low
        .crypto()
        .query_cross_signing_keys(vec![target_uid])
        .await
        .map_err(|e| format!("query target msk: {e:?}"))?;
    let target_msk = query
        .get(&target_uid)
        .map(|u| u.master_key.key.clone())
        .ok_or_else(|| format!("target {target_uid} msk not found"))?;

    let sig = sign_b64(&signer_keys.usk, &target_msk).map_err(|e| format!("sign: {e:?}"))?;

    signer_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(target_uid, sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await
        .map_err(|e| format!("upload sig: {e:?}"))?;

    Ok(())
}

// ---- tests ----

/// A user always trusts themselves (root of the Web of Trust).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_is_always_verified() {
    let alice = common::register_new("tg_self_a").await;
    let agent = alice.client.get_agent().expect("agent");

    assert!(agent.security().is_user_verified(alice.session.user_id).await);
}

/// Without a `USK -> MSK` signature, no trust is established.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_trust_chain_returns_false() {
    let alice = common::register_new("tg_none_a").await;
    let bob = common::register_new("tg_none_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_low = bob.low();

    setup_cs(&alice_agent.low()).await;
    setup_cs(&bob_low).await;

    let _ = alice_agent.user_info(bob.session.user_id).await;

    assert!(
        !alice_agent.security().is_user_verified(bob.session.user_id).await,
        "without a USK -> MSK signature, trust must be absent"
    );
}

/// A direct signature (Alice's USK signs Bob's MSK) establishes trust.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_trust_via_sas_signature() {
    let alice = common::register_new("tg_direct_a").await;
    let bob = common::register_new("tg_direct_b").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let bob_low = bob.low();
    let alice_low = alice_agent.low();

    let alice_cs = setup_cs(&alice_low).await;
    setup_cs(&bob_low).await;

    let _ = alice_agent.user_info(bob.session.user_id).await;

    sign_msk(&alice_low, &alice_cs, bob.session.user_id)
        .await
        .expect("alice signs bob msk");

    assert!(
        alice_agent.security().is_user_verified(bob.session.user_id).await,
        "direct USK -> MSK signature establishes trust"
    );
}

/// A transitive trust chain `Alice -> Bob -> Charlie` makes Charlie trusted
/// from Alice's perspective even though Alice never signed Charlie directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transitive_trust_alice_bob_charlie() {
    let alice = common::register_new("tg_trans_a").await;
    let bob = common::register_new("tg_trans_b").await;
    let charlie = common::register_new("tg_trans_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_low = alice_agent.low();
    let bob_low = bob.low();
    let charlie_low = charlie.low();

    let alice_cs = setup_cs(&alice_low).await;
    let bob_cs = setup_cs(&bob_low).await;
    let _charlie_cs = setup_cs(&charlie_low).await;

    let _ = alice_agent.user_info(bob.session.user_id).await;
    let _ = alice_agent.user_info(charlie.session.user_id).await;

    sign_msk(&alice_low, &alice_cs, bob.session.user_id).await.expect("alice signs bob");
    sign_msk(&bob_low, &bob_cs, charlie.session.user_id).await.expect("bob signs charlie");

    assert!(
        alice_agent.security().is_user_verified(bob.session.user_id).await,
        "Alice -> Bob: direct signature"
    );

    assert!(
        alice_agent.security().is_user_verified(charlie.session.user_id).await,
        "Alice -> Bob -> Charlie: transitive trust"
    );
}

/// Resetting cross-signing breaks the trust chain. A fresh client (which
/// rebuilds the graph from scratch) must see the broken state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_breaks_chain() {
    let alice = common::register_new("tg_rev_a").await;
    let bob = common::register_new("tg_rev_b").await;
    let charlie = common::register_new("tg_rev_c").await;

    let alice_agent = alice.client.get_agent().expect("alice agent");
    let alice_low = alice_agent.low();
    let bob_low = bob.low();
    let charlie_low = charlie.low();

    let alice_cs = setup_cs(&alice_low).await;
    let bob_cs = setup_cs(&bob_low).await;
    let _charlie_cs = setup_cs(&charlie_low).await;

    let _ = alice_agent.user_info(bob.session.user_id).await;
    let _ = alice_agent.user_info(charlie.session.user_id).await;

    sign_msk(&alice_low, &alice_cs, bob.session.user_id).await.unwrap();
    sign_msk(&bob_low, &bob_cs, charlie.session.user_id).await.unwrap();

    assert!(
        alice_agent.security().is_user_verified(charlie.session.user_id).await,
        "the Alice -> Bob -> Charlie chain must be trusted"
    );

    // Charlie resets his cross-signing keys.
    let charlie_pw = charlie.password.clone();
    charlie_low
        .crypto()
        .reset_cross_signing_keys(&charlie_pw)
        .await
        .expect("charlie reset");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Rebuild the graph from scratch on a fresh client.
    let mut fresh_client = LockNetClient::new(common::test_config());
    let _ = fresh_client
        .connection_request(Credentials::Session {
            refresh_jwt: alice.session.rjwt.clone(),
        })
        .await
        .expect("fresh session");
    let fresh_agent = fresh_client.get_agent().expect("fresh agent");

    let _ = fresh_agent.user_info(bob.session.user_id).await;
    let _ = fresh_agent.user_info(charlie.session.user_id).await;

    assert!(
        fresh_agent.security().is_user_verified(bob.session.user_id).await,
        "direct trust Alice -> Bob must survive"
    );

    assert!(
        !fresh_agent.security().is_user_verified(charlie.session.user_id).await,
        "after the reset, Charlie must be unreachable in the chain"
    );

    fresh_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}