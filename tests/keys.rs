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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_is_always_verified() {
    let alice = common::register_new("tg_self_a").await;
    let agent = alice.client.get_agent().expect("agent");

    assert!(agent.security().is_user_verified(alice.session.user_id).await);
}

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
        "без подписи USK->MSK доверия быть не должно"
    );
}

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
        "прямая подпись USK->MSK = доверие"
    );
}

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
        "Alice -> Bob: прямая подпись"
    );

    assert!(
        alice_agent.security().is_user_verified(charlie.session.user_id).await,
        "Alice -> Bob -> Charlie: транзитивное доверие"
    );
}

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
        "цепочка Alice -> Bob -> Charlie должна быть доверенной"
    );

    let charlie_pw = charlie.password.clone();
    charlie_low
        .crypto()
        .reset_cross_signing_keys(&charlie_pw)
        .await
        .expect("charlie reset");
    tokio::time::sleep(Duration::from_millis(200)).await;

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
        "прямое доверие Alice -> Bob не должно ломаться"
    );

    assert!(
        !fresh_agent.security().is_user_verified(charlie.session.user_id).await,
        "после reset Charlie должен быть недостижим в цепочке"
    );

    fresh_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    let mut c = charlie;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
    c.client.disconnect().await.ok();
}