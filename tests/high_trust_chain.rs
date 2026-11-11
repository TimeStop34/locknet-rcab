//! Trust-chain behaviour on `cross_signing_reset`.
//!
//! When a user resets their cross-signing keys, their old MSK/SSK/USK are
//! revoked server-side. Peers must:
//!
//! 1. Drop the reset user from the verified-set (and every session of that
//!    user from `verified_sessions`).
//! 2. **Rotate** the Megolm outbound session in every private chat where the
//!    reset user was a member, if the chat's policy gates fan-out by trust.
//!    Without rotation, the attacker (who may control the compromised device)
//!    keeps decrypting new messages with the old session key.
//! 3. Re-fan-out the fresh key to the remaining eligible members only.
//!
//! This test covers `MegolmRotationVisibility::OnlyVerifiedUsers` (default).
//! The `OnlyVerifiedSessions` case exercises the same rotation code path;
//! additionally it relies on the `verified_sessions` cache-cleanup fix,
//! which is best observed with a full SAS handshake (not covered here to
//! keep the test fast).
//!
//! Not covered: public groups (plaintext, no rotation needed),
//! `AllMembers` policy (reset doesn't change access).

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use locknet_rcab::core::crypto::signature::sign_b64;
use locknet_rcab::models::Signatures;
use locknet_rcab::{
    Credentials, HighEvent, LockNetAgent, LockNetClient, LockNetLowAgent, LockNetSessionContext,
    MegolmRotationVisibility,
};
use tokio::sync::broadcast;

// ---- helpers ----

/// Register a user with `MegolmRotationVisibility::OnlyVerifiedUsers` as the
/// default group policy (so newly created groups pick it up).
async fn register_strict(prefix: &str) -> (LockNetClient, LockNetSessionContext, String, String) {
    common::init_tracing();
    let username = format!("{}_{}", prefix, common::unique_suffix());
    let password = "secret123".to_string();
    let mut cfg = common::test_config();
    cfg.default_megolm_rotation_visibility = MegolmRotationVisibility::OnlyVerifiedUsers;
    cfg.default_history_visibility = locknet_rcab::HistoryVisibility::AllVerifiedUsers;
    let mut client = LockNetClient::new(cfg);
    let session = client
        .connection_request(Credentials::Register {
            username: username.clone(),
            password: password.clone(),
            display_name: Some(username.clone()),
        })
        .await
        .expect("register");
    (client, session, username, password)
}

/// Sign `target_uid`'s MSK with `signer_low`'s USK and upload the signature.
/// After this, `signer`'s `is_user_verified(target_uid)` should return true
/// (via WoT graph built from server data).
async fn sign_msk(
    signer_low: &Arc<LockNetLowAgent>,
    target_uid: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys = signer_low
        .store()
        .cross_signing_keys()
        .await
        .ok_or("signer has no cross-signing keys")?;

    let query = signer_low
        .crypto()
        .query_cross_signing_keys(vec![target_uid])
        .await?;
    let target_msk = query
        .get(&target_uid)
        .map(|u| u.master_key.key.clone())
        .ok_or("target has no master key")?;

    let sig = sign_b64(&keys.usk, &target_msk)?;
    signer_low
        .crypto()
        .upload_signatures(Signatures {
            user_signatures: [(target_uid, sig)].into_iter().collect(),
            device_signatures: HashMap::new(),
        })
        .await?;
    Ok(())
}

async fn wait_high<F>(rx: &mut broadcast::Receiver<HighEvent>, pred: F) -> HighEvent
where
    F: Fn(&HighEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
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

async fn wait_key_imported(
    rx: &mut broadcast::Receiver<HighEvent>,
    chat_id: i64,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(HighEvent::KeyImported {
                chat_id: cid,
                megolm_session_id,
            })) if cid == chat_id => return Some(megolm_session_id),
            Ok(Ok(_)) => continue,
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            Ok(Err(broadcast::error::RecvError::Closed)) => return None,
            Err(_) => return None,
        }
    }
}

// ---- test ----

/// Core scenario:
///
/// 1. Alice, Bob, Charlie all have cross-signing. Alice signs Bob's and
///    Charlie's MSKs with her USK → both are trusted by Alice.
/// 2. Alice creates a private group with Bob and Charlie. Default policy is
///    `OnlyVerifiedUsers`.
/// 3. Alice's first `send()`:
///    - creates megolm outbound session `s1`;
///    - fans out `s1` to Bob and Charlie (both pass `is_user_verified` and
///      `is_session_verified`).
/// 4. Bob resets his cross-signing. Server revokes Bob's MSK/SSK/USK and
///    notifies Alice with `cross_signing_reset(bob_id)`.
/// 5. Alice's agent must:
///    - drop Bob from `verified_users`;
///    - drop Bob's sessions from `verified_sessions`;
///    - **rotate** megolm in this chat (`s1` → `s2`);
///    - fan out `s2` to Charlie only (Bob excluded: `is_user_verified(bob)`
///      is now false).
/// 6. Alice's second `send()` uses `s2`. Bob has no `s2`, cannot decrypt.
///    Charlie has both `s1` and `s2`, can decrypt both messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_signing_reset_rotates_megolm_and_excludes_user() {
    common::init_tracing();

    // --- 1. Register three users with strict default policy ---
    let (mut alice_client, alice_sess, alice_user, _alice_pw) = register_strict("tc_a").await;
    let (mut bob_client, bob_sess, _bob_user, bob_pw) = register_strict("tc_b").await;
    let (mut charlie_client, charlie_sess, _charlie_user, _charlie_pw) =
        register_strict("tc_c").await;

    let _alice_uid = alice_sess.user_id;
    let bob_uid = bob_sess.user_id;
    let charlie_uid = charlie_sess.user_id;

    let alice_agent: Arc<LockNetAgent> = alice_client.get_agent().expect("alice agent");
    let bob_agent: Arc<LockNetAgent> = bob_client.get_agent().expect("bob agent");
    let charlie_agent: Arc<LockNetAgent> = charlie_client.get_agent().expect("charlie agent");
    let alice_low = alice_agent.low();
    let bob_low = bob_agent.low();
    let charlie_low = charlie_agent.low();

    // --- Setup cross-signing for all ---
    alice_agent
        .security()
        .setup_cross_signing()
        .await
        .expect("alice cs");
    bob_agent
        .security()
        .setup_cross_signing()
        .await
        .expect("bob cs");
    charlie_agent
        .security()
        .setup_cross_signing()
        .await
        .expect("charlie cs");

    // --- 2. Alice signs Bob's and Charlie's MSKs ---
    sign_msk(&alice_low, bob_uid).await.expect("sign bob");
    sign_msk(&alice_low, charlie_uid)
        .await
        .expect("sign charlie");

    // Populate alice's `state.users` so the trust-graph builder includes
    // bob and charlie as candidates on the very first check. Without this,
    // the first `is_user_verified(bob_uid)` caches `{alice, bob}` and the
    // subsequent charlie check sees a stale cache. In production this
    // happens naturally as events about these users arrive; the test
    // populates it explicitly.
    alice_agent
        .user_info(bob_uid)
        .await
        .expect("alice knows bob");
    alice_agent
        .user_info(charlie_uid)
        .await
        .expect("alice knows charlie");
    alice_agent.security().invalidate_trust_cache().await;

    // Sanity: WoT reaches both before reset.
    assert!(
        alice_agent.security().is_user_verified(bob_uid).await,
        "alice trusts bob (direct USK → MSK edge)"
    );
    assert!(
        alice_agent.security().is_user_verified(charlie_uid).await,
        "alice trusts charlie"
    );

    // --- 3. Alice creates a private group with Bob and Charlie ---
    let group = alice_agent
        .create_group("TCReset", false, None, vec![bob_uid, charlie_uid])
        .await
        .expect("create");
    let chat_id = group.id();

    let bob_inv = bob_agent
        .invites()
        .await
        .expect("bob inv")
        .into_iter()
        .find(|i| i.group.id == chat_id)
        .expect("bob invite");
    bob_agent
        .accept_invite(bob_inv.id)
        .await
        .expect("bob accept");

    let charlie_inv = charlie_agent
        .invites()
        .await
        .expect("charlie inv")
        .into_iter()
        .find(|i| i.group.id == chat_id)
        .expect("charlie invite");
    charlie_agent
        .accept_invite(charlie_inv.id)
        .await
        .expect("charlie accept");

    // --- 4. Alice sends m1: Bob and Charlie both get s1 ---
    let alice_chat = alice_agent.chat(chat_id).await.expect("alice chat");
    let mut bob_key_rx = bob_agent.subscribe();
    let mut charlie_key_rx = charlie_agent.subscribe();

    let m1 = alice_chat.send("m1 pre-reset").await.expect("send m1");
    let s1 = m1
        .encrypted_payload
        .as_ref()
        .expect("m1 payload")
        .megolm_session_id
        .clone();

    let bob_s1 = wait_key_imported(&mut bob_key_rx, chat_id, Duration::from_secs(10))
        .await
        .expect("bob gets s1");
    let charlie_s1 = wait_key_imported(&mut charlie_key_rx, chat_id, Duration::from_secs(10))
        .await
        .expect("charlie gets s1");
    assert_eq!(bob_s1, s1);
    assert_eq!(charlie_s1, s1);

    // Bob and Charlie can decrypt m1.
    let bob_chat = bob_agent.chat(chat_id).await.expect("bob chat");
    let bob_history = bob_chat.messages(None, 20).await.expect("bob msgs");
    assert_eq!(
        bob_history
            .iter()
            .find(|m| m.id == m1.id)
            .and_then(|m| m.text.as_deref()),
        Some("m1 pre-reset")
    );

    // --- 5. Bob resets cross-signing ---
    let mut alice_rx = alice_agent.subscribe();
    bob_agent
        .security()
        .reset_cross_signing(&bob_pw)
        .await
        .expect("bob reset");

    // Wait for Alice to process the reset event (which triggers rotation +
    // fan-out internally, before `event_tx.send`).
    let _ = wait_high(
        &mut alice_rx,
        |e| matches!(e, HighEvent::CrossSigningReset { user_id } if *user_id == bob_uid),
    )
    .await;

    // --- 6. After reset: Alice no longer trusts Bob ---
    assert!(
        !alice_agent.security().is_user_verified(bob_uid).await,
        "alice must not trust bob after reset"
    );
    assert!(
        !alice_agent
            .security()
            .is_session_verified(bob_uid, bob_sess.session_id)
            .await,
        "alice must not consider bob's session verified after reset"
    );
    assert!(
        alice_agent.security().is_user_verified(charlie_uid).await,
        "charlie unaffected by bob's reset"
    );

    // --- 7. Alice sends m2; server-side megolm already rotated by process_event ---
    let mut bob_rx = bob_agent.subscribe();
    let mut charlie_rx = charlie_agent.subscribe();

    let alice_chat2 = alice_agent.chat(chat_id).await.expect("alice chat 2");
    let m2 = alice_chat2.send("m2 post-reset").await.expect("send m2");
    let s2 = m2
        .encrypted_payload
        .as_ref()
        .expect("m2 payload")
        .megolm_session_id
        .clone();

    assert_ne!(s1, s2, "megolm must rotate after cross-signing reset");

    // Charlie gets s2.
    let charlie_s2 = wait_key_imported(&mut charlie_rx, chat_id, Duration::from_secs(10))
        .await
        .expect("charlie gets s2");
    assert_eq!(charlie_s2, s2);

    // Bob must NOT get s2.
    let bob_got_new_key = wait_key_imported(&mut bob_rx, chat_id, Duration::from_secs(2)).await;
    assert!(
        bob_got_new_key.is_none(),
        "bob must NOT receive the new megolm session after cross-signing reset; got {bob_got_new_key:?}"
    );

    // --- 8. Bob's store: only s1, no s2 ---
    let bob_sessions: Vec<String> = bob_low
        .store()
        .megolm_inbound_all()
        .await
        .into_iter()
        .filter(|(cid, _)| *cid == chat_id)
        .map(|(_, sid)| sid)
        .collect();
    assert_eq!(
        bob_sessions,
        vec![s1.clone()],
        "bob has only the pre-reset session"
    );

    // Charlie's store: both s1 and s2.
    let charlie_sessions: Vec<String> = charlie_low
        .store()
        .megolm_inbound_all()
        .await
        .into_iter()
        .filter(|(cid, _)| *cid == chat_id)
        .map(|(_, sid)| sid)
        .collect();
    assert!(
        charlie_sessions.contains(&s1) && charlie_sessions.contains(&s2),
        "charlie has both sessions: {charlie_sessions:?}"
    );

    // --- 9. Decryption: Bob cannot read m2, Charlie can ---
    let bob_has_s2 = bob_low.store().megolm_inbound(chat_id, &s2).await.is_some();
    assert!(!bob_has_s2, "bob store has no s2");

    let bob_m2_pt = bob_low
        .megolm()
        .decrypt(chat_id, m2.encrypted_payload.as_ref().expect("m2 payload"))
        .await
        .expect("decrypt call");
    assert!(
        bob_m2_pt.is_none(),
        "bob must NOT decrypt m2 (no s2), got {bob_m2_pt:?}"
    );

    let charlie_m2_pt = charlie_low
        .megolm()
        .decrypt(chat_id, m2.encrypted_payload.as_ref().expect("m2 payload"))
        .await
        .expect("decrypt call")
        .expect("charlie has s2");
    assert_eq!(charlie_m2_pt, "m2 post-reset");

    // --- Cleanup ---
    alice_client.disconnect().await.ok();
    bob_client.disconnect().await.ok();
    charlie_client.disconnect().await.ok();
    let _ = alice_user;
}
