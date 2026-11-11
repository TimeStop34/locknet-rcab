//! Key backup — wire protocol and real crypto.
//!
//! Covers two layers:
//!
//! **Wire-level** (`LockNetBackupHelper` methods without crypto):
//! - `versions()` / `new_version()` / `put()` / `get()` / `delete()`.
//! - Item overwrite semantics, missing version errors, isolation between
//!   users.
//!
//! **Crypto-level** (`export()` / `import()`):
//! - `RecoveryKey` → `backup_secret` via HKDF-SHA256 (info =
//!   `LOCKNET_ENCRYPTION_BACKUP_V1`).
//! - `auth_data.public_key` = `b64(sha256(backup_secret))`.
//! - Item encryption: XSalsa20-Poly1305 (`crypto_secretbox`), compatible
//!   with libsodium `SecretBox`.
//! - Item id format: `"<chat_id>:<megolm_session_id>"`.
//! - Import rejects mismatched `recovery_key` (auth_data check runs before
//!   decryption).
//! - Sessions recovered into a fresh device's store can decrypt historical
//!   messages.
//!
//! Requirements:
//!
//! - `setup_full()` for at least Alice (exports need cross-signing to be
//!   available; import on the new device also expects cross-signing to have
//!   been set up previously, or the test exercises only the session
//!   recovery path).
//! - A Megolm session must exist in Alice's store before `export()`; the
//!   simplest way is `megolm().create(group_id)` followed by `encrypt`.
//!
//! Not covered here: high-level flow via `SecurityHelper::backup_*`
//! (`tests/high_backup.rs`), server-side rate limits, cross-device recovery
//! via `key_request` (see `tests/high_key_request.rs`).

mod common;

use std::collections::HashMap;

use serde_json::json;

use locknet_rcab::api::low::helpers::backup::RecoveryKey;
use locknet_rcab::core::crypto::signature::{sign_b64, CrossSigningKeysPrivate};
use locknet_rcab::models::{CrossSigningKey, CrossSigningKeys, DeviceKeys, Signatures};
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

async fn setup_full(user: &common::TestUser) -> CrossSigningKeysPrivate {
    let low = user.low();
    let uid = user.session.user_id;
    let sid = user.session.session_id;

    let keys = CrossSigningKeysPrivate::generate();
    low.crypto()
        .upload_cross_signing_keys(build_cs_payload(uid, &keys))
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
            device_signatures: [(sid, dev_sig)].into_iter().collect(),
        })
        .await
        .expect("upload device signature");

    keys
}

async fn upload_keys_for_low(low: &LockNetLowAgent) {
    let keys = {
        let account = low.store().account().await;
        let mut acc = account.lock().await;
        acc.generate_one_time_keys(50);
        let otks = acc.one_time_keys_b64();
        let keys = DeviceKeys {
            curve25519_key: acc.curve25519_public_b64(),
            ed25519_key: acc.ed25519_public_b64(),
            one_time_keys: otks,
            signatures: HashMap::new(),
        };
        acc.mark_keys_as_published();
        keys
    };
    low.keys().upload(keys).await.expect("upload_keys");
}

// ---- wire-level tests ----

/// A fresh user has no backup versions; `new_version` creates v1 with the
/// given `auth_data`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_empty_then_new_version() {
    let user = common::register_new("bk_new").await;
    let low = user.low();

    let versions = low.backup().versions().await.expect("versions");
    assert!(versions.is_empty(), "new user must have no backup versions");

    let v = low
        .backup()
        .new_version(
            "ln.encryption.backup.v1",
            json!({"public_key": "test_fingerprint"}),
        )
        .await
        .expect("new_version");
    assert!(v >= 1);

    let versions = low.backup().versions().await.expect("versions");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version, v);
    assert_eq!(versions[0].algorithm, "ln.encryption.backup.v1");
    assert_eq!(versions[0].auth_data["public_key"], "test_fingerprint");

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// `put` + `get` round-trip: multiple items are stored and retrieved with
/// the exact blob contents (no transformation on the wire layer).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_put_get_roundtrip() {
    let user = common::register_new("bk_rtt").await;
    let low = user.low();

    let v = low
        .backup()
        .new_version("ln.encryption.backup.v1", json!({"public_key": "x"}))
        .await
        .expect("new_version");

    let mut items = HashMap::new();
    items.insert(
        "chat:123:megolm_a".to_string(),
        json!({"nonce": "AAAA", "ciphertext": "BBBB"}),
    );
    items.insert(
        "chat:456:megolm_b".to_string(),
        json!({"nonce": "CCCC", "ciphertext": "DDDD"}),
    );

    let count = low.backup().put(v, items).await.expect("put");
    assert_eq!(count, 2);

    let data = low.backup().get(v).await.expect("get");
    assert_eq!(data.version, v);
    assert_eq!(data.algorithm, "ln.encryption.backup.v1");
    assert_eq!(data.items.len(), 2);
    assert_eq!(data.items["chat:123:megolm_a"]["nonce"], "AAAA");
    assert_eq!(data.items["chat:456:megolm_b"]["ciphertext"], "DDDD");

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// `put` with an existing `item_id` overwrites the previous blob (server-side
/// upsert semantics; `count` reflects the number of items in the request,
/// not the number of new items).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_put_overwrites_same_item() {
    let user = common::register_new("bk_ovr").await;
    let low = user.low();

    let v = low
        .backup()
        .new_version("ln.encryption.backup.v1", json!({}))
        .await
        .expect("new_version");

    let mut first = HashMap::new();
    first.insert(
        "chat:1:session".to_string(),
        json!({"nonce": "N1", "ciphertext": "C1"}),
    );
    low.backup().put(v, first).await.expect("put #1");

    let mut second = HashMap::new();
    second.insert(
        "chat:1:session".to_string(),
        json!({"nonce": "N2", "ciphertext": "C2"}),
    );
    let count = low.backup().put(v, second).await.expect("put #2 overwrite");
    assert_eq!(count, 1);

    let data = low.backup().get(v).await.expect("get");
    assert_eq!(data.items.len(), 1);
    assert_eq!(data.items["chat:1:session"]["nonce"], "N2");
    assert_eq!(data.items["chat:1:session"]["ciphertext"], "C2");

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// `put` into an unknown version yields `backup_version_not_found`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_put_missing_version_fails() {
    let user = common::register_new("bk_miss_put").await;
    let low = user.low();

    let mut items = HashMap::new();
    items.insert("k".to_string(), json!({"nonce": "x", "ciphertext": "y"}));

    let err = low.backup().put(9999, items).await.unwrap_err();
    common::assert_server_code(err, "backup_version_not_found");

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// `get` from an unknown version yields `backup_version_not_found`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_get_missing_version_fails() {
    let user = common::register_new("bk_miss_get").await;
    let low = user.low();

    let err = low.backup().get(9999).await.unwrap_err();
    common::assert_server_code(err, "backup_version_not_found");

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// `delete` removes the version and all its items.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_delete_removes_version() {
    let user = common::register_new("bk_del").await;
    let low = user.low();

    let v = low
        .backup()
        .new_version("ln.encryption.backup.v1", json!({}))
        .await
        .expect("new_version");

    let mut items = HashMap::new();
    items.insert("x".to_string(), json!({"nonce": "n", "ciphertext": "c"}));
    low.backup().put(v, items).await.expect("put");

    low.backup().delete(v).await.expect("delete");

    let versions = low.backup().versions().await.expect("versions");
    assert!(versions.iter().all(|x| x.version != v));

    let err = low.backup().get(v).await.unwrap_err();
    common::assert_server_code(err, "backup_version_not_found");

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// Versions increment monotonically and preserve their `auth_data`
/// independently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_multiple_versions_increment() {
    let user = common::register_new("bk_multi").await;
    let low = user.low();

    let v1 = low.backup().new_version("ln.encryption.backup.v1", json!({"n": 1})).await.expect("new #1");
    let v2 = low.backup().new_version("ln.encryption.backup.v1", json!({"n": 2})).await.expect("new #2");
    let v3 = low.backup().new_version("ln.encryption.backup.v1", json!({"n": 3})).await.expect("new #3");

    assert!(v1 < v2 && v2 < v3, "versions must increment: {v1} < {v2} < {v3}");

    let versions = low.backup().versions().await.expect("versions");
    assert_eq!(versions.len(), 3);

    for (i, v) in [v1, v2, v3].iter().enumerate() {
        let data = low.backup().get(*v).await.expect("get");
        assert_eq!(data.auth_data["n"], (i + 1) as i64);
    }

    let mut u = user;
    u.client.disconnect().await.ok();
}

/// Backup is scoped per user: Bob cannot see or read Alice's versions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_isolated_between_users() {
    let alice = common::register_new("bk_iso_a").await;
    let bob = common::register_new("bk_iso_b").await;

    let alice_low = alice.low();
    let bob_low = bob.low();

    let v = alice_low
        .backup()
        .new_version("ln.encryption.backup.v1", json!({"public_key": "alice"}))
        .await
        .expect("alice new");
    let mut items = HashMap::new();
    items.insert("alice_only".to_string(), json!({"nonce": "n", "ciphertext": "c"}));
    alice_low.backup().put(v, items).await.expect("alice put");

    let bob_versions = bob_low.backup().versions().await.expect("bob versions");
    assert!(bob_versions.is_empty());

    let err = bob_low.backup().get(v).await.unwrap_err();
    common::assert_server_code(err, "backup_version_not_found");

    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

// ---- crypto-level tests ----

/// Full export/import round-trip: Alice exports, Alice2 (second session)
/// imports, and decrypts the historical message.
///
/// Verifies:
/// - `export()` produces exactly one item (one Megolm inbound session);
/// - `auth_data.public_key` is present;
/// - `import()` with the same `recovery_key` succeeds;
/// - the imported session decrypts the message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_export_import_roundtrip() {
    let alice = common::register_new("bkrt_a").await;
    let bob = common::register_new("bkrt_b").await;

    let alice_low = alice.low();
    let _bob_low = bob.low();

    setup_full(&alice).await;
    setup_full(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "BkRoundtrip").await;

    let info = alice_low.megolm().create(group_id).await.expect("create");
    let enc = alice_low.megolm().encrypt(group_id, "secret payload").await.unwrap();
    let _ack = alice_low.messages().send(group_id, enc.clone()).await.unwrap();

    let recovery = RecoveryKey::generate();
    let export = alice_low.backup().export(&recovery).await.expect("export");

    assert!(export.version >= 1);
    assert_eq!(export.items_uploaded, 1, "expected exactly one Megolm session");

    let versions = alice_low.backup().versions().await.expect("versions");
    let found = versions.iter().find(|v| v.version == export.version).expect("version");
    assert_eq!(found.algorithm, "ln.encryption.backup.v1");
    assert!(found.auth_data.get("public_key").is_some());

    let mut alice2_client = LockNetClient::new(common::test_config());
    let alice2_session = alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    assert_eq!(alice2_session.user_id, alice.session.user_id);
    let alice2_low = alice2_client.get_low_agent().expect("alice2 low");

    assert!(alice2_low.megolm().decrypt(group_id, &enc).await.unwrap().is_none());

    let import = alice2_low
        .backup()
        .import(export.version, &recovery)
        .await
        .expect("import");
    assert_eq!(import.version, export.version);
    assert_eq!(import.sessions_imported, 1);

    let pt = alice2_low
        .megolm()
        .decrypt(group_id, &enc)
        .await
        .unwrap()
        .expect("decrypt after import");
    assert_eq!(pt, "secret payload");

    let _ = info;
    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Importing with the wrong `recovery_key` fails at the `auth_data.public_key`
/// check, before any ciphertext is decrypted.
///
/// This means a wrong key cannot even be "tried" per item — the failure is
/// surfaced as `InvalidArgument("recovery key does not match ...")`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_wrong_recovery_key_fails() {
    let alice = common::register_new("bkwrk_a").await;
    let bob = common::register_new("bkwrk_b").await;

    let alice_low = alice.low();
    setup_full(&alice).await;
    setup_full(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "BkWrongRK").await;

    alice_low.megolm().create(group_id).await.expect("create");
    let enc = alice_low.megolm().encrypt(group_id, "payload").await.unwrap();
    alice_low.messages().send(group_id, enc).await.unwrap();

    let real_recovery = RecoveryKey::generate();
    let export = alice_low.backup().export(&real_recovery).await.expect("export");

    let mut alice2_client = LockNetClient::new(common::test_config());
    alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    let alice2_low = alice2_client.get_low_agent().expect("alice2 low");

    let wrong_recovery = RecoveryKey::generate();
    let err = alice2_low
        .backup()
        .import(export.version, &wrong_recovery)
        .await
        .unwrap_err();

    match err {
        locknet_rcab::LockNetError::InvalidArgument(msg) => {
            assert!(
                msg.contains("recovery key does not match"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Exporting with an empty store produces `items_uploaded = 0`, and importing
/// that empty version succeeds with `sessions_imported = 0`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_empty_store_exports_zero_items() {
    let alice = common::register_new("bkempty_a").await;
    setup_full(&alice).await;

    let alice_low = alice.low();
    let recovery = RecoveryKey::generate();
    let export = alice_low.backup().export(&recovery).await.expect("export");

    assert!(export.version >= 1);
    assert_eq!(export.items_uploaded, 0, "no Megolm sessions → 0 items");

    let import = alice_low
        .backup()
        .import(export.version, &recovery)
        .await
        .expect("import");
    assert_eq!(import.version, export.version);
    assert_eq!(import.sessions_imported, 0);

    let mut a = alice;
    a.client.disconnect().await.ok();
}

/// Multiple sessions across multiple chats, plus a rotation, produce three
/// items; importing restores all three and decrypts each message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_multi_session() {
    let alice = common::register_new("bkmulti_a").await;
    let bob = common::register_new("bkmulti_b").await;

    let alice_low = alice.low();
    setup_full(&alice).await;
    setup_full(&bob).await;

    let group1 = common::setup_group_with_two(&alice, &bob, "BkMulti1").await;
    let group2 = common::setup_group_with_two(&alice, &bob, "BkMulti2").await;

    let info1 = alice_low.megolm().create(group1).await.expect("create g1");
    let enc1 = alice_low.megolm().encrypt(group1, "g1 msg").await.unwrap();
    alice_low.messages().send(group1, enc1.clone()).await.unwrap();

    let info2 = alice_low.megolm().create(group2).await.expect("create g2");
    let enc2 = alice_low.megolm().encrypt(group2, "g2 msg").await.unwrap();
    alice_low.messages().send(group2, enc2.clone()).await.unwrap();

    let info1b = alice_low.megolm().rotate(group1).await.expect("rotate g1");
    let enc1b = alice_low.megolm().encrypt(group1, "g1 msg2").await.unwrap();
    alice_low.messages().send(group1, enc1b.clone()).await.unwrap();

    let recovery = RecoveryKey::generate();
    let export = alice_low.backup().export(&recovery).await.expect("export");
    assert_eq!(export.items_uploaded, 3, "expected 3 Megolm sessions");

    let mut alice2_client = LockNetClient::new(common::test_config());
    alice2_client
        .connection_request(Credentials::Login {
            username: alice.username.clone(),
            password: alice.password.clone(),
        })
        .await
        .expect("alice2 login");
    let alice2_low = alice2_client.get_low_agent().expect("alice2 low");

    let import = alice2_low
        .backup()
        .import(export.version, &recovery)
        .await
        .expect("import");
    assert_eq!(import.sessions_imported, 3);

    assert_eq!(
        alice2_low.megolm().decrypt(group1, &enc1).await.unwrap().unwrap(),
        "g1 msg"
    );
    assert_eq!(
        alice2_low.megolm().decrypt(group2, &enc2).await.unwrap().unwrap(),
        "g2 msg"
    );
    assert_eq!(
        alice2_low.megolm().decrypt(group1, &enc1b).await.unwrap().unwrap(),
        "g1 msg2"
    );

    let _ = (info1, info2, info1b);
    alice2_client.disconnect().await.ok();
    let mut a = alice;
    let mut b = bob;
    a.client.disconnect().await.ok();
    b.client.disconnect().await.ok();
}

/// Importing an unknown version fails with `backup_version_not_found`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_import_missing_version_fails() {
    let alice = common::register_new("bkmis_a").await;
    setup_full(&alice).await;
    let alice_low = alice.low();

    let recovery = RecoveryKey::generate();
    let _export = alice_low.backup().export(&recovery).await.expect("export");

    let err = alice_low
        .backup()
        .import(9999, &recovery)
        .await
        .unwrap_err();
    common::assert_server_code(err, "backup_version_not_found");

    let mut a = alice;
    a.client.disconnect().await.ok();
}

/// `RecoveryKey` is base64-encoded without padding (32 bytes → 43 chars) and
/// round-trips through `to_base64`/`from_base64`. Wrong-length inputs are
/// rejected with `InvalidArgument`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_recovery_key_serde() {
    let rk = RecoveryKey::generate();
    let b64 = rk.to_base64();
    assert_eq!(b64.len(), 43, "32 bytes without padding = 43 base64 characters");

    let recovered = RecoveryKey::from_base64(&b64).expect("from_base64");
    assert_eq!(rk.as_bytes(), recovered.as_bytes());

    let err = RecoveryKey::from_base64("short").unwrap_err();
    assert!(matches!(err, locknet_rcab::LockNetError::InvalidArgument(_)));

    let err = RecoveryKey::from_base64("AAAA").unwrap_err();
    assert!(matches!(err, locknet_rcab::LockNetError::InvalidArgument(_)));
}

/// Alice's backup restores history on a new device after Alice1 has "gone
/// offline".
///
/// This is the recovery story for a lost device: as long as the user still
/// remembers the `recovery_key`, the new device can decrypt the historical
/// messages without needing any other device to be online.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_recovers_history_for_lost_device() {
    let alice = common::register_new("bkhist_a").await;
    let bob = common::register_new("bkhist_b").await;

    let bob_uid = bob.session.user_id;
    let bob_sid = bob.session.session_id;
    let alice_rjwt = alice.session.rjwt.clone();

    let alice_low = alice.low();
    let bob_low = bob.low();

    setup_full(&alice).await;
    setup_full(&bob).await;

    let group_id = common::setup_group_with_two(&alice, &bob, "BkHist").await;
    let info = alice_low.megolm().create(group_id).await.expect("create");
    let enc = alice_low.megolm().encrypt(group_id, "historical payload").await.unwrap();
    let ack = alice_low.messages().send(group_id, enc.clone()).await.unwrap();

    bob_low
        .megolm()
        .import(group_id, info.megolm_session_id.clone(), info.session_key.clone())
        .await
        .expect("bob import");
    assert_eq!(
        bob_low.megolm().decrypt(group_id, &enc).await.unwrap().unwrap(),
        "historical payload"
    );

    let recovery = RecoveryKey::generate();
    let export = alice_low.backup().export(&recovery).await.expect("export");
    assert_eq!(export.items_uploaded, 1);

    let mut alice1 = alice;
    alice1.client.disconnect().await.ok();

    let mut alice2_client = LockNetClient::new(common::test_config());
    let _alice2_session = alice2_client
        .connection_request(Credentials::Session {
            refresh_jwt: alice_rjwt,
        })
        .await
        .expect("alice2 reconnect");
    let alice2_low = alice2_client.get_low_agent().expect("alice2 low");

    // Session credentials do not trigger upload_keys; do it manually.
    upload_keys_for_low(&alice2_low).await;

    assert!(alice2_low.megolm().decrypt(group_id, &enc).await.unwrap().is_none());

    let import = alice2_low
        .backup()
        .import(export.version, &recovery)
        .await
        .expect("import");
    assert_eq!(import.sessions_imported, 1);

    let pt = alice2_low
        .megolm()
        .decrypt(group_id, &enc)
        .await
        .unwrap()
        .expect("decrypt after recovery");
    assert_eq!(pt, "historical payload");

    let page = alice2_low
        .messages()
        .get(group_id, None, 20)
        .await
        .expect("get");
    assert!(page.messages.iter().any(|m| m.message_id == ack.message_id));

    let _ = (bob_uid, bob_sid);
    alice2_client.disconnect().await.ok();
    let mut b = bob;
    b.client.disconnect().await.ok();
}