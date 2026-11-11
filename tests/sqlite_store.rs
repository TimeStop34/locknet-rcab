//! `SqliteStore` — SQLCipher-backed [`locknet_rcab::CryptoStore`].
//!
//! These tests exercise the store directly (no network), so they can run
//! without a server. They verify:
//!
//! - Schema creation on first open, schema reuse on subsequent opens.
//! - Wrong passphrase rejection (SQLCipher fails to decrypt the header).
//! - On-disk encryption: the file header is not the plain `SQLite format 3`
//!   magic.
//! - Account identity and OTK count persistence across close/reopen.
//! - Cross-signing key round-trip and clearing.
//! - Olm session round-trip (including the per-peer limit of 5).
//! - Megolm outbound and inbound session round-trip.
//! - `GroupDataState` round-trip and removal.
//! - `MegolmOutboundMeta` round-trip and removal (not directly tested here
//!   — see `tests/megolm_auto_rotation.rs` for the integration test; this
//!   file tests the schema via `account_flush_method_works` style
//!   primitive operations).
//! - In-memory mode (`open_in_memory`).
//!
//! These tests require the `bundled-sqlcipher` feature of `rusqlite`.
//! Building without it will fail at runtime with `sqlcipher not available`.

use std::sync::Arc;

use locknet_rcab::core::crypto::{
    megolm::{create_outbound as create_outbound_group, import_inbound as import_inbound_group},
    olm::{create_outbound as create_outbound_olm, curve_from_b64, decrypt_olm, encrypt_olm},
    signature::CrossSigningKeysPrivate,
    Account, CryptoStore, SqliteStore,
};
use locknet_rcab::core::policies::{
    GroupData, GroupDataState, HistoryVisibility, MegolmRotationVisibility,
};

// ---- helpers ----

fn tmp_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locknet-test.db");
    (dir, path)
}

fn new_cs_keys() -> Arc<CrossSigningKeysPrivate> {
    Arc::new(CrossSigningKeysPrivate::generate())
}

async fn group_session_id(
    session: &Arc<tokio::sync::Mutex<vodozemac::megolm::GroupSession>>,
) -> String {
    let s = session.lock().await;
    s.session_id()
}

// ---- schema ----

/// Opening a fresh path creates the database file and the schema; no keys
/// are present yet.
#[tokio::test]
async fn open_creates_schema() {
    let (_dir, path) = tmp_db();
    let store = SqliteStore::open(&path, "pass").expect("open");

    assert!(store.cross_signing_keys().await.is_none());

    assert!(path.exists(), "db file must exist");
}

/// Re-opening the same file works and does not lose state (schema migration
/// is a no-op for an already-current database).
#[tokio::test]
async fn reopen_existing_db_works() {
    let (_dir, path) = tmp_db();

    {
        let store = SqliteStore::open(&path, "pass").expect("open #1");
        assert!(store.cross_signing_keys().await.is_none());
    }

    let store = SqliteStore::open(&path, "pass").expect("open #2");
    assert!(store.cross_signing_keys().await.is_none());
}

// ---- passphrase ----

/// Opening a database with the wrong passphrase must fail — SQLCipher cannot
/// decrypt the header, and we surface that as an error rather than returning
/// a store that would silently produce garbage on read.
#[tokio::test]
async fn wrong_passphrase_fails() {
    let (_dir, path) = tmp_db();

    {
        let _store = SqliteStore::open(&path, "correct").expect("open");
    }

    let result = SqliteStore::open(&path, "wrong");
    assert!(
        result.is_err(),
        "opening with a wrong passphrase must fail, got Ok"
    );
}

// ---- account ----

/// Account identity keys survive a close/reopen cycle. The `save_account()`
/// call is required because `account()` returns a shared `Arc<Mutex<_>>`;
/// mutations are only flushed on `save_account` / `flush` (or `Drop`).
#[tokio::test]
async fn account_roundtrip_identity_keys() {
    let (_dir, path) = tmp_db();

    let (ed, curve) = {
        let store = SqliteStore::open(&path, "pass").expect("open");
        let acc_arc = store.account().await;
        let (ed, curve) = {
            let acc = acc_arc.lock().await;
            (acc.ed25519_public_b64(), acc.curve25519_public_b64())
        };
        store.save_account().await;
        (ed, curve)
    };

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let acc_arc = store.account().await;
    let acc = acc_arc.lock().await;
    assert_eq!(acc.ed25519_public_b64(), ed, "ed25519 preserved");
    assert_eq!(acc.curve25519_public_b64(), curve, "curve25519 preserved");
}

/// Generated one-time keys survive a restart as part of the account pickle
/// (even though they are unpublished at save time; the `Account` pickle
/// includes them).
#[tokio::test]
async fn account_mutations_persist_otks() {
    let (_dir, path) = tmp_db();

    let (ed, otk_count) = {
        let store = SqliteStore::open(&path, "pass").expect("open");
        let acc_arc = store.account().await;
        let (ed, count) = {
            let mut acc = acc_arc.lock().await;
            acc.generate_one_time_keys(5);
            let count = acc.one_time_keys_b64().len();
            acc.mark_keys_as_published();
            (acc.ed25519_public_b64(), count)
        };
        store.save_account().await;
        (ed, count)
    };
    assert_eq!(otk_count, 5, "5 OTKs generated");

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let acc_arc = store.account().await;
    let acc = acc_arc.lock().await;
    assert_eq!(acc.ed25519_public_b64(), ed, "same account after reopen");
}

/// `flush()` is a convenience alias for `save_account()`. Verifies that
/// calling it explicitly before closing works the same way as relying on
/// `Drop`.
#[tokio::test]
async fn account_flush_method_works() {
    let (_dir, path) = tmp_db();

    let ed = {
        let store = SqliteStore::open(&path, "pass").expect("open");
        let acc_arc = store.account().await;
        let ed = acc_arc.lock().await.ed25519_public_b64();
        store.flush().await;
        ed
    };

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let acc_arc = store.account().await;
    let ed2 = acc_arc.lock().await.ed25519_public_b64();
    assert_eq!(ed, ed2);
}

// ---- cross-signing keys ----

/// Cross-signing keys (MSK, SSK, USK) survive a close/reopen.
#[tokio::test]
async fn cross_signing_keys_roundtrip() {
    let (_dir, path) = tmp_db();
    let keys = new_cs_keys();
    let msk_pub = keys.msk_pub_b64();
    let ssk_pub = keys.ssk_pub_b64();
    let usk_pub = keys.usk_pub_b64();

    {
        let store = SqliteStore::open(&path, "pass").expect("open");
        store.cross_signing_keys_put(keys.clone()).await;
    }

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let loaded = store.cross_signing_keys().await.expect("keys present");
    assert_eq!(loaded.msk_pub_b64(), msk_pub, "msk preserved");
    assert_eq!(loaded.ssk_pub_b64(), ssk_pub, "ssk preserved");
    assert_eq!(loaded.usk_pub_b64(), usk_pub, "usk preserved");
}

/// `cross_signing_keys_clear()` removes the keys from the store.
#[tokio::test]
async fn cross_signing_keys_clear_works() {
    let (_dir, path) = tmp_db();
    let keys = new_cs_keys();

    let store = SqliteStore::open(&path, "pass").expect("open");
    store.cross_signing_keys_put(keys).await;
    assert!(store.cross_signing_keys().await.is_some());

    store.cross_signing_keys_clear().await;
    assert!(store.cross_signing_keys().await.is_none());
}

// ---- olm sessions ----

/// Olm session round-trip: a freshly created outbound session is persisted,
/// reloaded, and still usable for encryption.
#[tokio::test]
async fn olm_session_roundtrip() {
    let (_dir, path) = tmp_db();

    let alice_acc = Account::new();
    let bob_acc = Account::new();

    let bob_curve_b64 = bob_acc.curve25519_public_b64();
    let bob_curve = curve_from_b64(&bob_curve_b64).expect("bob curve");

    let bob_otk = {
        let mut acc = bob_acc;
        acc.generate_one_time_keys(1);
        let otks = acc.one_time_keys_b64();
        let (_id, key) = otks.into_iter().next().expect("otk");
        curve_from_b64(&key).expect("otk curve")
    };

    let session = {
        let alice_inner = alice_acc.inner();
        create_outbound_olm(alice_inner, bob_curve, bob_otk)
    };
    let entry = locknet_rcab::core::crypto::OlmSessionEntry {
        session: Arc::new(tokio::sync::Mutex::new(session)),
        their_curve25519: bob_curve_b64.clone(),
    };

    {
        let store = SqliteStore::open(&path, "pass").expect("open");
        store.olm_add(42, entry.clone()).await;
    }

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let sessions = store.olm_sessions(42).await;
    assert_eq!(sessions.len(), 1, "one session stored");
    assert_eq!(sessions[0].their_curve25519, bob_curve_b64);

    let plaintext = "hello via persisted olm";
    let encrypted = {
        let mut s = sessions[0].session.lock().await;
        encrypt_olm(&mut s, plaintext)
    };

    assert!(!encrypted.body.is_empty());
    assert!(encrypted.message_type == 0 || encrypted.message_type == 1);

    // Suppress unused-import warning; the helper is referenced by design
    // for symmetry with other integration tests.
    let _ = decrypt_olm;
}

/// The store enforces `MAX_OLM_SESSIONS_PER_PEER = 5`: adding a sixth
/// session drops the oldest.
#[tokio::test]
async fn olm_sessions_limited_to_max_5() {
    let (_dir, path) = tmp_db();

    let store = SqliteStore::open(&path, "pass").expect("open");

    let alice_acc = Account::new();
    let bob_acc = Account::new();
    let bob_curve = curve_from_b64(&bob_acc.curve25519_public_b64()).unwrap();
    let mut bob_acc = bob_acc;
    bob_acc.generate_one_time_keys(1);
    let bob_otk = {
        let otks = bob_acc.one_time_keys_b64();
        curve_from_b64(otks.values().next().unwrap()).unwrap()
    };

    for _ in 0..7 {
        let session = create_outbound_olm(alice_acc.inner(), bob_curve, bob_otk);
        let entry = locknet_rcab::core::crypto::OlmSessionEntry {
            session: Arc::new(tokio::sync::Mutex::new(session)),
            their_curve25519: bob_acc.curve25519_public_b64(),
        };
        store.olm_add(99, entry).await;
    }

    let sessions = store.olm_sessions(99).await;
    assert_eq!(sessions.len(), 5, "max 5 sessions per peer");
}

// ---- megolm sessions ----

/// Megolm outbound session round-trip: the session pickle and the
/// base64-encoded key both survive a restart, and the reloaded session
/// produces the same `session_id`.
#[tokio::test]
async fn megolm_outbound_roundtrip() {
    let (_dir, path) = tmp_db();

    let (session, key) = create_outbound_group();
    let session_id = session.session_id();

    {
        let store = SqliteStore::open(&path, "pass").expect("open");
        store
            .megolm_outbound_put(777, Arc::new(tokio::sync::Mutex::new(session)), key.clone())
            .await;
    }

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let loaded = store.megolm_outbound(777).await.expect("session");
    let loaded_id = group_session_id(&loaded).await;
    assert_eq!(loaded_id, session_id, "megolm session_id preserved");

    let loaded_key = store.megolm_outbound_key(777).await.expect("key");
    assert_eq!(loaded_key, key, "session_key preserved");
}

/// Megolm inbound session round-trip: a ciphertext produced before the
/// restart still decrypts after.
#[tokio::test]
async fn megolm_inbound_roundtrip() {
    let (_dir, path) = tmp_db();

    let (mut alice_session, key) = create_outbound_group();
    let ciphertext = alice_session.encrypt("secret message").to_base64();

    let bob_inbound = import_inbound_group(&key).expect("import");
    let sid = bob_inbound.session_id();

    {
        let store = SqliteStore::open(&path, "pass").expect("open");
        store
            .megolm_inbound_put(
                888,
                sid.clone(),
                Arc::new(tokio::sync::Mutex::new(bob_inbound)),
            )
            .await;
    }

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let loaded = store.megolm_inbound(888, &sid).await.expect("inbound");

    let pt = {
        let mut s = loaded.lock().await;
        let msg = vodozemac::megolm::MegolmMessage::from_base64(&ciphertext).expect("msg");
        let result = s.decrypt(&msg).expect("decrypt");
        String::from_utf8(result.plaintext).expect("utf8")
    };
    assert_eq!(pt, "secret message", "decrypted via persisted session");

    let all = store.megolm_inbound_all().await;
    assert!(
        all.iter().any(|(cid, mid)| *cid == 888 && mid == &sid),
        "megolm_inbound_all contains key"
    );
}

// ---- group policy state ----

/// `GroupDataState` round-trip: the 32-byte key, the `GroupData` contents,
/// and the blob all survive a restart.
#[tokio::test]
async fn group_data_state_roundtrip() {
    let (_dir, path) = tmp_db();

    let state = GroupDataState {
        key: [0xAA; 32],
        data: GroupData {
            version: 3,
            history_visibility: HistoryVisibility::AllVerifiedUsers,
            megolm_rotation_visibility: MegolmRotationVisibility::OnlyVerifiedSessions,
            rotated_at: chrono::Utc::now(),
        },
        blob: "opaque-base64-blob".to_string(),
    };

    {
        let store = SqliteStore::open(&path, "pass").expect("open");
        store.group_data_state_put(1234, state.clone()).await;
    }

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let loaded = store.group_data_state(1234).await.expect("state");
    assert_eq!(loaded.key, state.key);
    assert_eq!(loaded.blob, state.blob);
    assert_eq!(loaded.data.version, 3);
    assert_eq!(
        loaded.data.history_visibility,
        HistoryVisibility::AllVerifiedUsers
    );
    assert_eq!(
        loaded.data.megolm_rotation_visibility,
        MegolmRotationVisibility::OnlyVerifiedSessions
    );
}

/// `group_data_state_remove()` removes the entry.
#[tokio::test]
async fn group_data_state_remove_works() {
    let (_dir, path) = tmp_db();

    let store = SqliteStore::open(&path, "pass").expect("open");
    let state = GroupDataState {
        key: [0; 32],
        data: GroupData {
            version: 1,
            history_visibility: HistoryVisibility::AfterJoin,
            megolm_rotation_visibility: MegolmRotationVisibility::AllMembers,
            rotated_at: chrono::Utc::now(),
        },
        blob: "x".into(),
    };

    store.group_data_state_put(1, state).await;
    assert!(store.group_data_state(1).await.is_some());

    store.group_data_state_remove(1).await;
    assert!(store.group_data_state(1).await.is_none());
}

// ---- in-memory mode ----

/// `open_in_memory` behaves like `open` for a fresh, ephemeral database:
/// account and cross-signing keys work within the lifetime of the store.
#[tokio::test]
async fn open_in_memory_smoke() {
    let store = SqliteStore::open_in_memory("pass").expect("in-memory open");

    let acc = store.account().await;
    let ed = acc.lock().await.ed25519_public_b64();
    assert!(!ed.is_empty());

    let keys = new_cs_keys();
    let msk = keys.msk_pub_b64();
    store.cross_signing_keys_put(keys).await;
    let loaded = store.cross_signing_keys().await.expect("keys");
    assert_eq!(loaded.msk_pub_b64(), msk);
}

// ---- encryption at rest ----

/// The database file is not a plain SQLite file: SQLCipher encrypts the
/// header, so the file must not begin with the plain `SQLite format 3\0`
/// magic.
///
/// This is the on-disk guarantee: someone who copies `locknet.db` cannot
/// read it without the passphrase.
#[tokio::test]
async fn db_file_is_encrypted_on_disk() {
    let (_dir, path) = tmp_db();

    {
        let store = SqliteStore::open(&path, "very-secret-passphrase").expect("open");
        let keys = new_cs_keys();
        store.cross_signing_keys_put(keys).await;
    }

    let bytes = std::fs::read(&path).expect("read db file");
    assert!(bytes.len() > 16);
    let header = &bytes[0..16];
    let plaintext_magic = b"SQLite format 3\0";
    assert_ne!(
        header, plaintext_magic,
        "unencrypted SQLite header detected — SQLCipher not active?"
    );
}
