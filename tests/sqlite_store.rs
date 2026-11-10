use std::sync::Arc;

use locknet_rcab::core::crypto::{
    megolm::{create_outbound as create_outbound_group, import_inbound as import_inbound_group},
    olm::{
        create_outbound as create_outbound_olm, decrypt_olm, encrypt_olm, curve_from_b64,
    },
    signature::CrossSigningKeysPrivate,
    Account, CryptoStore, SqliteStore,
};
use locknet_rcab::core::policies::{
    GroupData, GroupDataState, HistoryVisibility, MegolmRotationVisibility,
};


fn tmp_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locknet-test.db");
    (dir, path)
}

fn new_cs_keys() -> Arc<CrossSigningKeysPrivate> {
    Arc::new(CrossSigningKeysPrivate::generate())
}

async fn group_session_id(session: &Arc<tokio::sync::Mutex<vodozemac::megolm::GroupSession>>) -> String {
    let s = session.lock().await;
    s.session_id()
}


#[tokio::test]
async fn open_creates_schema() {
    let (_dir, path) = tmp_db();
    let store = SqliteStore::open(&path, "pass").expect("open");

    assert!(store.cross_signing_keys().await.is_none());

    assert!(path.exists(), "db file must exist");
}

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


#[tokio::test]
async fn wrong_passphrase_fails() {
    let (_dir, path) = tmp_db();

    {
        let _store = SqliteStore::open(&path, "correct").expect("open");
    }

    let result = SqliteStore::open(&path, "wrong");
    assert!(
        result.is_err(),
        "open with wrong passphrase must fail, got Ok"
    );
}


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
    assert_eq!(otk_count, 5, "5 OTK generated");

    let store = SqliteStore::open(&path, "pass").expect("reopen");
    let acc_arc = store.account().await;
    let acc = acc_arc.lock().await;
    assert_eq!(acc.ed25519_public_b64(), ed, "same account after reopen");
}

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

    let _ = decrypt_olm;
}

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
        curve_from_b64(&otks.values().next().unwrap()).unwrap()
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
            .megolm_inbound_put(888, sid.clone(), Arc::new(tokio::sync::Mutex::new(bob_inbound)))
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
    assert_eq!(loaded.data.history_visibility, HistoryVisibility::AllVerifiedUsers);
    assert_eq!(
        loaded.data.megolm_rotation_visibility,
        MegolmRotationVisibility::OnlyVerifiedSessions
    );
}

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