//! SQLCipher-backed [`CryptoStore`] implementation.
//!
//! Stores Olm account, Olm sessions, Megolm sessions, cross-signing keys,
//! group policy blobs, and rotation metadata in a single encrypted SQLite
//! database. Schema is versioned via `PRAGMA user_version`.

use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OnceCell};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
};
use vodozemac::olm::{Account as OlmAccount, AccountPickle, Session as OlmSession, SessionPickle};
use vodozemac::Ed25519Keypair;

use crate::core::crypto::signature::CrossSigningKeysPrivate;
use crate::core::crypto::store::{CryptoStore, MAX_OLM_SESSIONS_PER_PEER};
use crate::core::crypto::{Account, OlmSessionEntry};
use crate::core::errors::{LockNetError, Result};
use crate::core::policies::{GroupData, GroupDataState, MegolmOutboundMeta};

const SCHEMA_VERSION: i64 = 2;

/// Persistent [`CryptoStore`] backed by SQLCipher.
///
/// The database file is encrypted with the `passphrase` supplied at open
/// time. The passphrase is **not** stored by this type; obtaining and
/// protecting it (Keychain, KWallet, Credential Manager, TPM, prompt, etc.)
/// is the caller's responsibility.
///
/// # Persistence guarantees
///
/// Mutations to the [`Account`] (returned by [`CryptoStore::account`]) and to
/// [`OlmSessionEntry`] entries (returned by [`CryptoStore::olm_sessions`]) are
/// **not** flushed automatically. Call [`CryptoStore::save_account`] and
/// [`CryptoStore::olm_persist`] after mutating. [`CryptoStore::save_account`]
/// is also invoked on `Drop`, best-effort.
///
/// # Examples
///
/// ```rust,no_run
/// use locknet_rcab::SqliteStore;
///
/// let store = SqliteStore::open("./locknet.db", "my-secret-passphrase")
///     .expect("open store");
/// ```
pub struct SqliteStore {
    conn: Arc<StdMutex<Connection>>,
    account_cache: OnceCell<Arc<Mutex<Account>>>,
}

impl SqliteStore {
    /// Open or create an encrypted database at `path`.
    ///
    /// Runs schema migrations if needed.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if the passphrase is wrong
    ///   (SQLCipher fails to decrypt the header).
    /// - [`LockNetError::InvalidResponse`] if the file cannot be opened, or
    ///   if SQLCipher is not available in the linked SQLite build.
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| LockNetError::InvalidResponse(format!("sqlite open: {e}")))?;
        Self::configure(&conn, passphrase)?;
        Ok(Self {
            conn: Arc::new(StdMutex::new(conn)),
            account_cache: OnceCell::new(),
        })
    }

    /// Open an in-memory encrypted database. Intended for tests and
    /// short-lived clients.
    ///
    /// # Errors
    ///
    /// Same as [`SqliteStore::open`].
    pub fn open_in_memory(passphrase: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| LockNetError::InvalidResponse(format!("sqlite open_in_memory: {e}")))?;
        Self::configure(&conn, passphrase)?;
        Ok(Self {
            conn: Arc::new(StdMutex::new(conn)),
            account_cache: OnceCell::new(),
        })
    }

    fn configure(conn: &Connection, passphrase: &str) -> Result<()> {
        conn.pragma_update(None, "key", passphrase)
            .map_err(|e| LockNetError::InvalidResponse(format!("sqlcipher key: {e}")))?;

        let cipher_version: Option<String> = conn
            .pragma_query_value(None, "cipher_version", |r| r.get(0))
            .optional()
            .ok()
            .flatten();
        if cipher_version.unwrap_or_default().is_empty() {
            return Err(LockNetError::InvalidResponse(
                "sqlcipher not available (cipher_version empty)".into(),
            ));
        }

        conn.execute_batch("SELECT count(*) FROM sqlite_master;")
            .map_err(|e| LockNetError::InvalidArgument(format!("wrong passphrase: {e}")))?;

        Self::migrate(conn)?;
        Ok(())
    }

    fn migrate(conn: &Connection) -> Result<()> {
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|e| LockNetError::InvalidResponse(format!("user_version: {e}")))?;

        if v < 1 {
            conn.execute_batch(
                r#"
                CREATE TABLE account (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    pickle BLOB NOT NULL
                );
                CREATE TABLE olm_sessions (
                    peer_session_id INTEGER NOT NULL,
                    session_index INTEGER NOT NULL,
                    pickle BLOB NOT NULL,
                    their_curve TEXT NOT NULL,
                    PRIMARY KEY (peer_session_id, session_index)
                );
                CREATE TABLE megolm_outbound (
                    chat_id INTEGER PRIMARY KEY,
                    pickle BLOB NOT NULL,
                    session_key TEXT NOT NULL
                );
                CREATE TABLE megolm_inbound (
                    chat_id INTEGER NOT NULL,
                    megolm_session_id TEXT NOT NULL,
                    pickle BLOB NOT NULL,
                    PRIMARY KEY (chat_id, megolm_session_id)
                );
                CREATE TABLE cross_signing_keys (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    pickle BLOB NOT NULL
                );
                CREATE TABLE group_data_state (
                    chat_id INTEGER PRIMARY KEY,
                    key BLOB NOT NULL,
                    data_json TEXT NOT NULL,
                    blob TEXT NOT NULL
                );
                "#,
            )
            .map_err(|e| LockNetError::InvalidResponse(format!("create schema: {e}")))?;

            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(|e| LockNetError::InvalidResponse(format!("set user_version: {e}")))?;
        }

        if v < 2 {
            conn.execute_batch(
                r#"
                CREATE TABLE megolm_outbound_meta (
                    chat_id INTEGER PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    messages_sent INTEGER NOT NULL
                );
                "#,
            )
            .map_err(|e| LockNetError::InvalidResponse(format!("create v2 schema: {e}")))?;

            conn.pragma_update(None, "user_version", 2)
                .map_err(|e| LockNetError::InvalidResponse(format!("set user_version 2: {e}")))?;
        }

        Ok(())
    }

    /// Explicitly flush the cached Olm account to the database.
    ///
    /// Equivalent to [`CryptoStore::save_account`]; provided as a
    /// convenience method.
    pub async fn flush(&self) {
        self.save_account().await;
    }

    fn write_account(&self, acc: &Account) {
        let pickle = acc.inner().pickle();
        let pickle_bytes = match serde_json::to_vec(&pickle) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(?e, "failed to serialize account pickle, skipping save");
                return;
            }
        };
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO account (id, pickle) VALUES (1, ?1)",
                params![pickle_bytes],
            );
        }
    }
}

impl Drop for SqliteStore {
    fn drop(&mut self) {
        if let Some(acc_arc) = self.account_cache.get() {
            if let Ok(acc) = acc_arc.try_lock() {
                self.write_account(&acc);
            } else {
                tracing::warn!(
                    "SqliteStore dropped while account was locked; \
                     call flush() before drop to guarantee persistence"
                );
            }
        }
    }
}

// ---- vodozemac pickle helpers ----

fn olm_account_from_pickle_bytes(bytes: &[u8]) -> Option<OlmAccount> {
    let pickle: AccountPickle = serde_json::from_slice(bytes).ok()?;
    Some(OlmAccount::from_pickle(pickle))
}

fn olm_session_from_pickle_bytes(bytes: &[u8]) -> Option<OlmSession> {
    let pickle: SessionPickle = serde_json::from_slice(bytes).ok()?;
    Some(OlmSession::from_pickle(pickle))
}

fn group_session_from_pickle_bytes(bytes: &[u8]) -> Option<GroupSession> {
    let pickle: GroupSessionPickle = serde_json::from_slice(bytes).ok()?;
    Some(GroupSession::from_pickle(pickle))
}

fn inbound_group_session_from_pickle_bytes(bytes: &[u8]) -> Option<InboundGroupSession> {
    let pickle: InboundGroupSessionPickle = serde_json::from_slice(bytes).ok()?;
    Some(InboundGroupSession::from_pickle(pickle))
}

/// Serializable container for the three cross-signing private keys.
#[derive(Serialize, Deserialize)]
struct CrossSigningPickle {
    msk: Ed25519Keypair,
    ssk: Ed25519Keypair,
    usk: Ed25519Keypair,
}

#[async_trait]
impl CryptoStore for SqliteStore {
    async fn account(&self) -> Arc<Mutex<Account>> {
        self.account_cache
            .get_or_init(|| async {
                let pickle_bytes: Option<Vec<u8>> = {
                    // Recover from a poisoned mutex — another thread panicked
                    // while holding it. The connection itself is still valid;
                    // the poison flag is just a signal.
                    let conn = match self.conn.lock() {
                        Ok(g) => g,
                        Err(poisoned) => {
                            tracing::error!(
                                "conn mutex was poisoned, recovering (data may be inconsistent)"
                            );
                            poisoned.into_inner()
                        }
                    };

                    match conn
                        .query_row("SELECT pickle FROM account WHERE id = 1", [], |r| r.get(0))
                        .optional()
                    {
                        Ok(v) => v,
                        Err(e) => {
                            // I/O error, DB corruption, etc. Treat as
                            // "no account"; the caller will see empty logs
                            // and can recreate by re-running setup.
                            tracing::error!(?e, "failed to read account pickle from DB");
                            None
                        }
                    }
                };

                let acc = match pickle_bytes {
                    Some(bytes) => match olm_account_from_pickle_bytes(&bytes) {
                        Some(inner) => Account::from_inner(inner),
                        None => {
                            tracing::error!(
                                "corrupted account pickle in DB, using empty account \
                                 (identity keys will change — you will need to re-run \
                                 setup_cross_signing and re-upload device keys)"
                            );
                            Account::new()
                        }
                    },
                    None => Account::new(),
                };

                Arc::new(Mutex::new(acc))
            })
            .await
            .clone()
    }

    async fn save_account(&self) {
        if let Some(acc_arc) = self.account_cache.get() {
            let acc = acc_arc.lock().await;
            self.write_account(&acc);
        }
    }

    // ---- Olm sessions ----

    async fn olm_sessions(&self, peer_session_id: i64) -> Vec<OlmSessionEntry> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn.prepare(
            "SELECT pickle, their_curve FROM olm_sessions \
             WHERE peer_session_id = ?1 ORDER BY session_index ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([peer_session_id], |r| {
            let pickle: Vec<u8> = r.get(0)?;
            let their_curve: String = r.get(1)?;
            Ok((pickle, their_curve))
        }) {
            Ok(rs) => rs,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();
        for row in rows.flatten() {
            let (pickle_bytes, their_curve) = row;
            if let Some(session) = olm_session_from_pickle_bytes(&pickle_bytes) {
                result.push(OlmSessionEntry {
                    session: Arc::new(Mutex::new(session)),
                    their_curve25519: their_curve,
                });
            }
        }
        result
    }

    async fn olm_add(&self, peer_session_id: i64, entry: OlmSessionEntry) {
        let (pickle_bytes, their_curve) = {
            let s = entry.session.lock().await;
            let pickle = s.pickle();
            match serde_json::to_vec(&pickle) {
                Ok(bytes) => (bytes, entry.their_curve25519.clone()),
                Err(e) => {
                    tracing::error!(?e, "failed to serialize olm session, skipping save");
                    return;
                }
            }
        };

        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return,
        };

        let next_idx: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(session_index), -1) + 1 FROM olm_sessions WHERE peer_session_id = ?1",
                [peer_session_id],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let _ = conn.execute(
            "INSERT OR REPLACE INTO olm_sessions \
             (peer_session_id, session_index, pickle, their_curve) VALUES (?1, ?2, ?3, ?4)",
            params![peer_session_id, next_idx, pickle_bytes, their_curve],
        );

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM olm_sessions WHERE peer_session_id = ?1",
                [peer_session_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let excess = (count - MAX_OLM_SESSIONS_PER_PEER as i64).max(0);
        if excess > 0 {
            let _ = conn.execute(
                "DELETE FROM olm_sessions WHERE rowid IN (\
                    SELECT rowid FROM olm_sessions \
                    WHERE peer_session_id = ?1 ORDER BY session_index ASC LIMIT ?2\
                )",
                params![peer_session_id, excess],
            );
        }
    }

    async fn olm_remove_all(&self, peer_session_id: i64) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "DELETE FROM olm_sessions WHERE peer_session_id = ?1",
                [peer_session_id],
            );
        }
    }

    // ---- Megolm outbound ----

    async fn megolm_outbound(&self, chat_id: i64) -> Option<Arc<Mutex<GroupSession>>> {
        let conn = self.conn.lock().ok()?;
        let pickle_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT pickle FROM megolm_outbound WHERE chat_id = ?1",
                [chat_id],
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        let bytes = pickle_bytes?;
        let session = group_session_from_pickle_bytes(&bytes)?;
        Some(Arc::new(Mutex::new(session)))
    }

    async fn megolm_outbound_key(&self, chat_id: i64) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        conn.query_row(
            "SELECT session_key FROM megolm_outbound WHERE chat_id = ?1",
            [chat_id],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    async fn megolm_outbound_put(
        &self,
        chat_id: i64,
        session: Arc<Mutex<GroupSession>>,
        key: String,
    ) {
        let pickle_bytes = {
            let s = session.lock().await;
            let pickle = s.pickle();
            match serde_json::to_vec(&pickle) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(?e, "failed to serialize group session, skipping save");
                    return;
                }
            }
        };
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO megolm_outbound (chat_id, pickle, session_key) \
                 VALUES (?1, ?2, ?3)",
                params![chat_id, pickle_bytes, key],
            );
        }
    }

    // ---- Megolm inbound ----

    async fn megolm_inbound(
        &self,
        chat_id: i64,
        megolm_session_id: &str,
    ) -> Option<Arc<Mutex<InboundGroupSession>>> {
        let conn = self.conn.lock().ok()?;
        let pickle_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT pickle FROM megolm_inbound \
                 WHERE chat_id = ?1 AND megolm_session_id = ?2",
                params![chat_id, megolm_session_id],
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        let bytes = pickle_bytes?;
        let session = inbound_group_session_from_pickle_bytes(&bytes)?;
        Some(Arc::new(Mutex::new(session)))
    }

    async fn megolm_inbound_put(
        &self,
        chat_id: i64,
        megolm_session_id: String,
        session: Arc<Mutex<InboundGroupSession>>,
    ) {
        let pickle_bytes = {
            let s = session.lock().await;
            let pickle = s.pickle();
            match serde_json::to_vec(&pickle) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(
                        ?e,
                        "failed to serialize inbound group session, skipping save"
                    );
                    return;
                }
            }
        };
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO megolm_inbound \
                 (chat_id, megolm_session_id, pickle) VALUES (?1, ?2, ?3)",
                params![chat_id, megolm_session_id, pickle_bytes],
            );
        }
    }

    async fn megolm_inbound_all(&self) -> Vec<(i64, String)> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match conn.prepare("SELECT chat_id, megolm_session_id FROM megolm_inbound") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    // ---- Cross-signing keys ----

    async fn cross_signing_keys(&self) -> Option<Arc<CrossSigningKeysPrivate>> {
        let conn = self.conn.lock().ok()?;
        let pickle_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT pickle FROM cross_signing_keys WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .ok()?;
        let bytes = pickle_bytes?;
        let pickle: CrossSigningPickle = serde_json::from_slice(&bytes).ok()?;
        Some(Arc::new(CrossSigningKeysPrivate {
            msk: Arc::new(pickle.msk),
            ssk: Arc::new(pickle.ssk),
            usk: Arc::new(pickle.usk),
        }))
    }

    async fn cross_signing_keys_put(&self, keys: Arc<CrossSigningKeysPrivate>) {
        let pickle = CrossSigningPickle {
            msk: (*keys.msk).clone(),
            ssk: (*keys.ssk).clone(),
            usk: (*keys.usk).clone(),
        };
        let bytes = match serde_json::to_vec(&pickle) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    ?e,
                    "failed to serialize cross-signing pickle, skipping save"
                );
                return;
            }
        };
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO cross_signing_keys (id, pickle) VALUES (1, ?1)",
                params![bytes],
            );
        }
    }

    async fn cross_signing_keys_clear(&self) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("DELETE FROM cross_signing_keys WHERE id = 1", []);
        }
    }

    // ---- Group policy state ----

    async fn group_data_state(&self, chat_id: i64) -> Option<GroupDataState> {
        let conn = self.conn.lock().ok()?;
        let row: Option<(Vec<u8>, String, String)> = conn
            .query_row(
                "SELECT key, data_json, blob FROM group_data_state WHERE chat_id = ?1",
                [chat_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()?;
        let (key_bytes, data_json, blob) = row?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let data: GroupData = serde_json::from_str(&data_json).ok()?;
        Some(GroupDataState { key, data, blob })
    }

    async fn group_data_state_put(&self, chat_id: i64, state: GroupDataState) {
        let data_json = match serde_json::to_string(&state.data) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, "failed to serialize group data, skipping save");
                return;
            }
        };
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO group_data_state \
                 (chat_id, key, data_json, blob) VALUES (?1, ?2, ?3, ?4)",
                params![chat_id, state.key.as_slice(), data_json, state.blob],
            );
        }
    }

    async fn group_data_state_remove(&self, chat_id: i64) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute("DELETE FROM group_data_state WHERE chat_id = ?1", [chat_id]);
        }
    }

    async fn megolm_outbound_meta(&self, chat_id: i64) -> Option<MegolmOutboundMeta> {
        let conn = self.conn.lock().ok()?;
        let row: Option<(String, String, i64)> = conn
            .query_row(
                "SELECT session_id, created_at, messages_sent \
                 FROM megolm_outbound_meta WHERE chat_id = ?1",
                [chat_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()?;
        let (session_id, created_at_str, messages_sent) = row?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .ok()?
            .with_timezone(&chrono::Utc);
        Some(MegolmOutboundMeta {
            session_id,
            created_at,
            messages_sent: messages_sent as u64,
        })
    }

    async fn megolm_outbound_meta_put(&self, chat_id: i64, meta: MegolmOutboundMeta) {
        let created_at = meta.created_at.to_rfc3339();
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO megolm_outbound_meta \
                 (chat_id, session_id, created_at, messages_sent) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    chat_id,
                    meta.session_id,
                    created_at,
                    meta.messages_sent as i64
                ],
            );
        }
    }

    async fn megolm_outbound_meta_remove(&self, chat_id: i64) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "DELETE FROM megolm_outbound_meta WHERE chat_id = ?1",
                [chat_id],
            );
        }
    }

    async fn olm_persist(&self, peer_session_id: i64, entries: &[OlmSessionEntry]) {
        // Prepare pickles without holding the conn lock across `.await`.
        let mut prepared: Vec<(i64, Vec<u8>, String)> = Vec::with_capacity(entries.len());
        for (idx, entry) in entries.iter().enumerate() {
            let s = entry.session.lock().await;
            let pickle = s.pickle();
            let bytes = match serde_json::to_vec(&pickle) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(?e, "failed to serialize olm session, skipping save");
                    return;
                }
            };
            prepared.push((idx as i64, bytes, entry.their_curve25519.clone()));
        }

        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = conn.execute(
            "DELETE FROM olm_sessions WHERE peer_session_id = ?1",
            [peer_session_id],
        );
        for (idx, bytes, curve) in prepared {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO olm_sessions \
                 (peer_session_id, session_index, pickle, their_curve) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![peer_session_id, idx, bytes, curve],
            );
        }
    }
}
