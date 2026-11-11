//! Persistent storage abstraction for cryptographic state.
//!
//! All E2EE state (Olm account and sessions, Megolm sessions, cross-signing
//! private keys, group policy blobs, rotation metadata) is owned by a
//! [`CryptoStore`] implementation. [`InMemoryStore`] is provided for tests;
//! [`crate::core::crypto::SqliteStore`] provides persistence across process
//! restarts.
//!
//! The trait is `async` because persistent implementations perform I/O.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use vodozemac::megolm::{GroupSession, InboundGroupSession};

use super::account::Account;
use super::olm::OlmSessionEntry;
use super::signature::CrossSigningKeysPrivate;
use crate::core::policies::{GroupDataState, MegolmOutboundMeta};

/// Maximum number of Olm sessions kept per peer device.
pub(crate) const MAX_OLM_SESSIONS_PER_PEER: usize = 5;

/// Cryptographic state storage.
///
/// # Contract
///
/// - Methods with `_put` / `_add` / `_remove` / `_clear` **write** to the
///   store. Implementations must guarantee that the data is durable by the
///   time the returned future resolves: persistent stores commit, in-memory
///   stores mutate the backing map.
/// - Getter methods return `Option` or an empty collection and never return a
///   silent `None` due to lock contention.
/// - `account()` and `olm_sessions()` return shared `Arc<Mutex<_>>` handles
///   that the caller mutates in place. After mutating, the caller **must**
///   call [`CryptoStore::save_account`] or [`CryptoStore::olm_persist`] to
///   persist the change (no-op for in-memory stores).
#[async_trait]
pub trait CryptoStore: Send + Sync {
    /// The Olm account (identity keys and one-time keys).
    async fn account(&self) -> Arc<Mutex<Account>>;

    /// Established Olm sessions with `peer_session_id`, oldest first.
    async fn olm_sessions(&self, peer_session_id: i64) -> Vec<OlmSessionEntry>;

    /// Append a new Olm session for `peer_session_id`, trimming the oldest
    /// when the per-peer limit (`MAX_OLM_SESSIONS_PER_PEER`) is exceeded.
    async fn olm_add(&self, peer_session_id: i64, entry: OlmSessionEntry);

    /// Remove all Olm sessions for `peer_session_id`.
    async fn olm_remove_all(&self, peer_session_id: i64);

    /// Outbound Megolm session for `chat_id`.
    async fn megolm_outbound(&self, chat_id: i64) -> Option<Arc<Mutex<GroupSession>>>;

    /// Base64-encoded session key of the outbound Megolm session for `chat_id`.
    async fn megolm_outbound_key(&self, chat_id: i64) -> Option<String>;

    /// Insert or replace the outbound Megolm session and its key for `chat_id`.
    async fn megolm_outbound_put(
        &self,
        chat_id: i64,
        session: Arc<Mutex<GroupSession>>,
        key: String,
    );

    /// Inbound Megolm session for `(chat_id, megolm_session_id)`.
    async fn megolm_inbound(
        &self,
        chat_id: i64,
        megolm_session_id: &str,
    ) -> Option<Arc<Mutex<InboundGroupSession>>>;

    /// Insert or replace an inbound Megolm session.
    async fn megolm_inbound_put(
        &self,
        chat_id: i64,
        megolm_session_id: String,
        session: Arc<Mutex<InboundGroupSession>>,
    );

    /// All `(chat_id, megolm_session_id)` pairs known to this store.
    async fn megolm_inbound_all(&self) -> Vec<(i64, String)>;

    /// Private cross-signing keys (MSK, SSK, USK), if generated.
    async fn cross_signing_keys(&self) -> Option<Arc<CrossSigningKeysPrivate>>;

    /// Persist cross-signing private keys.
    async fn cross_signing_keys_put(&self, keys: Arc<CrossSigningKeysPrivate>);

    /// Remove cross-signing private keys (used on reset).
    async fn cross_signing_keys_clear(&self);

    /// Cached policy state for `chat_id`.
    ///
    /// `None` means: not a member yet, or the `group_data_key` has not been
    /// received via `ln.encryption.group_key`.
    async fn group_data_state(&self, chat_id: i64) -> Option<GroupDataState>;

    /// Persist policy state for `chat_id`.
    async fn group_data_state_put(&self, chat_id: i64, state: GroupDataState);

    /// Remove policy state for `chat_id`.
    async fn group_data_state_remove(&self, chat_id: i64);

    /// Auto-rotation metadata for the outbound Megolm session of `chat_id`.
    async fn megolm_outbound_meta(&self, chat_id: i64) -> Option<MegolmOutboundMeta>;

    /// Persist auto-rotation metadata.
    async fn megolm_outbound_meta_put(&self, chat_id: i64, meta: MegolmOutboundMeta);

    /// Remove auto-rotation metadata.
    async fn megolm_outbound_meta_remove(&self, chat_id: i64);

    /// Persist any mutations made to the [`Account`] returned by
    /// [`CryptoStore::account`].
    ///
    /// - [`InMemoryStore`]: no-op (mutations are already visible).
    /// - [`crate::core::crypto::SqliteStore`]: write the pickled account to
    ///   the database.
    ///
    /// Call this after `generate_one_time_keys`, `mark_keys_as_published`,
    /// or `create_inbound_session`.
    async fn save_account(&self) {}

    /// Persist the **current** state of all Olm sessions for a peer.
    ///
    /// Olm session state mutates on every `encrypt`/`decrypt` (ratchet
    /// advance, `has_received_message` flag flip). Because
    /// [`CryptoStore::olm_sessions`] returns *clones* for `SqliteStore`
    /// (freshly deserialized from pickle), mutations are **not** persisted
    /// automatically. Call this after any mutation.
    ///
    /// - [`InMemoryStore`]: no-op (shared `Arc`s already reflect mutations).
    /// - [`crate::core::crypto::SqliteStore`]: delete-by-peer, then insert
    ///   the current pickles.
    async fn olm_persist(&self, peer_session_id: i64, entries: &[OlmSessionEntry]);
}

/// In-memory [`CryptoStore`] for tests and short-lived clients.
///
/// State is lost on process exit. All operations use `tokio::sync::Mutex`, so
/// they are safe to call concurrently.
pub struct InMemoryStore {
    account: Arc<Mutex<Account>>,
    olm_sessions: Arc<Mutex<HashMap<i64, Vec<OlmSessionEntry>>>>,
    megolm_out: Arc<Mutex<HashMap<i64, (Arc<Mutex<GroupSession>>, String)>>>,
    megolm_in: Arc<Mutex<HashMap<(i64, String), Arc<Mutex<InboundGroupSession>>>>>,
    cross_signing: Arc<Mutex<Option<Arc<CrossSigningKeysPrivate>>>>,
    group_data: Arc<Mutex<HashMap<i64, GroupDataState>>>,
    megolm_out_meta: Arc<Mutex<HashMap<i64, MegolmOutboundMeta>>>,
}

impl InMemoryStore {
    /// Create an empty store with a freshly generated Olm account.
    pub fn new() -> Self {
        Self {
            account: Arc::new(Mutex::new(Account::new())),
            olm_sessions: Arc::new(Mutex::new(HashMap::new())),
            megolm_out: Arc::new(Mutex::new(HashMap::new())),
            megolm_in: Arc::new(Mutex::new(HashMap::new())),
            cross_signing: Arc::new(Mutex::new(None)),
            group_data: Arc::new(Mutex::new(HashMap::new())),
            megolm_out_meta: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CryptoStore for InMemoryStore {
    async fn account(&self) -> Arc<Mutex<Account>> {
        self.account.clone()
    }

    async fn olm_sessions(&self, peer_session_id: i64) -> Vec<OlmSessionEntry> {
        self.olm_sessions
            .lock()
            .await
            .get(&peer_session_id)
            .cloned()
            .unwrap_or_default()
    }

    async fn olm_add(&self, peer_session_id: i64, entry: OlmSessionEntry) {
        let mut g = self.olm_sessions.lock().await;
        let list = g.entry(peer_session_id).or_insert_with(Vec::new);
        list.push(entry);
        if list.len() > MAX_OLM_SESSIONS_PER_PEER {
            list.remove(0);
        }
    }

    async fn olm_remove_all(&self, peer_session_id: i64) {
        self.olm_sessions.lock().await.remove(&peer_session_id);
    }

    async fn megolm_outbound(&self, chat_id: i64) -> Option<Arc<Mutex<GroupSession>>> {
        self.megolm_out
            .lock()
            .await
            .get(&chat_id)
            .map(|(s, _)| s.clone())
    }

    async fn megolm_outbound_key(&self, chat_id: i64) -> Option<String> {
        self.megolm_out
            .lock()
            .await
            .get(&chat_id)
            .map(|(_, k)| k.clone())
    }

    async fn megolm_outbound_put(
        &self,
        chat_id: i64,
        session: Arc<Mutex<GroupSession>>,
        key: String,
    ) {
        self.megolm_out.lock().await.insert(chat_id, (session, key));
    }

    async fn megolm_inbound(
        &self,
        chat_id: i64,
        megolm_session_id: &str,
    ) -> Option<Arc<Mutex<InboundGroupSession>>> {
        self.megolm_in
            .lock()
            .await
            .get(&(chat_id, megolm_session_id.to_string()))
            .cloned()
    }

    async fn megolm_inbound_put(
        &self,
        chat_id: i64,
        megolm_session_id: String,
        session: Arc<Mutex<InboundGroupSession>>,
    ) {
        self.megolm_in
            .lock()
            .await
            .insert((chat_id, megolm_session_id), session);
    }

    async fn megolm_inbound_all(&self) -> Vec<(i64, String)> {
        self.megolm_in.lock().await.keys().cloned().collect()
    }

    async fn cross_signing_keys(&self) -> Option<Arc<CrossSigningKeysPrivate>> {
        self.cross_signing.lock().await.clone()
    }

    async fn cross_signing_keys_put(&self, keys: Arc<CrossSigningKeysPrivate>) {
        *self.cross_signing.lock().await = Some(keys);
    }

    async fn cross_signing_keys_clear(&self) {
        *self.cross_signing.lock().await = None;
    }

    async fn group_data_state(&self, chat_id: i64) -> Option<GroupDataState> {
        self.group_data.lock().await.get(&chat_id).cloned()
    }

    async fn group_data_state_put(&self, chat_id: i64, state: GroupDataState) {
        self.group_data.lock().await.insert(chat_id, state);
    }

    async fn group_data_state_remove(&self, chat_id: i64) {
        self.group_data.lock().await.remove(&chat_id);
    }

    async fn megolm_outbound_meta(&self, chat_id: i64) -> Option<MegolmOutboundMeta> {
        self.megolm_out_meta.lock().await.get(&chat_id).cloned()
    }

    async fn megolm_outbound_meta_put(&self, chat_id: i64, meta: MegolmOutboundMeta) {
        self.megolm_out_meta.lock().await.insert(chat_id, meta);
    }

    async fn megolm_outbound_meta_remove(&self, chat_id: i64) {
        self.megolm_out_meta.lock().await.remove(&chat_id);
    }

    async fn olm_persist(&self, _peer_session_id: i64, _entries: &[OlmSessionEntry]) {
        // no-op: InMemoryStore хранит те же Arc в map, мутации уже видны.
    }
}
