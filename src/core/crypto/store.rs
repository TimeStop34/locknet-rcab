use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use vodozemac::megolm::{GroupSession, InboundGroupSession};

use crate::core::policies::GroupDataState;
use super::account::Account;
use super::olm::OlmSessionEntry;
use super::signature::CrossSigningKeysPrivate;

const MAX_OLM_SESSIONS_PER_PEER: usize = 5;

/// Хранилище криптографического состояния клиента.
///
/// Все методы **async** — потому что persistent-реализации (SQLite,
/// Android KeyStore, ...) делают I/O.
///
/// ## Контракт
///
/// - Методы с `_put`/`_add`/`_remove`/`_clear` **записывают** в хранилище.
///   Реализация **обязана** гарантировать, что после возврата из `await`
///   данные зафиксированы (persistent store — commit, InMemory — запись в map).
/// - Методы-геттеры возвращают `Option` или пустую коллекцию, **никогда**
///   не возвращают «молча `None` из-за race», как это было с `try_lock`.
#[async_trait]
pub trait CryptoStore: Send + Sync {
    async fn account(&self) -> Arc<Mutex<Account>>;

    // ---- Olm sessions ----

    async fn olm_sessions(&self, peer_session_id: i64) -> Vec<OlmSessionEntry>;
    async fn olm_add(&self, peer_session_id: i64, entry: OlmSessionEntry);
    async fn olm_remove_all(&self, peer_session_id: i64);

    // ---- Megolm outbound ----

    async fn megolm_outbound(&self, chat_id: i64) -> Option<Arc<Mutex<GroupSession>>>;
    async fn megolm_outbound_key(&self, chat_id: i64) -> Option<String>;
    async fn megolm_outbound_put(
        &self,
        chat_id: i64,
        session: Arc<Mutex<GroupSession>>,
        key: String,
    );

    // ---- Megolm inbound ----

    async fn megolm_inbound(
        &self,
        chat_id: i64,
        megolm_session_id: &str,
    ) -> Option<Arc<Mutex<InboundGroupSession>>>;
    async fn megolm_inbound_put(
        &self,
        chat_id: i64,
        megolm_session_id: String,
        session: Arc<Mutex<InboundGroupSession>>,
    );
    async fn megolm_inbound_all(&self) -> Vec<(i64, String)>;

    // ---- Cross-signing (private keys) ----

    async fn cross_signing_keys(&self) -> Option<Arc<CrossSigningKeysPrivate>>;
    async fn cross_signing_keys_put(&self, keys: Arc<CrossSigningKeysPrivate>);
    async fn cross_signing_keys_clear(&self);

    // ---- Group policy blob ----

    /// Шифрованный `GroupData` для чата. `None` = группа без политики
    /// (старая версия / мы не участник / ключа нет).
    async fn group_data_state(&self, chat_id: i64) -> Option<GroupDataState>;
    async fn group_data_state_put(&self, chat_id: i64, state: GroupDataState);
    async fn group_data_state_remove(&self, chat_id: i64);
}

pub struct InMemoryStore {
    account: Arc<Mutex<Account>>,
    olm_sessions: Arc<Mutex<HashMap<i64, Vec<OlmSessionEntry>>>>,
    megolm_out: Arc<Mutex<HashMap<i64, (Arc<Mutex<GroupSession>>, String)>>>,
    megolm_in: Arc<Mutex<HashMap<(i64, String), Arc<Mutex<InboundGroupSession>>>>>,
    cross_signing: Arc<Mutex<Option<Arc<CrossSigningKeysPrivate>>>>,
    group_data: Arc<Mutex<HashMap<i64, GroupDataState>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            account: Arc::new(Mutex::new(Account::new())),
            olm_sessions: Arc::new(Mutex::new(HashMap::new())),
            megolm_out: Arc::new(Mutex::new(HashMap::new())),
            megolm_in: Arc::new(Mutex::new(HashMap::new())),
            cross_signing: Arc::new(Mutex::new(None)),
            group_data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self { Self::new() }
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
}