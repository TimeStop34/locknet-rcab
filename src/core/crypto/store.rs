use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use vodozemac::megolm::{GroupSession, InboundGroupSession};

use super::account::Account;
use super::olm::OlmSessionEntry;
use super::signature::CrossSigningKeysPrivate;

const MAX_OLM_SESSIONS_PER_PEER: usize = 5;

pub trait CryptoStore: Send + Sync {
    fn account(&self) -> Arc<Mutex<Account>>;

    fn olm_sessions(&self, peer_session_id: i64) -> Vec<OlmSessionEntry>;
    fn olm_add(&self, peer_session_id: i64, entry: OlmSessionEntry);
    fn olm_remove_all(&self, peer_session_id: i64);

    fn megolm_outbound(&self, chat_id: i64) -> Option<Arc<Mutex<GroupSession>>>;
    fn megolm_outbound_key(&self, chat_id: i64) -> Option<String>;
    fn megolm_outbound_put(&self, chat_id: i64, session: Arc<Mutex<GroupSession>>, key: String);

    fn megolm_inbound(&self, chat_id: i64, megolm_session_id: &str) -> Option<Arc<Mutex<InboundGroupSession>>>;
    fn megolm_inbound_put(&self, chat_id: i64, megolm_session_id: String, session: Arc<Mutex<InboundGroupSession>>);
    fn megolm_inbound_all(&self) -> Vec<(i64, String)>;

    fn cross_signing_keys(&self) -> Option<Arc<CrossSigningKeysPrivate>>;
    fn cross_signing_keys_put(&self, keys: Arc<CrossSigningKeysPrivate>);
    fn cross_signing_keys_clear(&self);
}

pub struct InMemoryStore {
    account: Arc<Mutex<Account>>,
    olm_sessions: Arc<Mutex<HashMap<i64, Vec<OlmSessionEntry>>>>,
    megolm_out: Arc<Mutex<HashMap<i64, (Arc<Mutex<GroupSession>>, String)>>>,
    megolm_in: Arc<Mutex<HashMap<(i64, String), Arc<Mutex<InboundGroupSession>>>>>,
    cross_signing: Arc<Mutex<Option<Arc<CrossSigningKeysPrivate>>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            account: Arc::new(Mutex::new(Account::new())),
            olm_sessions: Arc::new(Mutex::new(HashMap::new())),
            megolm_out: Arc::new(Mutex::new(HashMap::new())),
            megolm_in: Arc::new(Mutex::new(HashMap::new())),
            cross_signing: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self { Self::new() }
}

impl CryptoStore for InMemoryStore {
    fn account(&self) -> Arc<Mutex<Account>> { self.account.clone() }

    fn olm_sessions(&self, peer_session_id: i64) -> Vec<OlmSessionEntry> {
        self.olm_sessions.try_lock().ok().and_then(|g| g.get(&peer_session_id).cloned()).unwrap_or_default()
    }
    fn olm_add(&self, peer_session_id: i64, entry: OlmSessionEntry) {
        if let Ok(mut g) = self.olm_sessions.try_lock() {
            let list = g.entry(peer_session_id).or_insert_with(Vec::new);
            list.push(entry);
            if list.len() > MAX_OLM_SESSIONS_PER_PEER { list.remove(0); }
        }
    }
    fn olm_remove_all(&self, peer_session_id: i64) {
        if let Ok(mut g) = self.olm_sessions.try_lock() { g.remove(&peer_session_id); }
    }

    fn megolm_outbound(&self, chat_id: i64) -> Option<Arc<Mutex<GroupSession>>> {
        self.megolm_out.try_lock().ok().and_then(|g| g.get(&chat_id).map(|(s, _)| s.clone()))
    }
    fn megolm_outbound_key(&self, chat_id: i64) -> Option<String> {
        self.megolm_out.try_lock().ok().and_then(|g| g.get(&chat_id).map(|(_, k)| k.clone()))
    }
    fn megolm_outbound_put(&self, chat_id: i64, session: Arc<Mutex<GroupSession>>, key: String) {
        if let Ok(mut g) = self.megolm_out.try_lock() { g.insert(chat_id, (session, key)); }
    }

    fn megolm_inbound(&self, chat_id: i64, megolm_session_id: &str) -> Option<Arc<Mutex<InboundGroupSession>>> {
        self.megolm_in.try_lock().ok().and_then(|g| g.get(&(chat_id, megolm_session_id.to_string())).cloned())
    }
    fn megolm_inbound_put(&self, chat_id: i64, megolm_session_id: String, session: Arc<Mutex<InboundGroupSession>>) {
        if let Ok(mut g) = self.megolm_in.try_lock() { g.insert((chat_id, megolm_session_id), session); }
    }
    fn megolm_inbound_all(&self) -> Vec<(i64, String)> {
        self.megolm_in.try_lock().ok().map(|g| g.keys().cloned().collect()).unwrap_or_default()
    }

    fn cross_signing_keys(&self) -> Option<Arc<CrossSigningKeysPrivate>> {
        self.cross_signing.try_lock().ok().and_then(|g| g.clone())
    }
    fn cross_signing_keys_put(&self, keys: Arc<CrossSigningKeysPrivate>) {
        if let Ok(mut g) = self.cross_signing.try_lock() { *g = Some(keys); }
    }
    fn cross_signing_keys_clear(&self) {
        if let Ok(mut g) = self.cross_signing.try_lock() { *g = None; }
    }
}