use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::event::Event as LowEvent;
use crate::api::low::models::MembershipChange;
use crate::core::errors::{LockNetError, Result};
use super::event::HighEvent;
use super::models::{Chat, Invite, User};
use super::security::SecurityHelper;
use super::state::ClientState;

pub struct LockNetAgent {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) state: Arc<RwLock<ClientState>>,
    pub(crate) event_tx: broadcast::Sender<HighEvent>,
    pub(crate) security: Arc<SecurityHelper>,
    process_handle: Option<JoinHandle<()>>,
}

impl LockNetAgent {
    pub(crate) fn new(low: Arc<LockNetLowAgent>) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        let state = Arc::new(RwLock::new(ClientState::new(low.user_id(), low.session_id())));
        let security = Arc::new(SecurityHelper { low: low.clone(), state: state.clone(), event_tx: event_tx.clone() });
        let mut agent = Self { low, state, event_tx, security, process_handle: None };
        agent.start_process();
        agent
    }

    fn start_process(&mut self) {
        let low = self.low.clone();
        let state = self.state.clone();
        let event_tx = self.event_tx.clone();
        let mut rx = low.subscribe();
        let handle = tokio::spawn(async move {
            while let Ok(evt) = rx.recv().await {
                if let Err(e) = process_event(&low, &state, &event_tx, evt).await {
                    tracing::warn!(?e, "high process error");
                }
            }
        });
        self.process_handle = Some(handle);
    }

    pub fn user_id(&self) -> i64 { self.low.user_id() }
    pub fn session_id(&self) -> i64 { self.low.session_id() }
    pub async fn user(&self) -> User { let mut state = self.state.write().await; state.resolve_user(self.low.user_id()) }
    pub fn subscribe(&self) -> broadcast::Receiver<HighEvent> { self.event_tx.subscribe() }
    pub fn security(&self) -> Arc<SecurityHelper> { self.security.clone() }
    pub fn low(&self) -> Arc<LockNetLowAgent> { self.low.clone() }

    pub async fn chats(&self) -> Result<Vec<Chat>> { self.refresh_chats().await }
    pub fn cached_chats(&self) -> Vec<Chat