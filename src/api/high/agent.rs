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
        let security = Arc::new(SecurityHelper {
            low: low.clone(),
            state: state.clone(),
            event_tx: event_tx.clone(),
        });

        let mut agent = Self {
            low,
            state,
            event_tx,
            security,
            process_handle: None,
        };
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

    pub fn user_id(&self) -> i64 {
        self.low.user_id()
    }

    pub fn session_id(&self) -> i64 {
        self.low.session_id()
    }

    pub async fn user(&self) -> User {
        let mut state = self.state.write().await;
        state.resolve_user(self.low.user_id())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HighEvent> {
        self.event_tx.subscribe()
    }

    pub fn security(&self) -> Arc<SecurityHelper> {
        self.security.clone()
    }

    pub fn low(&self) -> Arc<LockNetLowAgent> {
        self.low.clone()
    }

    pub async fn chats(&self) -> Result<Vec<Chat>> {
        self.refresh_chats().await
    }

    pub fn cached_chats(&self) -> Vec<Chat> {
        let groups = self
            .state
            .try_read()
            .ok()
            .map(|s| s.groups.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        groups
            .into_iter()
            .map(|g| Chat::new(self.low.clone(), g))
            .collect()
    }

    pub async fn refresh_chats(&self) -> Result<Vec<Chat>> {
        let groups = self.low.groups().list().await?;
        let mut state = self.state.write().await;
        let mut result = Vec::with_capacity(groups.len());
        for dto in groups {
            let group = state.group_to_domain(&dto);
            state.groups.insert(group.id, group.clone());
            result.push(Chat::new(self.low.clone(), group));
        }
        Ok(result)
    }

    pub async fn chat(&self, chat_id: i64) -> Result<Chat> {
        {
            let state = self.state.read().await;
            if let Some(g) = state.groups.get(&chat_id) {
                return Ok(Chat::new(self.low.clone(), g.clone()));
            }
        }
        let dto = self.low.groups().info(chat_id).await?;
        let mut state = self.state.write().await;
        let group = state.group_to_domain(&dto);
        state.groups.insert(group.id, group.clone());
        Ok(Chat::new(self.low.clone(), group))
    }

    pub async fn open_direct(&self, other_user_id: i64) -> Result<Chat> {
        let dto = self.low.groups().create_direct(other_user_id).await?;
        let mut state = self.state.write().await;
        let group = state.group_to_domain(&dto);
        state.groups.insert(group.id, group.clone());
        Ok(Chat::new(self.low.clone(), group))
    }

    pub async fn create_group(
        &self,
        name: impl Into<String>,
        is_public: bool,
        public_id: Option<String>,
        participants: Vec<i64>,
    ) -> Result<Chat> {
        let dto = self
            .low
            .groups()
            .create(name, is_public, public_id, participants)
            .await?;
        let mut state = self.state.write().await;
        let group = state.group_to_domain(&dto);
        state.groups.insert(group.id, group.clone());
        Ok(Chat::new(self.low.clone(), group))
    }

    pub async fn join_group(&self, public_id: impl Into<String>) -> Result<Chat> {
        let dto = self.low.groups().join(public_id).await?;
        let mut state = self.state.write().await;
        let group = state.group_to_domain(&dto);
        state.groups.insert(group.id, group.clone());
        Ok(Chat::new(self.low.clone(), group))
    }

    pub async fn leave_chat(&self, chat_id: i64) -> Result<()> {
        self.low.groups().leave(chat_id).await?;
        let mut state = self.state.write().await;
        state.groups.remove(&chat_id);
        Ok(())
    }

    pub async fn invites(&self) -> Result<Vec<Invite>> {
        let dtos = self.low.groups().invites().await?;
        let mut state = self.state.write().await;
        let mut result = Vec::with_capacity(dtos.len());
        for dto in dtos {
            let invite = state.invite_to_domain(&dto);
            state.invites.insert(invite.id, invite.clone());
            result.push(invite);
        }
        Ok(result)
    }

    pub async fn accept_invite(&self, invite_id: i64) -> Result<Chat> {
        self.low.groups().accept_invite(invite_id).await?;
        let invite = {
            let mut state = self.state.write().await;
            state.invites.remove(&invite_id)
        };
        let invite = invite
            .ok_or_else(|| LockNetError::InvalidResponse("invite not found in state".into()))?;
        self.chat(invite.group.id).await
    }

    pub async fn decline_invite(&self, invite_id: i64) -> Result<()> {
        self.low.groups().decline_invite(invite_id).await?;
        let mut state = self.state.write().await;
        state.invites.remove(&invite_id);
        Ok(())
    }

    pub async fn user_info(&self, user_id: i64) -> Result<User> {
        let keys = self.low.keys().query(vec![user_id]).await?;
        let cs = self
            .low
            .crypto()
            .query_cross_signing_keys(vec![user_id])
            .await
            .ok();

        let mut state = self.state.write().await;
        let mut user = state.resolve_user(user_id);

        if let Some(devs) = keys.get(&user_id) {
            user.sessions = devs
                .iter()
                .map(|(sid, d)| super::models::SessionInfo {
                    id: *sid,
                    ed25519_key: Some(d.ed25519_key.clone()),
                    curve25519_key: Some(d.curve25519_key.clone()),
                    verified: cs
                        .as_ref()
                        .and_then(|c| c.get(&user_id))
                        .and_then(|e| e.devices.get(sid))
                        .and_then(|dev| dev.signatures.get(&user_id))
                        .and_then(|m| m.get("self_signing"))
                        .is_some(),
                })
                .collect();
        }

        if let Some(entry) = cs.as_ref().and_then(|c| c.get(&user_id)) {
            user.verified = entry
                .master_key
                .signatures
                .get(&self.low.user_id())
                .and_then(|m| m.get("user_signing"))
                .is_some();
        }

        state.users.insert(user_id, user.clone());
        Ok(user)
    }

    pub fn cached_user(&self, user_id: i64) -> Option<User> {
        self.state
            .try_read()
            .ok()
            .and_then(|s| s.users.get(&user_id).cloned())
    }

    pub async fn shutdown(&mut self) {
        if let Some(h) = self.process_handle.take() {
            h.abort();
            let _ = h.await;
        }
    }
}

async fn process_event(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    evt: LowEvent,
) -> Result<()> {
    match evt {
        LowEvent::ToDevice(payload) => {
            let pt = match low.olm().decrypt(payload).wait().await {
                Ok(Some(pt)) => pt,
                _ => return Ok(()),
            };

            if low.megolm().decrypt_group_key(&pt).await.unwrap_or(false) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&pt) {
                    if let (Some(chat_id), Some(mid)) = (
                        v.pointer("/content/chat_id").and_then(|x| x.as_i64()),
                        v.pointer("/content/megolm_session_id")
                            .and_then(|x| x.as_str()),
                    ) {
                        let _ = event_tx.send(HighEvent::KeyImported {
                            chat_id,
                            megolm_session_id: mid.to_string(),
                        });
                    }
                }
            }
        }

        LowEvent::MessageCreate(m) => {
            let text = match &m.encrypted {
                Some(enc) => low.megolm().decrypt(m.chat_id, enc).await.ok().flatten(),
                None => None,
            };

            let (chat, message) = {
                if !state.read().await.groups.contains_key(&m.chat_id) {
                    if let Ok(dto) = low.groups().info(m.chat_id).await {
                        let mut st = state.write().await;
                        let g = st.group_to_domain(&dto);
                        st.groups.insert(g.id, g);
                    } else {
                        return Ok(());
                    }
                }

                let mut st = state.write().await;
                let group = match st.groups.get(&m.chat_id).cloned() {
                    Some(g) => g,
                    None => return Ok(()),
                };
                let dto = crate::api::low::models::Message {
                    message_id: m.message_id,
                    chat_id: m.chat_id,
                    author_id: m.author_id,
                    author_session_id: m.author_session_id,
                    encrypted: Some(m.encrypted.clone()),
                    thread_id: m.thread_id,
                    created_at: m.created_at,
                    edited_at: m.edited_at,
                    deleted: false,
                    reactions: m.reactions.clone(),
                };
                let message = st.message_to_domain(&dto, text);
                st.messages.insert(message.id, message.clone());
                (Chat::new(low.clone(), group), message)
            };

            let _ = event_tx.send(HighEvent::NewMessage { chat, message });
        }

        LowEvent::MessageUpdate(u) => {
            let text = low.megolm().decrypt(u.chat_id, &u.encrypted).await.ok().flatten();
            let mut st = state.write().await;
            let group = match st.groups.get(&u.chat_id).cloned() {
                Some(g) => g,
                None => return Ok(()),
            };
            let existing = st.messages.get(&u.message_id).cloned();
            let message = match existing {
                Some(mut existing) => {
                    existing.text = text;
                    existing.edited_at = Some(u.edited_at);
                    existing.encrypted_payload = Some(u.encrypted);
                    existing
                }
                None => {
                    let dto = crate::api::low::models::Message {
                        message_id: u.message_id,
                        chat_id: u.chat_id,
                        author_id: 0,
                        author_session_id: 0,
                        encrypted: Some(u.encrypted),
                        thread_id: None,
                        created_at: u.edited_at,
                        edited_at: Some(u.edited_at),
                        deleted: false,
                        reactions: Vec::new(),
                    };
                    st.message_to_domain(&dto, text)
                }
            };
            st.messages.insert(message.id, message.clone());
            drop(st);

            let _ = event_tx.send(HighEvent::MessageUpdated {
                chat: Chat::new(low.clone(), group),
                message,
            });
        }

        LowEvent::MessageDelete(d) => {
            {
                let mut st = state.write().await;
                if let Some(m) = st.messages.get_mut(&d.message_id) {
                    m.deleted = true;
                    m.text = None;
                    m.encrypted_payload = None;
                }
            }
            let _ = event_tx.send(HighEvent::MessageDeleted {
                chat_id: d.chat_id,
                message_id: d.message_id,
            });
        }

        LowEvent::ReactionAdd(r) => {
            let user = {
                let st = state.read().await;
                st.users
                    .get(&r.user_id)
                    .cloned()
                    .unwrap_or_else(|| User::unknown(r.user_id))
            };
            let _ = event_tx.send(HighEvent::ReactionAdded {
                chat_id: r.chat_id,
                message_id: r.message_id,
                user,
                emoji: r.emoji,
            });
        }

        LowEvent::ReactionRemove(r) => {
            let user = {
                let st = state.read().await;
                st.users
                    .get(&r.user_id)
                    .cloned()
                    .unwrap_or_else(|| User::unknown(r.user_id))
            };
            let _ = event_tx.send(HighEvent::ReactionRemoved {
                chat_id: r.chat_id,
                message_id: r.message_id,
                user,
                emoji: r.emoji,
            });
        }

        LowEvent::GroupCreated(g) => {
            let mut st = state.write().await;
            let group = st.group_to_domain(&g.group);
            st.groups.insert(group.id, group.clone());
            drop(st);
            let _ = event_tx.send(HighEvent::GroupCreated { group });
        }

        LowEvent::GroupMembershipChanged(m) => {
            if matches!(m.change, MembershipChange::Added | MembershipChange::Left) {
                let _ = low.megolm().rotate(m.group_id).await;
                fan_out_group_key(low.clone(), state.clone(), m.group_id).await;
            }

            let user = {
                let st = state.read().await;
                st.users
                    .get(&m.user_id)
                    .cloned()
                    .unwrap_or_else(|| User::unknown(m.user_id))
            };
            let _ = event_tx.send(HighEvent::GroupMembershipChanged {
                group_id: m.group_id,
                change: m.change,
                user,
            });
        }

        LowEvent::GroupInviteCreated(i) => {
            let invite = {
                let mut st = state.write().await;
                let dto = crate::api::low::models::Invite {
                    id: i.invite_id,
                    group_id: i.group_id,
                    group_name: i.group_name,
                    inviter_id: i.inviter_id,
                    created_at: i.created_at,
                };
                st.invite_to_domain(&dto)
            };
            let _ = event_tx.send(HighEvent::InviteReceived { invite });
        }

        LowEvent::CrossSigningSignatureAdded(s) => {
            {
                let mut st = state.write().await;
                if s.signer_user_id != low.user_id() {
                    st.verified_users.insert(s.signer_user_id);
                }
            }
            let _ = event_tx.send(HighEvent::UserVerified {
                user_id: s.signer_user_id,
            });
        }

        LowEvent::CrossSigningReset(r) => {
            {
                let mut st = state.write().await;
                st.verified_users.remove(&r.user_id);
            }
            if r.user_id == low.user_id() {
                low.store().cross_signing_keys_clear();
            }
            let _ = event_tx.send(HighEvent::CrossSigningReset { user_id: r.user_id });
        }

        LowEvent::Reconnected => {
            let _ = low.events().sync_until_empty(100).await;
            let _ = event_tx.send(HighEvent::Reconnected);
        }

        LowEvent::SessionExpired => {
            let _ = event_tx.send(HighEvent::SessionExpired);
        }

        LowEvent::Unknown { .. } => {}
    }
    Ok(())
}

async fn fan_out_group_key(
    low: Arc<LockNetLowAgent>,
    state: Arc<RwLock<ClientState>>,
    chat_id: i64,
) {
    let group = {
        let mut st = state.write().await;
        if !st.groups.contains_key(&chat_id) {
            drop(st);
            if let Ok(dto) = low.groups().info(chat_id).await {
                let mut st2 = state.write().await;
                let g = st2.group_to_domain(&dto);
                st2.groups.insert(g.id, g);
            }
            state.write().await.groups.get(&chat_id).cloned()
        } else {
            st.groups.get(&chat_id).cloned()
        }
    };

    let group = match group {
        Some(g) => g,
        None => return,
    };

    if let Err(e) = low.megolm().ensure_session(chat_id).await {
        tracing::warn!(?e, "fan_out: ensure_session failed");
        return;
    }

    for member in &group.members {
        let sessions = match low.keys().query(vec![member.user.id]).await {
            Ok(q) => q.get(&member.user.id).cloned().unwrap_or_default(),
            Err(_) => continue,
        };

        for sid in sessions.keys() {
            if let Err(e) = low
                .megolm()
                .share_group_key(chat_id, member.user.id, *sid)
                .await
            {
                tracing::warn!(?e, ?member.user.id, ?sid, "fan_out: share failed");
            }
        }
    }
}

impl Drop for LockNetAgent {
    fn drop(&mut self) {
        if let Some(h) = self.process_handle.take() {
            h.abort();
        }
    }
}