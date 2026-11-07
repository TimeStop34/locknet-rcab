use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::event::Event as LowEvent;
use crate::core::errors::{LockNetError, Result};
use crate::core::policies::{HistoryVisibility, MegolmRotationVisibility};
use super::event::HighEvent;
use super::models::{Chat, Group, Invite, Message, Reaction, User};
use super::security::SecurityHelper;
use super::state::{ClientState, PendingSasStart};

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
            low, state, event_tx, security, process_handle: None,
        };
        agent.start_process();
        agent
    }

    fn start_process(&mut self) {
        let low = self.low.clone();
        let state = self.state.clone();
        let event_tx = self.event_tx.clone();
        let security = self.security.clone();
        let mut rx = low.subscribe();
        let handle = tokio::spawn(async move {
            while let Ok(evt) = rx.recv().await {
                if let Err(e) = process_event(&low, &state, &event_tx, &security, evt).await {
                    tracing::warn!(?e, "high process error");
                }
            }
        });
        self.process_handle = Some(handle);
    }

    pub(crate) async fn shutdown(&self) {
        if let Some(h) = self.process_handle.as_ref() {
            h.abort();
        }
    }

    pub fn user_id(&self) -> i64 { self.low.user_id() }
    pub fn session_id(&self) -> i64 { self.low.session_id() }

    pub async fn user(&self) -> User {
        let mut st = self.state.write().await;
        st.resolve_user(self.low.user_id())
    }

    pub async fn chats(&self) -> Result<Vec<Chat>> {
        let cached = self.cached_chats();
        if !cached.is_empty() {
            return Ok(cached);
        }
        self.refresh_chats().await
    }

    pub fn cached_chats(&self) -> Vec<Chat> {
        let st = match self.state.try_read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        st.groups
            .values()
            .map(|g| Chat::new(self.low.clone(), g.clone(), self.state.clone(), self.event_tx.clone(), self.security.clone()))
            .collect()
    }

    pub async fn refresh_chats(&self) -> Result<Vec<Chat>> {
        let groups = self.low.groups().list().await?;
        let mut out = Vec::with_capacity(groups.len());
        for dto in groups {
            let g = {
                let mut st = self.state.write().await;
                let g = st.group_to_domain(&dto, &self.low).await;
                st.groups.insert(g.id, g.clone());
                g
            };
            out.push(Chat::new(self.low.clone(), g, self.state.clone(), self.event_tx.clone(), self.security.clone()));
        }
        Ok(out)
    }

    pub async fn chat(&self, chat_id: i64) -> Result<Chat> {
        if let Some(c) = self.cached_chat(chat_id) {
            return Ok(c);
        }
        let info = self.low.groups().info(chat_id).await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&info, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(self.low.clone(), g, self.state.clone(), self.event_tx.clone(), self.security.clone()))
    }

    fn cached_chat(&self, chat_id: i64) -> Option<Chat> {
        let st = self.state.try_read().ok()?;
        st.groups
            .get(&chat_id)
            .map(|g| Chat::new(self.low.clone(), g.clone(), self.state.clone(), self.event_tx.clone(), self.security.clone()))
    }

    pub async fn open_direct(&self, other_user_id: i64) -> Result<Chat> {
        let group = self.low.groups().create_direct(other_user_id).await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&group, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(self.low.clone(), g, self.state.clone(), self.event_tx.clone(), self.security.clone()))
    }

    pub async fn create_group(
        &self,
        name: impl Into<String>,
        is_public: bool,
        public_id: Option<String>,
        participants: Vec<i64>,
    ) -> Result<Chat> {
        let group = self
            .low
            .groups()
            .create(name, is_public, public_id, participants)
            .await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&group, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(self.low.clone(), g, self.state.clone(), self.event_tx.clone(), self.security.clone()))
    }

    pub async fn join_group(&self, public_id: impl Into<String>) -> Result<Chat> {
        let group = self.low.groups().join(public_id).await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&group, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(self.low.clone(), g, self.state.clone(), self.event_tx.clone(), self.security.clone()))
    }

    pub async fn leave_chat(&self, chat_id: i64) -> Result<()> {
        self.low.groups().leave(chat_id).await?;
        let mut st = self.state.write().await;
        st.groups.remove(&chat_id);
        Ok(())
    }

    pub async fn invites(&self) -> Result<Vec<Invite>> {
        let invites = self.low.groups().invites().await?;
        let mut st = self.state.write().await;
        let mut out = Vec::with_capacity(invites.len());
        for dto in invites {
            let inv = st.invite_to_domain(&dto);
            st.invites.insert(inv.id, inv.clone());
            out.push(inv);
        }
        Ok(out)
    }

    pub async fn accept_invite(&self, invite_id: i64) -> Result<Chat> {
        let group_id = {
            let st = self.state.read().await;
            st.invites.get(&invite_id).map(|i| i.group.id)
        };
        let group_id = match group_id {
            Some(gid) => gid,
            None => {
                let _ = self.invites().await?;
                let st = self.state.read().await;
                st.invites.get(&invite_id).map(|i| i.group.id).ok_or_else(|| {
                    LockNetError::InvalidArgument(format!("invite {invite_id} not found"))
                })?
            }
        };

        self.low.groups().accept_invite(invite_id).await?;
        {
            let mut st = self.state.write().await;
            st.invites.remove(&invite_id);
        }
        self.chat(group_id).await
    }

    pub async fn decline_invite(&self, invite_id: i64) -> Result<()> {
        self.low.groups().decline_invite(invite_id).await?;
        let mut st = self.state.write().await;
        st.invites.remove(&invite_id);
        Ok(())
    }

    pub async fn user_info(&self, user_id: i64) -> Result<User> {
        let mut st = self.state.write().await;
        Ok(st.resolve_user(user_id))
    }

    pub fn cached_user(&self, user_id: i64) -> Option<User> {
        let st = self.state.try_read().ok()?;
        st.users.get(&user_id).cloned()
    }

    pub fn cached_message(&self, message_id: i64) -> Option<Message> {
        let st = self.state.try_read().ok()?;
        st.messages.get(&message_id).cloned()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HighEvent> { self.event_tx.subscribe() }
    pub fn security(&self) -> Arc<SecurityHelper> { self.security.clone() }
    pub fn low(&self) -> Arc<LockNetLowAgent> { self.low.clone() }
}

fn stub_group(chat_id: i64) -> Group {
    Group {
        id: chat_id,
        public_id: None,
        name: format!("chat {chat_id}"),
        is_public: false,
        created_by: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        members: Vec::new(),
        member_count: 0,
        encrypted_group_data: None,
        group_data: None,
    }
}

async fn decrypt_text(
    low: &LockNetLowAgent,
    chat_id: i64,
    enc: &crate::api::low::models::Encrypted,
) -> Option<String> {
    if enc.algorithm == "ln.plaintext.v1" {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&enc.ciphertext)
            .ok()?;
        String::from_utf8(bytes).ok()
    } else {
        low.megolm().decrypt(chat_id, enc).await.ok().flatten()
    }
}

async fn resolve_user_by_session(
    low: &Arc<LockNetLowAgent>,
    chat_ids: &[i64],
    target_session: i64,
) -> Option<i64> {
    let mut candidates: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for cid in chat_ids {
        if let Ok(info) = low.groups().info(*cid).await {
            if let Some(members) = info.members {
                for m in members {
                    candidates.insert(m.user_id);
                }
            }
        }
    }
    if candidates.is_empty() {
        return None;
    }
    let candidates_vec: Vec<i64> = candidates.into_iter().collect();
    let sessions = low.keys().query(candidates_vec.clone()).await.ok()?;
    for uid in candidates_vec {
        if let Some(map) = sessions.get(&uid) {
            if map.contains_key(&target_session) {
                return Some(uid);
            }
        }
    }
    None
}

async fn respond_key_request(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    sender_session: i64,
    txid: String,
    chat_ids: Vec<i64>,
    have: Vec<String>,
) {
    let sender_user = match resolve_user_by_session(low, &chat_ids, sender_session).await {
        Some(u) => u,
        None => {
            tracing::warn!(sender_session, "key_request: cannot resolve user_id, ignoring");
            return;
        }
    };

    let security = SecurityHelper {
        low: low.clone(),
        state: state.clone(),
        event_tx: event_tx.clone(),
    };

    let mut allowed_chats = Vec::new();
    let mut has_after_join = false;

    for chat_id in &chat_ids {
        let history_vis = low.store().group_data_state(*chat_id).await
            .map(|s| s.data.history_visibility)
            .unwrap_or(HistoryVisibility::AfterJoin);

        if history_vis == HistoryVisibility::AfterJoin {
            has_after_join = true;
            continue;
        }

        let allowed = match history_vis {
            HistoryVisibility::AllVerifiedSessions => {
                security.is_session_verified(sender_user, sender_session).await
            }
            HistoryVisibility::AllVerifiedUsers => {
                security.is_session_verified(sender_user, sender_session).await
                    && security.is_user_verified(sender_user).await
            }
            _ => false,
        };

        if allowed {
            allowed_chats.push(*chat_id);
        }
    }

    if allowed_chats.is_empty() {
        let reason = if has_after_join {
            "history_visibility_policy"
        } else {
            "not verified"
        };
        let _ = low
            .key_sharing()
            .send_denied(sender_user, sender_session, txid, reason.into())
            .await;
        return;
    }

    let have_set: std::collections::HashSet<String> = have.into_iter().collect();

    let mut to_send: Vec<(i64, String, String)> = Vec::new();
    for (cid, mid) in low.store().megolm_inbound_all().await {
        if !allowed_chats.contains(&cid) {
            continue;
        }
        let key = format!("{}:{}", cid, mid);
        if have_set.contains(&key) {
            continue;
        }
        if let Some(session) = low.store().megolm_inbound(cid, &mid).await {
            let mut s = session.lock().await;
            let first = s.first_known_index();
            if let Some(exported) = s.export_at(first) {
                to_send.push((cid, mid, exported.to_base64()));
            }
        }
    }

    if to_send.is_empty() {
        if let Err(e) = low
            .key_sharing()
            .send_done(sender_user, sender_session, txid, 0)
            .await
        {
            tracing::warn!(?e, "send_done(0) failed");
        }
        return;
    }

    let mut sent = 0u32;
    for (cid, mid, key) in to_send {
        if let Err(e) = low
            .key_sharing()
            .send_group_key(sender_user, sender_session, txid.clone(), cid, mid, key)
            .await
        {
            tracing::warn!(?e, "send_group_key failed");
            continue;
        }
        sent += 1;
    }

    if let Err(e) = low
        .key_sharing()
        .send_done(sender_user, sender_session, txid, sent)
        .await
    {
        tracing::warn!(?e, "send_done failed");
    }
}

/// Пытается расшифровать все `pending_decrypt[chat_id]` сообщения
/// актуальными megolm-inbound ключами. Обновляет `state.messages[*].text`,
/// убирает успешные из pending и эмитит `HighEvent::MessageDecrypted`
/// для каждого.
///
/// Вызывается после успешного импорта нового megolm-ключа
/// (`ln.encryption.group_key` в `process_event`).
async fn try_decrypt_pending(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    chat_id: i64,
) {
    // 1. Снять копию (message_id, encrypted) из state.
    let pending: Vec<(i64, crate::api::low::models::Encrypted)> = {
        let st = state.read().await;
        st.pending_decrypt_for(chat_id)
            .into_iter()
            .filter_map(|mid| {
                st.messages
                    .get(&mid)
                    .and_then(|m| m.encrypted_payload.clone())
                    .map(|enc| (mid, enc))
            })
            .collect()
    };

    if pending.is_empty() {
        return;
    }

    // 2. Пробуем decrypt по каждому.
    let mut decrypted: Vec<(i64, String)> = Vec::new();
    for (mid, enc) in pending {
        if let Ok(Some(text)) = low.megolm().decrypt(chat_id, &enc).await {
            decrypted.push((mid, text));
        }
    }

    if decrypted.is_empty() {
        return;
    }

    // 3. Обновляем state + чистим pending только для успешных.
    {
        let mut st = state.write().await;
        for (mid, text) in &decrypted {
            if let Some(m) = st.messages.get_mut(mid) {
                m.text = Some(text.clone());
            }
        }
        let decrypted_ids: std::collections::HashSet<i64> =
            decrypted.iter().map(|(id, _)| *id).collect();
        st.retain_pending_decrypt(chat_id, |mid| !decrypted_ids.contains(&mid));
    }

    // 4. Эмитим MessageDecrypted.
    for (mid, text) in decrypted {
        let _ = event_tx.send(HighEvent::MessageDecrypted {
            chat_id,
            message_id: mid,
            text,
        });
    }
}

async fn process_event(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    security: &Arc<SecurityHelper>,
    evt: LowEvent,
) -> Result<()> {
    match evt {
        LowEvent::MessageCreate(mc) => {
            let text = decrypt_text(low, mc.chat_id, &mc.encrypted).await;

            let mut st = state.write().await;
            let msg = st.message_create_to_domain(&mc, text);
            st.messages.insert(msg.id, msg.clone());
            let chat = st
                .groups
                .get(&mc.chat_id)
                .map(|g| Chat::new(low.clone(), g.clone(), state.clone(), event_tx.clone(), security.clone()))
                .unwrap_or_else(|| {
                    Chat::new(low.clone(), stub_group(mc.chat_id), state.clone(), event_tx.clone(), security.clone())
                });
            drop(st);

            let _ = event_tx.send(HighEvent::NewMessage { chat, message: msg });
        }
        LowEvent::MessageUpdate(u) => {
            let text = decrypt_text(low, u.chat_id, &u.encrypted).await;

            let mut st = state.write().await;
            let msg_opt = if let Some(m) = st.messages.get_mut(&u.message_id) {
                m.encrypted_payload = Some(u.encrypted.clone());
                m.edited_at = Some(u.edited_at);
                if text.is_some() {
                    m.text = text;
                }
                Some(m.clone())
            } else {
                None
            };
            let chat = st
                .groups
                .get(&u.chat_id)
                .map(|g| Chat::new(low.clone(), g.clone(), state.clone(), event_tx.clone(), security.clone()))
                .unwrap_or_else(|| {
                    Chat::new(low.clone(), stub_group(u.chat_id), state.clone(), event_tx.clone(), security.clone())
                });
            drop(st);

            if let Some(message) = msg_opt {
                let _ = event_tx.send(HighEvent::MessageUpdated { chat, message });
            }
        }
        LowEvent::MessageDelete(d) => {
            let mut st = state.write().await;
            if let Some(m) = st.messages.get_mut(&d.message_id) {
                m.deleted = true;
                m.encrypted_payload = None;
                m.text = None;
            }
            drop(st);
            let _ = event_tx.send(HighEvent::MessageDeleted {
                chat_id: d.chat_id,
                message_id: d.message_id,
            });
        }
        LowEvent::ReactionAdd(r) => {
            let mut st = state.write().await;
            let user = st.resolve_user(r.user_id);
            if let Some(m) = st.messages.get_mut(&r.message_id) {
                if let Some(re) = m.reactions.iter_mut().find(|x| x.emoji == r.emoji) {
                    if !re.user_ids.contains(&r.user_id) {
                        re.user_ids.push(r.user_id);
                        re.count = re.user_ids.len();
                    }
                } else {
                    m.reactions.push(Reaction {
                        emoji: r.emoji.clone(),
                        user_ids: vec![r.user_id],
                        count: 1,
                    });
                }
            }
            drop(st);
            let _ = event_tx.send(HighEvent::ReactionAdded {
                chat_id: r.chat_id,
                message_id: r.message_id,
                user,
                emoji: r.emoji,
            });
        }
        LowEvent::ReactionRemove(r) => {
            let mut st = state.write().await;
            let user = st.resolve_user(r.user_id);
            if let Some(m) = st.messages.get_mut(&r.message_id) {
                if let Some(idx) = m.reactions.iter().position(|x| x.emoji == r.emoji) {
                    let re = &mut m.reactions[idx];
                    re.user_ids.retain(|uid| *uid != r.user_id);
                    re.count = re.user_ids.len();
                    if re.count == 0 {
                        m.reactions.remove(idx);
                    }
                }
            }
            drop(st);
            let _ = event_tx.send(HighEvent::ReactionRemoved {
                chat_id: r.chat_id,
                message_id: r.message_id,
                user,
                emoji: r.emoji,
            });
        }
        LowEvent::GroupCreated(gc) => {
            let g = {
                let mut st = state.write().await;
                let g = st.group_to_domain(&gc.group, low).await;
                st.groups.insert(g.id, g.clone());
                g
            };
            let _ = event_tx.send(HighEvent::GroupCreated { group: g });
        }
        LowEvent::GroupInviteCreated(gi) => {
            let mut st = state.write().await;
            let inv = st.invite_from_push(&gi);
            st.invites.insert(inv.id, inv.clone());
            drop(st);
            let _ = event_tx.send(HighEvent::InviteReceived { invite: inv });
        }
        LowEvent::GroupMembershipChanged(mc) => {
            let user = {
                let mut st = state.write().await;
                let u = st.resolve_user(mc.user_id);
                st.groups.remove(&mc.group_id);
                u
            };

            // Ротация имеет смысл только если мы **участвуем** в группе —
            // то есть знаем политику. Иначе мы свежее устройство без ключа,
            // и создание новой policy с "creation defaults" = downgrade-атака.
            let has_local_policy = low.store().group_data_state(mc.group_id).await.is_some();

            if has_local_policy {
                if let Ok(group_dto) = low.groups().info(mc.group_id).await {
                    if !group_dto.is_public {
                        let mut participant_ids: Vec<i64> = group_dto
                            .members
                            .as_ref()
                            .map(|list| list.iter().map(|m| m.user_id).collect())
                            .unwrap_or_default();

                        if matches!(
                            mc.change,
                            crate::api::low::models::MembershipChange::Left
                        ) {
                            participant_ids.retain(|uid| *uid != mc.user_id);
                        }

                        if !participant_ids.is_empty() {
                            if let Ok(info) = low.megolm().rotate(mc.group_id).await {
                                let policy = low.store().group_data_state(mc.group_id).await
                                    .map(|s| s.data.megolm_rotation_visibility)
                                    .unwrap_or(MegolmRotationVisibility::OnlyVerifiedUsers);
                                if let Err(e) = crate::api::high::group_key::fan_out_group_key(
                                    low,
                                    mc.group_id,
                                    &participant_ids,
                                    &info,
                                    policy,
                                    security,
                                )
                                .await
                                {
                                    tracing::warn!(?e, "membership rotation fan-out failed");
                                }

                                // Sync new blob to server (creator only, idempotent).
                                if let Ok(fresh) = low.groups().info(mc.group_id).await {
                                    if fresh.created_by == low.user_id() {
                                        if let Some(state_gd) = low.store().group_data_state(mc.group_id).await {
                                            if fresh.encrypted_group_data.as_deref() != Some(state_gd.blob.as_str()) {
                                                let _ = low.groups()
                                                    .update_group_data(mc.group_id, &state_gd.blob)
                                                    .await;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::debug!(
                    group_id = mc.group_id,
                    "membership changed but no local policy — skipping rotation (need key_request)"
                );
            }

            let _ = event_tx.send(HighEvent::GroupMembershipChanged {
                group_id: mc.group_id,
                change: mc.change,
                user,
            });
        }
        LowEvent::GroupDataUpdated { group_id } => {
            // Сервер уведомил, что `encrypted_group_data` обновлён (кем-то
            // из участников — обычно создателем). Перечитываем группу:
            // `group_to_domain` расшифрует новый blob нашим локальным
            // `group_data_key` и применит anti-replay по version.
            //
            // Если не сможем расшифровать (ротация с другого устройства) —
            // `group_data` остаётся `None`, применяются строжайшие defaults.
            if let Ok(dto) = low.groups().info(group_id).await {
                let g = {
                    let mut st = state.write().await;
                    if !st.groups.contains_key(&group_id) {
                        // Группа не в кэше — нам неинтересно (мы её не знаем)
                        return Ok(());
                    }
                    let g = st.group_to_domain(&dto, low).await;
                    st.groups.insert(g.id, g.clone());
                    g
                };
                let _ = event_tx.send(HighEvent::PolicyChanged { group_id: g.id });
            }
        }
        LowEvent::ToDevice(payload) => {
            let sender_session = payload.sender_session_id;
            if let Ok(Some(pt)) = low.olm().decrypt(payload).wait().await {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&pt) {
                    let t = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match t {
                        "ln.encryption.group_key" => {
                            let txid = val
                                .pointer("/content/transaction_id")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let chat_id = val
                                .pointer("/content/chat_id")
                                .and_then(|v| v.as_i64());
                            let megolm_id = val
                                .pointer("/content/megolm_session_id")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            if low.megolm().decrypt_group_key(&pt).await.is_ok() {
                                if let (Some(cid), Some(mid)) = (chat_id, megolm_id) {
                                    let _ = event_tx.send(HighEvent::KeyImported {
                                        chat_id: cid,
                                        megolm_session_id: mid.clone(),
                                    });
                                    if let Some(tx) = txid {
                                        let _ = event_tx.send(HighEvent::KeyRequestImported {
                                            txid: tx,
                                            chat_id: cid,
                                            megolm_session_id: mid,
                                        });
                                    }
                                    // Новый ключ — попробовать расшифровать pending
                                    try_decrypt_pending(low, state, event_tx, cid).await;
                                }
                            }
                        }
                        "ln.encryption.key_request_done" => {
                            let txid = val
                                .pointer("/content/transaction_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let count = val
                                .pointer("/content/count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let _ = event_tx.send(HighEvent::KeyRequestDone {
                                txid,
                                total_imported: count,
                            });
                        }
                        "ln.encryption.key_denied" => {
                            let txid = val
                                .pointer("/content/transaction_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let reason = val
                                .pointer("/content/reason")
                                .and_then(|v| v.as_str())
                                .unwrap_or("denied")
                                .to_string();
                            let _ = event_tx.send(HighEvent::KeyRequestDenied { txid, reason });
                        }
                        "ln.encryption.key_request" => {
                            let content = val.get("content").cloned().unwrap_or_default();
                            let chat_ids: Vec<i64> = content
                                .get("chat_ids")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
                                .unwrap_or_default();
                            let txid = content
                                .get("transaction_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let have: Vec<String> = content
                                .get("have")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let _ = event_tx.send(HighEvent::KeyRequestReceived {
                                from_user: 0,
                                from_session: sender_session,
                                chat_ids: chat_ids.clone(),
                            });

                            let low2 = low.clone();
                            let state2 = state.clone();
                            let event_tx2 = event_tx.clone();
                            tokio::spawn(async move {
                                respond_key_request(
                                    &low2,
                                    &state2,
                                    &event_tx2,
                                    sender_session,
                                    txid,
                                    chat_ids,
                                    have,
                                )
                                .await;
                            });
                        }
                        t if t.starts_with("ln.encryption.key.verification.qr.") => {
                            let _ = event_tx.send(HighEvent::QrMessage {
                                sender_user: 0,
                                sender_session,
                                content: val,
                            });
                        }
                        t if t.starts_with("ln.encryption.key.verification.") => {
                            if t == "ln.encryption.key.verification.start" {
                                let txid = val
                                    .pointer("/content/transaction_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if !txid.is_empty() {
                                    let mut st = state.write().await;
                                    st.pending_sas_starts.insert(
                                        txid,
                                        PendingSasStart {
                                            from_user: None,
                                            from_session: sender_session,
                                        },
                                    );
                                }
                            }
                            let _ = event_tx.send(HighEvent::SasMessage {
                                sender_user: 0,
                                sender_session,
                                content: val,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        LowEvent::CrossSigningReset(r) => {
            let mut st = state.write().await;
            st.verified_users.remove(&r.user_id);
            st.invalidate_trust_graph();
            drop(st);
            let _ = event_tx.send(HighEvent::CrossSigningReset { user_id: r.user_id });
        }
        LowEvent::Reconnected => {
            let _ = event_tx.send(HighEvent::Reconnected);
        }
        LowEvent::SessionExpired => {
            let _ = event_tx.send(HighEvent::SessionExpired);
        }
        LowEvent::CrossSigningSignatureAdded(_) => {
            let mut st = state.write().await;
            st.invalidate_trust_graph();
        }
        LowEvent::Unknown { .. } => {}
    }
    Ok(())
}