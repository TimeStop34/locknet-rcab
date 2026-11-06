use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::models::Encrypted;
use crate::core::crypto::megolm::MEGOLM_ALGORITHM;
use crate::core::errors::{LockNetError, Result};
use super::group::Group;
use super::message::Message;
use super::reaction::Reaction;
use super::user::User;
use crate::api::high::event::HighEvent;
use crate::api::high::security::SecurityHelper;
use crate::api::high::state::ClientState;

pub(crate) const PLAINTEXT_ALGORITHM: &str = "ln.plaintext.v1";

const KEY_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct ChatInner {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) group: Group,
    pub(crate) state: Arc<RwLock<ClientState>>,
    pub(crate) high_event_tx: broadcast::Sender<HighEvent>,
    pub(crate) security: Arc<SecurityHelper>,
    pub(crate) coverage: RwLock<Option<(String, usize)>>,
}

#[derive(Clone)]
pub struct Chat { pub(crate) inner: Arc<ChatInner> }

impl Chat {
    pub(crate) fn new(
        low: Arc<LockNetLowAgent>,
        group: Group,
        state: Arc<RwLock<ClientState>>,
        high_event_tx: broadcast::Sender<HighEvent>,
        security: Arc<SecurityHelper>,
    ) -> Self {
        Self {
            inner: Arc::new(ChatInner {
                low,
                group,
                state,
                high_event_tx,
                security,
                coverage: RwLock::new(None),
            }),
        }
    }

    pub fn id(&self) -> i64 { self.inner.group.id }
    pub fn name(&self) -> String { self.inner.group.name.clone() }
    pub fn is_public(&self) -> bool { self.inner.group.is_public }
    pub fn is_direct(&self) -> bool { self.inner.group.is_direct() }
    pub fn is_encrypted(&self) -> bool { !self.inner.group.is_public }
    pub fn public_id(&self) -> Option<String> { self.inner.group.public_id.clone() }
    pub fn created_by(&self) -> i64 { self.inner.group.created_by }
    pub fn created_at(&self) -> DateTime<Utc> { self.inner.group.created_at }
    pub fn members(&self) -> Vec<User> { self.inner.group.members.iter().map(|m| m.user.clone()).collect() }
    pub fn member_count(&self) -> usize { self.inner.group.member_count }
    pub fn group(&self) -> &Group { &self.inner.group }

    pub async fn refresh_dto(&self) -> Result<crate::api::low::models::Group> {
        self.inner.low.groups().info(self.id()).await
    }

    /// Защита от downgrade-атаки.
    ///
    /// Перед шифрованием мы должны **знать** политику группы. Если локального
    /// `group_data_state` нет, различаем два случая:
    ///
    /// 1. **Создание** — мы создатель, сервер ещё не имеет `encrypted_group_data`.
    ///    Можно создать новую политику с "creation defaults".
    /// 2. **Recovery** — либо мы не создатель, либо сервер уже имеет blob.
    ///    Нельзя создавать новую политику — это подменит строгую на мягкую
    ///    (сервер мог специально скрыть blob). Нужно вызвать
    ///    `request_missing_keys()` / дождаться `group_key` от другого устройства.
    async fn ensure_policy_known(&self) -> Result<()> {
        if !self.is_encrypted() {
            return Ok(());
        }

        if self.inner.low.store().group_data_state(self.id()).is_some() {
            return Ok(());
        }

        let is_creator = self.inner.group.created_by == self.inner.low.user_id();
        if !is_creator {
            return Err(LockNetError::InvalidArgument(
                "cannot send: group policy unknown (no local group_data, not creator). \
                 Call request_missing_keys() first."
                    .into(),
            ));
        }

        // Создатель без локального state — проверяем сервер.
        // Если blob есть — мы были в группе раньше, потеряли store.
        if let Ok(fresh) = self.inner.low.groups().info(self.id()).await {
            if fresh.encrypted_group_data.is_some() {
                return Err(LockNetError::InvalidArgument(
                    "cannot send: server has group policy blob but local key missing. \
                     Call request_missing_keys() to recover."
                        .into(),
                ));
            }
        }

        Ok(())
    }

        /// Синхронизирует локальную policy в сервер, если мы создатель
    /// и блоб расходится. Идемпотентно.
    ///
    /// Вызывается после `megolm.ensure_session` (в send) и после ротации
    /// в `process_event` (через `LockNetAgent::sync_policy_for_chat`).
    pub(crate) async fn sync_policy_to_server(&self) -> Result<()> {
        if !self.is_encrypted() {
            return Ok(());
        }
        let low = &self.inner.low;
        let chat_id = self.id();

        // Только создатель может писать
        if self.inner.group.created_by != low.user_id() {
            return Ok(());
        }

        let Some(state) = low.store().group_data_state(chat_id) else {
            return Ok(());
        };

        // Сравниваем с тем, что сервер знает (актуальный snapshot в state.groups)
        let server_blob = {
            let st = self.inner.state.read().await;
            st.groups
                .get(&chat_id)
                .and_then(|g| g.encrypted_group_data.clone())
        };

        if server_blob.as_deref() == Some(state.blob.as_str()) {
            return Ok(());
        }

        low.groups().update_group_data(chat_id, &state.blob).await?;

        // Обновляем snapshot в state.groups, чтобы следующий вызов не дёргал сеть
        {
            let mut st = self.inner.state.write().await;
            if let Some(g) = st.groups.get_mut(&chat_id) {
                g.encrypted_group_data = Some(state.blob);
            }
        }
        Ok(())
    }

    pub async fn send(&self, text: impl Into<String>) -> Result<Message> {
        let text = text.into();
        let chat_id = self.id();
        let low = self.inner.low.clone();

        let encrypted = if self.is_encrypted() {
            self.ensure_policy_known().await?;

            let info = low.megolm().ensure_session(chat_id).await?;

            // Гарантируем, что сервер знает нашу policy (для anti-downgrade
            // проверки при восстановлении на другом устройстве).
            self.sync_policy_to_server().await?;

            let need_fanout = {
                let guard = self.inner.coverage.read().await;
                match &*guard {
                    Some((sid, cnt)) => {
                        sid != &info.megolm_session_id
                            || *cnt != self.inner.group.member_count
                    }
                    None => true,
                }
            };

            if need_fanout {
                let fresh = low.groups().info(chat_id).await.ok();
                let (participant_ids, member_count): (Vec<i64>, usize) =
                    match fresh.as_ref().and_then(|g| g.members.as_ref()) {
                        Some(list) => (
                            list.iter().map(|m| m.user_id).collect(),
                            list.len(),
                        ),
                        None => (
                            self.inner
                                .group
                                .members
                                .iter()
                                .map(|m| m.user.id)
                                .collect(),
                            self.inner.group.member_count,
                        ),
                    };
                if !participant_ids.is_empty() {
                    let policy = low
                        .store()
                        .group_data_state(chat_id)
                        .map(|s| s.data.megolm_rotation_visibility)
                        .unwrap_or(crate::core::policies::MegolmRotationVisibility::OnlyVerifiedUsers);
                    crate::api::high::group_key::fan_out_group_key(
                        &low,
                        chat_id,
                        &participant_ids,
                        &info,
                        policy,
                        &self.inner.security,
                    )
                    .await?;
                }
                *self.inner.coverage.write().await =
                    Some((info.megolm_session_id.clone(), member_count));
            }

            low.megolm().encrypt(chat_id, &text).await?
        } else {
            Encrypted {
                algorithm: PLAINTEXT_ALGORITHM.into(),
                sender_key: String::new(),
                sender_session_id: low.session_id(),
                megolm_session_id: String::new(),
                ciphertext: base64_encode(text.as_bytes()),
            }
        };

        let ack = low.messages().send(chat_id, encrypted.clone()).await?;
        Ok(Message {
            id: ack.message_id,
            chat_id,
            author: User::unknown(low.user_id()),
            author_session_id: low.session_id(),
            text: Some(text),
            encrypted: encrypted.algorithm == MEGOLM_ALGORITHM,
            encrypted_payload: Some(encrypted),
            thread_id: None,
            created_at: ack.created_at,
            edited_at: None,
            deleted: false,
            reactions: Vec::new(),
        })
    }

    pub async fn send_encrypted(&self, encrypted: Encrypted) -> Result<Message> {
        let chat_id = self.id();
        let low = self.inner.low.clone();
        let ack = low.messages().send(chat_id, encrypted.clone()).await?;
        let text = low.megolm().decrypt(chat_id, &encrypted).await.ok().flatten();
        Ok(Message {
            id: ack.message_id,
            chat_id,
            author: User::unknown(low.user_id()),
            author_session_id: low.session_id(),
            text,
            encrypted: true,
            encrypted_payload: Some(encrypted),
            thread_id: None,
            created_at: ack.created_at,
            edited_at: None,
            deleted: false,
            reactions: Vec::new(),
        })
    }

    pub async fn messages(&self, before: Option<i64>, limit: u32) -> Result<Vec<Message>> {
        let chat_id = self.id();
        let low = self.inner.low.clone();
        let page = low.messages().get(chat_id, before, limit).await?;
        let mut result = Vec::with_capacity(page.messages.len());
        let mut missing: Vec<i64> = Vec::new();

        for dto in page.messages {
            let encrypted = dto.encrypted.clone();
            let (text, was_encrypted) = match &encrypted {
                Some(enc) => {
                    if enc.algorithm == PLAINTEXT_ALGORITHM {
                        (base64_decode_str(&enc.ciphertext), false)
                    } else {
                        let t = low.megolm().decrypt(chat_id, enc).await.ok().flatten();
                        let was_enc = t.is_none();
                        if was_enc {
                            missing.push(dto.message_id);
                        }
                        (t, true)
                    }
                }
                None => (None, false),
            };

            result.push(Message {
                id: dto.message_id,
                chat_id: dto.chat_id,
                author: User::unknown(dto.author_id),
                author_session_id: dto.author_session_id,
                text,
                encrypted: was_encrypted,
                encrypted_payload: encrypted,
                thread_id: dto.thread_id,
                created_at: dto.created_at,
                edited_at: dto.edited_at,
                deleted: dto.deleted,
                reactions: dto
                    .reactions
                    .into_iter()
                    .map(|r| Reaction { emoji: r.emoji, user_ids: r.user_ids, count: r.count })
                    .collect(),
            });
        }

        if !missing.is_empty() {
            let mut st = self.inner.state.write().await;
            for mid in &missing {
                st.push_pending_decrypt(chat_id, *mid);
            }
        }

        Ok(result)
    }

    pub async fn request_missing_keys(&self) -> Result<(usize, u32)> {
        let chat_id = self.id();
        let low = self.inner.low.clone();

        let pending = {
            let st = self.inner.state.read().await;
            st.pending_decrypt_for(chat_id)
        };
        if pending.is_empty() {
            return Ok((0, 0));
        }

        let our_uid = low.user_id();
        let our_sid = low.session_id();
        let created_by = self.inner.group.created_by;

        let mut query_uids: Vec<i64> = vec![our_uid];
        if created_by != 0 && created_by != our_uid {
            query_uids.push(created_by);
        }
        let all_sessions = low.keys().query(query_uids.clone()).await?;

        let mut candidates: Vec<(i64, i64)> = Vec::new();
        if let Some(sess) = all_sessions.get(&our_uid) {
            for sid in sess.keys() {
                if *sid != our_sid {
                    candidates.push((our_uid, *sid));
                }
            }
        }
        if created_by != 0 && created_by != our_uid {
            if let Some(sess) = all_sessions.get(&created_by) {
                for sid in sess.keys() {
                    candidates.push((created_by, *sid));
                }
            }
        }

        let mut last_err: Option<LockNetError> = None;
        let mut imported_total = 0u32;
        let mut any_done = false;

        for (target_uid, target_sid) in candidates {
            let mut high_rx = self.inner.high_event_tx.subscribe();

            let txid = match low
                .key_sharing()
                .send_request_only(target_uid, target_sid, vec![chat_id])
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };

            let mut session_imported = 0u32;
            let mut session_done = false;
            let mut denied_reason: Option<String> = None;

            let deadline = tokio::time::Instant::now() + KEY_REQUEST_TIMEOUT;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    last_err = Some(LockNetError::Timeout(KEY_REQUEST_TIMEOUT));
                    break;
                }
                match tokio::time::timeout(remaining, high_rx.recv()).await {
                    Ok(Ok(HighEvent::KeyRequestImported { txid: t, .. })) if t == txid => {
                        session_imported += 1;
                    }
                    Ok(Ok(HighEvent::KeyRequestDone { txid: t, total_imported })) if t == txid => {
                        session_imported = total_imported;
                        session_done = true;
                        break;
                    }
                    Ok(Ok(HighEvent::KeyRequestDenied { txid: t, reason })) if t == txid => {
                        denied_reason = Some(reason);
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    Ok(Err(_)) => {
                        last_err = Some(LockNetError::RunnerDown);
                        break;
                    }
                    Err(_) => {
                        last_err = Some(LockNetError::Timeout(KEY_REQUEST_TIMEOUT));
                        break;
                    }
                }
            }

            if session_done && session_imported > 0 {
                imported_total += session_imported;
                any_done = true;
                break;
            }
            if let Some(r) = denied_reason {
                last_err = Some(LockNetError::Server {
                    code: "key_denied".into(),
                    message: r,
                });
            }
        }

        {
            let mut st = self.inner.state.write().await;
            st.clear_pending_decrypt(chat_id);
        }

        if !any_done && imported_total == 0 {
            if let Some(e) = last_err {
                return Err(e);
            }
        }

        Ok((pending.len(), imported_total))
    }

    pub async fn edit(&self, message_id: i64, new_text: impl Into<String>) -> Result<()> {
        let chat_id = self.id();
        let low = self.inner.low.clone();
        let new_text = new_text.into();
        let encrypted = if self.is_encrypted() {
            self.ensure_policy_known().await?;
            low.megolm().ensure_session(chat_id).await?;
            low.megolm().encrypt(chat_id, &new_text).await?
        } else {
            Encrypted {
                algorithm: PLAINTEXT_ALGORITHM.into(),
                sender_key: String::new(),
                sender_session_id: low.session_id(),
                megolm_session_id: String::new(),
                ciphertext: base64_encode(new_text.as_bytes()),
            }
        };
        low.messages().edit(message_id, encrypted).await
    }

    pub async fn delete(&self, message_id: i64) -> Result<()> {
        self.inner.low.messages().delete(message_id).await
    }

    pub async fn add_reaction(&self, message_id: i64, emoji: impl Into<String>) -> Result<()> {
        self.inner.low.messages().add_reaction(message_id, emoji).await
    }

    pub async fn remove_reaction(&self, message_id: i64, emoji: impl Into<String>) -> Result<()> {
        self.inner.low.messages().remove_reaction(message_id, emoji).await
    }
}

impl std::fmt::Debug for Chat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chat")
            .field("id", &self.inner.group.id)
            .field("name", &self.inner.group.name)
            .finish()
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode_str(s: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    String::from_utf8(bytes).ok()
}