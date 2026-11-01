use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::models::Encrypted;
use crate::core::crypto::megolm::MEGOLM_ALGORITHM;
use crate::core::errors::Result;

use super::group::Group;
use super::message::Message;
use super::reaction::Reaction;
use super::user::User;

pub(crate) const PLAINTEXT_ALGORITHM: &str = "ln.plaintext.v1";

pub(crate) struct ChatInner {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) group: Group,
}

#[derive(Clone)]
pub struct Chat {
    pub(crate) inner: Arc<ChatInner>,
}

impl Chat {
    pub(crate) fn new(low: Arc<LockNetLowAgent>, group: Group) -> Self {
        Self {
            inner: Arc::new(ChatInner { low, group }),
        }
    }

    pub fn id(&self) -> i64 {
        self.inner.group.id
    }

    pub fn name(&self) -> String {
        self.inner.group.name.clone()
    }

    pub fn is_public(&self) -> bool {
        self.inner.group.is_public
    }

    pub fn is_direct(&self) -> bool {
        self.inner.group.is_direct()
    }

    pub fn is_encrypted(&self) -> bool {
        !self.inner.group.is_public
    }

    pub fn public_id(&self) -> Option<String> {
        self.inner.group.public_id.clone()
    }

    pub fn created_by(&self) -> i64 {
        self.inner.group.created_by
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.inner.group.created_at
    }

    pub fn members(&self) -> Vec<User> {
        self.inner.group.members.iter().map(|m| m.user.clone()).collect()
    }

    pub fn member_count(&self) -> usize {
        self.inner.group.member_count
    }

    pub fn group(&self) -> &Group {
        &self.inner.group
    }

    pub async fn refresh(&self) -> Result<Group> {
        self.inner.low.groups().info(self.id()).await
    }

    pub async fn send(&self, text: impl Into<String>) -> Result<Message> {
        let text = text.into();
        let chat_id = self.id();
        let low = self.inner.low.clone();

        let encrypted = if self.is_encrypted() {
            low.megolm().ensure_session(chat_id).await?;
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
        for dto in page.messages {
            let encrypted = dto.encrypted.clone();
            let text = match &encrypted {
                Some(enc) => {
                    if enc.algorithm == PLAINTEXT_ALGORITHM {
                        base64_decode_str(&enc.ciphertext)
                    } else {
                        low.megolm().decrypt(chat_id, enc).await.ok().flatten()
                    }
                }
                None => None,
            };

            result.push(Message {
                id: dto.message_id,
                chat_id: dto.chat_id,
                author: User::unknown(dto.author_id),
                author_session_id: dto.author_session_id,
                text,
                encrypted: encrypted.is_some(),
                encrypted_payload: encrypted,
                thread_id: dto.thread_id,
                created_at: dto.created_at,
                edited_at: dto.edited_at,
                deleted: dto.deleted,
                reactions: dto
                    .reactions
                    .into_iter()
                    .map(|r| Reaction {
                        emoji: r.emoji,
                        user_ids: r.user_ids,
                        count: r.count,
                    })
                    .collect(),
            });
        }
        Ok(result)
    }

    pub async fn edit(&self, message_id: i64, new_text: impl Into<String>) -> Result<()> {
        let chat_id = self.id();
        let low = self.inner.low.clone();
        let new_text = new_text.into();

        let encrypted = if self.is_encrypted() {
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