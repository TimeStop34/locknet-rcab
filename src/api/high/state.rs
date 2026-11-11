//! Internal cache and per-connection state for [`crate::LockNetAgent`].
//!
//! Tracks chats, users, invites, messages, verified sessions, pending
//! decryptions, active flows (SAS, QR), and the Web-of-Trust cache. All
//! access goes through the agent's `RwLock<ClientState>`.

use super::models::chat::PLAINTEXT_ALGORITHM;
use super::models::{Group, GroupMember, Invite, Message, Reaction, User};
use crate::api::high::verification::qr::QrFlow;
use crate::api::high::verification::sas::SasFlow;
use crate::api::low::models as low_models;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// A pending SAS start from another session, waiting for
/// [`crate::LockNetAgent`]'s user to accept or decline.
#[derive(Debug, Clone)]
pub(crate) struct PendingSasStart {
    /// The user who sent the start, if resolvable from cache. `None` means we
    /// will try to resolve it during `sas_accept`.
    pub from_user: Option<i64>,
    /// The session that sent the start.
    pub from_session: i64,
}

pub(crate) struct ClientState {
    #[allow(dead_code)]
    pub user_id: i64,
    #[allow(dead_code)]
    pub session_id: i64,
    pub groups: HashMap<i64, Group>,
    pub users: HashMap<i64, User>,
    pub invites: HashMap<i64, Invite>,
    pub messages: HashMap<i64, Message>,
    pub verified_users: HashSet<i64>,
    pub verified_sessions: HashMap<i64, i64>,
    pub pending_decrypt: HashMap<i64, Vec<i64>>,
    pub active_sas: HashMap<String, Arc<Mutex<SasFlow>>>,
    pub pending_sas_starts: HashMap<String, PendingSasStart>,
    pub active_qr: HashMap<String, Arc<Mutex<QrFlow>>>,
    pub reachable_users: Option<HashSet<i64>>,
}

impl ClientState {
    pub fn new(user_id: i64, session_id: i64) -> Self {
        Self {
            user_id,
            session_id,
            groups: HashMap::new(),
            users: HashMap::new(),
            invites: HashMap::new(),
            messages: HashMap::new(),
            verified_users: HashSet::new(),
            verified_sessions: HashMap::new(),
            pending_decrypt: HashMap::new(),
            active_sas: HashMap::new(),
            pending_sas_starts: HashMap::new(),
            active_qr: HashMap::new(),
            reachable_users: None,
        }
    }

    /// Resolve a user by ID, inserting a placeholder [`User::unknown`] if
    /// not cached.
    pub fn resolve_user(&mut self, user_id: i64) -> User {
        if !self.users.contains_key(&user_id) {
            // New user discovered — the cached reachable-set was built from
            // a smaller candidate list and may miss trust edges involving
            // this user.
            self.reachable_users = None;
        }
        self.users
            .entry(user_id)
            .or_insert_with(|| User::unknown(user_id))
            .clone()
    }

    /// Convert a wire [`low_models::Group`] into a domain [`Group`].
    ///
    /// If the server sends an `encrypted_group_data` blob newer than the
    /// locally cached one, it is decrypted, anti-replay-checked, and stored.
    /// Policy resolution may fail (missing key) — in that case,
    /// [`Group::group_data`] stays `None` and safe defaults apply.
    pub async fn group_to_domain(
        &mut self,
        dto: &low_models::Group,
        low: &Arc<crate::api::low::agent::LockNetLowAgent>,
    ) -> Group {
        use crate::core::crypto::group_data::decrypt_group_data;

        let mut local_state = low.store().group_data_state(dto.id).await;

        if let (Some(state), Some(blob)) = (local_state.as_ref(), dto.encrypted_group_data.as_ref())
        {
            if let Ok(server_data) = decrypt_group_data(blob, &state.key) {
                if server_data.version > state.data.version {
                    tracing::info!(
                        chat_id = dto.id,
                        from = state.data.version,
                        to = server_data.version,
                        "group_data updated from server"
                    );
                    let new_state = crate::core::policies::GroupDataState {
                        key: state.key,
                        data: server_data,
                        blob: blob.clone(),
                    };
                    low.store()
                        .group_data_state_put(dto.id, new_state.clone())
                        .await;
                    local_state = Some(new_state);
                } else if server_data.version < state.data.version {
                    tracing::warn!(
                        chat_id = dto.id,
                        incoming = server_data.version,
                        current = state.data.version,
                        "group_data version downgrade from server, ignoring"
                    );
                }
            }
        }

        let members = dto
            .members
            .as_ref()
            .map(|list| {
                list.iter()
                    .map(|m| GroupMember {
                        user: self.resolve_user(m.user_id),
                        is_mod: m.is_mod,
                        joined_at: dto.updated_at,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Group {
            id: dto.id,
            public_id: dto.public_id.clone(),
            name: dto.name.clone(),
            is_public: dto.is_public,
            created_by: dto.created_by,
            created_at: dto.created_at,
            updated_at: dto.updated_at,
            members,
            member_count: dto.member_count,
            encrypted_group_data: dto.encrypted_group_data.clone(),
            group_data: local_state.map(|s| s.data),
        }
    }

    /// Convert a wire [`low_models::Message`] into a domain [`Message`].
    #[allow(dead_code)]
    pub fn message_to_domain(
        &mut self,
        dto: &low_models::Message,
        text: Option<String>,
    ) -> Message {
        Message {
            id: dto.message_id,
            chat_id: dto.chat_id,
            author: self.resolve_user(dto.author_id),
            author_session_id: dto.author_session_id,
            text,
            encrypted: dto
                .encrypted
                .as_ref()
                .map(|e| e.algorithm != PLAINTEXT_ALGORITHM)
                .unwrap_or(false),
            encrypted_payload: dto.encrypted.clone(),
            thread_id: dto.thread_id,
            created_at: dto.created_at,
            edited_at: dto.edited_at,
            deleted: dto.deleted,
            reactions: dto
                .reactions
                .iter()
                .map(|r| Reaction {
                    emoji: r.emoji.clone(),
                    user_ids: r.user_ids.clone(),
                    count: r.count,
                })
                .collect(),
        }
    }

    /// Convert a wire [`low_models::MessageCreate`] (new message push) into a
    /// domain [`Message`].
    pub fn message_create_to_domain(
        &mut self,
        dto: &low_models::MessageCreate,
        text: Option<String>,
    ) -> Message {
        Message {
            id: dto.message_id,
            chat_id: dto.chat_id,
            author: self.resolve_user(dto.author_id),
            author_session_id: dto.author_session_id,
            text,
            encrypted: dto.encrypted.algorithm != PLAINTEXT_ALGORITHM,
            encrypted_payload: Some(dto.encrypted.clone()),
            thread_id: dto.thread_id,
            created_at: dto.created_at,
            edited_at: dto.edited_at,
            deleted: false,
            reactions: dto
                .reactions
                .iter()
                .map(|r| Reaction {
                    emoji: r.emoji.clone(),
                    user_ids: r.user_ids.clone(),
                    count: r.count,
                })
                .collect(),
        }
    }

    /// Convert a wire [`low_models::Invite`] into a domain [`Invite`].
    ///
    /// Uses the cached [`Group`] if available; otherwise builds a minimal
    /// placeholder group with only the metadata from the invite.
    pub fn invite_to_domain(&mut self, dto: &low_models::Invite) -> Invite {
        let group = self
            .groups
            .get(&dto.group_id)
            .cloned()
            .unwrap_or_else(|| Group {
                id: dto.group_id,
                public_id: None,
                name: dto.group_name.clone(),
                is_public: false,
                created_by: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                members: Vec::new(),
                member_count: 0,
                encrypted_group_data: None,
                group_data: None,
            });
        let inviter = self.resolve_user(dto.inviter_id);
        Invite {
            id: dto.id,
            group,
            inviter,
            created_at: dto.created_at,
        }
    }

    /// Convert a wire [`low_models::GroupInviteCreated`] (push) into a
    /// domain [`Invite`].
    pub fn invite_from_push(&mut self, dto: &low_models::GroupInviteCreated) -> Invite {
        let group = self
            .groups
            .get(&dto.group_id)
            .cloned()
            .unwrap_or_else(|| Group {
                id: dto.group_id,
                public_id: None,
                name: dto.group_name.clone(),
                is_public: false,
                created_by: 0,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                members: Vec::new(),
                member_count: 0,
                encrypted_group_data: None,
                group_data: None,
            });
        let inviter = self.resolve_user(dto.inviter_id);
        Invite {
            id: dto.invite_id,
            group,
            inviter,
            created_at: dto.created_at,
        }
    }

    /// Mark `message_id` as pending decryption in `chat_id`.
    pub fn push_pending_decrypt(&mut self, chat_id: i64, message_id: i64) {
        let list = self.pending_decrypt.entry(chat_id).or_default();
        if !list.contains(&message_id) {
            list.push(message_id);
        }
    }

    /// All message IDs pending decryption in `chat_id`.
    pub fn pending_decrypt_for(&self, chat_id: i64) -> Vec<i64> {
        self.pending_decrypt
            .get(&chat_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Clear the pending-decryption list for `chat_id`.
    pub fn clear_pending_decrypt(&mut self, chat_id: i64) {
        self.pending_decrypt.remove(&chat_id);
    }

    /// Retain only those pending message IDs for which `keep(mid) == true`.
    /// Removes the entry entirely if the list becomes empty.
    pub fn retain_pending_decrypt<F: Fn(i64) -> bool>(&mut self, chat_id: i64, keep: F) {
        if let Some(list) = self.pending_decrypt.get_mut(&chat_id) {
            list.retain(|mid| keep(*mid));
            if list.is_empty() {
                self.pending_decrypt.remove(&chat_id);
            }
        }
    }

    #[allow(dead_code)]
    pub fn chat_created_by(&self, chat_id: i64) -> Option<i64> {
        self.groups.get(&chat_id).map(|g| g.created_by)
    }

    /// Invalidate the Web-of-Trust cache. The next
    /// [`crate::SecurityHelper::is_user_verified`] call will rebuild the graph.
    pub fn invalidate_trust_graph(&mut self) {
        self.reachable_users = None;
    }

    /// Cached set of users reachable via the Web of Trust, if computed.
    pub fn cached_reachable(&self) -> Option<&HashSet<i64>> {
        self.reachable_users.as_ref()
    }

    /// Store the computed reachable set.
    pub fn set_reachable(&mut self, set: HashSet<i64>) {
        self.reachable_users = Some(set);
    }
}
