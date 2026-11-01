use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::api::low::helpers::verification::sas::SasFlow;
use crate::api::low::models as low_models;

use super::models::{Group, GroupMember, Invite, Message, Reaction, User};

pub(crate) struct ClientState {
    pub user_id: i64,
    pub session_id: i64,
    pub groups: HashMap<i64, Group>,
    pub users: HashMap<i64, User>,
    pub invites: HashMap<i64, Invite>,
    pub messages: HashMap<i64, Message>,
    pub verified_users: HashSet<i64>,
    pub verified_sessions: HashSet<i64>,
    pub pending_decrypt: HashMap<i64, Vec<i64>>,
    pub active_sas: HashMap<String, Arc<Mutex<SasFlow>>>,
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
            verified_sessions: HashSet::new(),
            pending_decrypt: HashMap::new(),
            active_sas: HashMap::new(),
        }
    }

    pub fn resolve_user(&mut self, user_id: i64) -> User {
        self.users
            .entry(user_id)
            .or_insert_with(|| User::unknown(user_id))
            .clone()
    }

    pub fn group_to_domain(&mut self, dto: &low_models::Group) -> Group {
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
        }
    }

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
            encrypted: dto.encrypted.is_some(),
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
            });
        let inviter = self.resolve_user(dto.inviter_id);
        Invite {
            id: dto.id,
            group,
            inviter,
            created_at: dto.created_at,
        }
    }
}