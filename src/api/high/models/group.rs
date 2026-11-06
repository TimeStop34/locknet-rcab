use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::core::policies::{GroupData, HistoryVisibility, MegolmRotationVisibility};
use super::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember { pub user: User, pub is_mod: bool, pub joined_at: DateTime<Utc> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: i64,
    pub public_id: Option<String>,
    pub name: String,
    pub is_public: bool,
    pub created_by: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub members: Vec<GroupMember>,
    pub member_count: usize,

    /// Что сервер прислал в `get_group_info` / `get_groups` / event.
    /// Не расшифровано, пока не сопоставим с локальным ключом.
    pub encrypted_group_data: Option<String>,

    /// Расшифрованные политики (если у нас есть `group_data_key`).
    /// `None` = ключа нет; используем safe default.
    pub group_data: Option<GroupData>,
}

impl Group {
    pub fn is_direct(&self) -> bool {
        !self.is_public && self.public_id.is_none() && self.member_count == 2
    }

    /// Политика видимости истории. Safe default при отсутствии ключа — `AfterJoin`.
    pub fn history_visibility(&self) -> HistoryVisibility {
        self.group_data
            .as_ref()
            .map(|d| d.history_visibility)
            .unwrap_or(HistoryVisibility::AfterJoin)
    }

    /// Политика ротации. Safe default при отсутствии ключа — `OnlyVerifiedUsers`.
    pub fn megolm_rotation_visibility(&self) -> MegolmRotationVisibility {
        self.group_data
            .as_ref()
            .map(|d| d.megolm_rotation_visibility)
            .unwrap_or(MegolmRotationVisibility::OnlyVerifiedUsers)
    }
}