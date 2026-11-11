//! Groups (chats) and their members.

use super::user::User;
use crate::core::policies::{GroupData, HistoryVisibility, MegolmRotationVisibility};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A group member with their resolved [`User`] and membership metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Resolved user.
    pub user: User,
    /// Whether this member is a moderator.
    pub is_mod: bool,
    /// When the member joined (approximated by the last group update).
    pub joined_at: DateTime<Utc>,
}

/// A group (chat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group ID (snowflake).
    pub id: i64,
    /// Public handle, `None` for private groups.
    pub public_id: Option<String>,
    /// Group name.
    pub name: String,
    /// Whether the group is public.
    pub is_public: bool,
    /// Creator's user ID.
    pub created_by: i64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
    /// Member list. Empty if the caller is not a member.
    pub members: Vec<GroupMember>,
    /// Number of members.
    pub member_count: usize,

    /// Opaque encrypted policy blob, as received from the server.
    pub encrypted_group_data: Option<String>,

    /// Decrypted policies. `None` if we have not yet received a
    /// `group_data_key` for this group (e.g. brand-new device before
    /// `key_request`).
    pub group_data: Option<GroupData>,
}

impl Group {
    /// Whether this is a 1-to-1 chat.
    ///
    /// A group is considered direct if it is private, has no `public_id`,
    /// and has exactly two members.
    pub fn is_direct(&self) -> bool {
        !self.is_public && self.public_id.is_none() && self.member_count == 2
    }

    /// Effective [`HistoryVisibility`] policy.
    ///
    /// Falls back to [`HistoryVisibility::AfterJoin`] if [`Self::group_data`]
    /// is not available — the most restrictive option.
    pub fn history_visibility(&self) -> HistoryVisibility {
        self.group_data
            .as_ref()
            .map(|d| d.history_visibility)
            .unwrap_or(HistoryVisibility::AfterJoin)
    }

    /// Effective [`MegolmRotationVisibility`] policy.
    ///
    /// Falls back to [`MegolmRotationVisibility::OnlyVerifiedUsers`] if
    /// [`Self::group_data`] is not available.
    pub fn megolm_rotation_visibility(&self) -> MegolmRotationVisibility {
        self.group_data
            .as_ref()
            .map(|d| d.megolm_rotation_visibility)
            .unwrap_or(MegolmRotationVisibility::OnlyVerifiedUsers)
    }
}
