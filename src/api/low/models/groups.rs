//! Groups, members, invitations, and group-related events.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One member of a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberInfo {
    /// Member's user ID.
    pub user_id: i64,
    /// Whether this member is a moderator.
    pub is_mod: bool,
}

/// A group (chat).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group ID (snowflake).
    pub id: i64,
    /// Human-readable handle, required for public groups, `None` for private.
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
    /// Member list. `None` when the caller is not a member and the group is
    /// public (only `member_count` is exposed).
    pub members: Option<Vec<GroupMemberInfo>>,
    /// Number of members.
    pub member_count: usize,
    /// Opaque encrypted policy blob. Decryptable only by group members who
    /// hold the `group_data_key` (delivered via `ln.encryption.group_key`).
    /// The server stores and forwards it without validating its contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_group_data: Option<String>,
}

/// One pending invitation, as returned by `get_invites`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Invite ID (used to accept/decline).
    pub id: i64,
    /// Group being joined.
    pub group_id: i64,
    /// Group name (denormalized for convenience).
    pub group_name: String,
    /// User who sent the invite.
    pub inviter_id: i64,
    /// When the invite was created.
    pub created_at: Option<DateTime<Utc>>,
}

/// Payload of a `group_created` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreated {
    /// The created group.
    pub group: Group,
}

/// Payload of a `group_invite_created` event.
///
/// Delivered to a user who has been invited to a group (through
/// `create_group` / `create_direct`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInviteCreated {
    /// Invite ID (used to accept/decline).
    pub invite_id: i64,
    /// Group being joined.
    pub group_id: i64,
    /// Group name.
    pub group_name: String,
    /// User who sent the invite.
    pub inviter_id: i64,
    /// When the invite was created.
    pub created_at: Option<DateTime<Utc>>,
}

/// Direction of a membership change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MembershipChange {
    /// A user joined the group (accepted invite or `join_group`).
    Added,
    /// A user left the group.
    Left,
}

/// Payload of a `group_membership_changed` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembershipChanged {
    /// Group whose membership changed.
    pub group_id: i64,
    /// Whether someone joined or left.
    pub change: MembershipChange,
    /// User whose membership changed.
    pub user_id: i64,
}
