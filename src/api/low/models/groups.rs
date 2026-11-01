use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberInfo { pub user_id: i64, pub is_mod: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: i64,
    pub public_id: Option<String>,
    pub name: String,
    pub is_public: bool,
    pub created_by: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub members: Option<Vec<GroupMemberInfo>>,
    pub member_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite { pub id: i64, pub group_id: i64, pub group_name: String, pub inviter_id: i64, pub created_at: Option<DateTime<Utc>> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreated { pub group: Group }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInviteCreated { pub invite_id: i64, pub group_id: i64, pub group_name: String, pub inviter_id: i64, pub created_at: Option<DateTime<Utc>> }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MembershipChange { Added, Left }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembershipChanged { pub group_id: i64, pub change: MembershipChange, pub user_id: i64 }