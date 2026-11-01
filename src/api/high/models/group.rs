use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub user: User,
    pub is_mod: bool,
    pub joined_at: DateTime<Utc>,
}

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
}

impl Group {
    pub fn is_direct(&self) -> bool {
        !self.is_public && self.public_id.is_none() && self.member_count == 2
    }
}