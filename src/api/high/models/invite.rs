use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::group::Group;
use super::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub id: i64,
    pub group: Group,
    pub inviter: User,
    pub created_at: Option<DateTime<Utc>>,
}