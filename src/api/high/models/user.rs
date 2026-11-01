use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: i64,
    pub ed25519_key: Option<String>,
    pub curve25519_key: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub is_bot: bool,
    pub verified: bool,
    pub sessions: Vec<SessionInfo>,
}

impl User {
    pub fn unknown(id: i64) -> Self {
        Self {
            id,
            username: "unknown".into(),
            display_name: None,
            avatar_url: None,
            is_bot: false,
            verified: false,
            sessions: Vec::new(),
        }
    }

    pub fn display(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.username)
    }
}