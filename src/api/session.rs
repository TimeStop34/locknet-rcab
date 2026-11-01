use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct LockNetSessionContext {
    pub user_id: i64,
    pub session_id: i64,
    pub ajwt: String,
    pub rjwt: String,
    pub rtime: DateTime<Utc>,
    pub space: String,
    pub vname: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Credentials {
    Login { username: String, password: String },
    Register { username: String, password: String, display_name: Option<String> },
    Session { refresh_jwt: String },
}