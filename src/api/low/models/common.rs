use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted {
    pub algorithm: String,
    pub sender_key: String,
    pub sender_session_id: i64,
    pub megolm_session_id: String,
    pub ciphertext: String,
}