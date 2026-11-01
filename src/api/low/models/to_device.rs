use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDeviceCiphertext {
    #[serde(rename = "type")] pub ciphertext_type: u8,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDevicePayload {
    pub algorithm: String,
    pub sender_key: String,
    pub sender_session_id: i64,
    pub ciphertext: HashMap<String, ToDeviceCiphertext>,
}

pub type ToDeviceMessages = HashMap<i64, HashMap<i64, serde_json::Value>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToDeviceAck { pub accepted: usize, pub dropped: usize }