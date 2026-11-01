use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersion { pub version: i32, pub algorithm: String, pub auth_data: serde_json::Value, pub created_at: Option<DateTime<Utc>> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersionData { pub version: i32, pub algorithm: String, pub auth_data: serde_json::Value, pub items: HashMap<String, serde_json::Value> }