use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub type SignaturesMap = HashMap<String, HashMap<String, String>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeys {
    pub curve25519_key: String,
    pub ed25519_key: String,
    pub one_time_keys: HashMap<String, String>,
    pub signatures: SignaturesMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtkCounts { pub one_time_key_counts: HashMap<String, u64> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity { pub curve25519_key: String, pub ed25519_key: String }

pub type QueryKeysResult = HashMap<i64, HashMap<i64, DeviceIdentity>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Otk { pub key_id: String, pub key: String }