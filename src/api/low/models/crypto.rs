use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::keys::SignaturesMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningKey { pub key: String, pub signatures: SignaturesMap }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningKeys {
    pub master_key: CrossSigningKey,
    pub self_signing_key: CrossSigningKey,
    pub user_signing_key: CrossSigningKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signatures { pub user_signatures: HashMap<i64, String>, pub device_signatures: HashMap<i64, String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturesAck { pub users_updated: usize, pub devices_updated: usize }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningDevice {
    pub ed25519_key: String,
    #[serde(default)] pub curve25519_key: Option<String>,
    pub signatures: SignaturesMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningUser {
    pub master_key: CrossSigningKey,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub self_signing_key: Option<CrossSigningKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub user_signing_key: Option<CrossSigningKey>,
    pub devices: HashMap<i64, CrossSigningDevice>,
}

pub type CrossSigningQuery = HashMap<i64, CrossSigningUser>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetResult { pub affected_users: Vec<i64> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningSignatureAdded { pub signer_user_id: i64, pub key_type: String, pub target: String, pub signature: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningReset { pub user_id: i64 }