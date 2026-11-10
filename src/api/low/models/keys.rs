//! Device keys, one-time keys, and `query_keys` results.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// `{"<signer_user_id>": {"<signature_type>": "<base64_sig>"}}`.
pub type SignaturesMap = HashMap<String, HashMap<String, String>>;

/// Uploaded device identity keys plus one-time keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeys {
    /// Device's Curve25519 identity key (for Olm).
    pub curve25519_key: String,
    /// Device's Ed25519 identity key (for signatures).
    pub ed25519_key: String,
    /// One-time keys as `{"curve25519:<id>": "<key>"}`.
    pub one_time_keys: HashMap<String, String>,
    /// Optional self-signing signatures (from `setup_cross_signing`).
    pub signatures: SignaturesMap,
}

/// Result of `upload_keys`: remaining one-time key counts by algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtkCounts {
    /// Map `algorithm → remaining count`.
    pub one_time_key_counts: HashMap<String, u64>,
}

/// Identity keys of one device, as returned by `query_keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Device's Curve25519 identity key.
    pub curve25519_key: String,
    /// Device's Ed25519 identity key.
    pub ed25519_key: String,
}

/// Result of `query_keys`: `user_id → session_id → DeviceIdentity`.
pub type QueryKeysResult = HashMap<i64, HashMap<i64, DeviceIdentity>>;

/// A claimed one-time key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Otk {
    /// Key identifier (`"curve25519:<id>"`).
    pub key_id: String,
    /// Base64-encoded key bytes.
    pub key: String,
}