//! Cross-signing wire types.
//!
//! All public keys are base64 (unpadded). Signature maps are shaped
//! `{"<signer_user_id>": {"<purpose>": "<base64_sig>"}}`, where `purpose` is
//! `"master"` (MSK signs SSK/USK) or `"user_signing"` (USK signs another
//! user's MSK) or `"self_signing"` (SSK signs a device ed25519).

use super::keys::SignaturesMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One cross-signing public key with its signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningKey {
    /// Base64-encoded Ed25519 public key.
    pub key: String,
    /// Signatures on this key from other cross-signing keys.
    pub signatures: SignaturesMap,
}

/// The three public cross-signing keys of a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningKeys {
    /// Master signing key (root of trust).
    pub master_key: CrossSigningKey,
    /// Self-signing key (signs this user's own device ed25519 keys).
    pub self_signing_key: CrossSigningKey,
    /// User-signing key (signs other users' MSKs).
    pub user_signing_key: CrossSigningKey,
}

/// Signatures to upload via `upload_signatures`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signatures {
    /// `target_user_id → base64_sig` — your USK signing another user's MSK.
    pub user_signatures: HashMap<i64, String>,
    /// `target_session_id → base64_sig` — your SSK signing your own device.
    pub device_signatures: HashMap<i64, String>,
}

/// Result of `upload_signatures`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturesAck {
    /// Number of target MSKs updated.
    pub users_updated: usize,
    /// Number of target sessions updated.
    pub devices_updated: usize,
}

/// One device as returned by `query_cross_signing_keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningDevice {
    /// Device's Ed25519 identity key.
    pub ed25519_key: String,
    /// Device's Curve25519 identity key, if uploaded.
    #[serde(default)]
    pub curve25519_key: Option<String>,
    /// Signatures on the device's ed25519 key.
    pub signatures: SignaturesMap,
}

/// One user's cross-signing entry in a `query_cross_signing_keys` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningUser {
    /// User's master signing key (always present if the user has any CS keys).
    pub master_key: CrossSigningKey,
    /// Self-signing key, if uploaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_signing_key: Option<CrossSigningKey>,
    /// User-signing key, if uploaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_signing_key: Option<CrossSigningKey>,
    /// `session_id → device` for active sessions that have uploaded
    /// identity keys.
    pub devices: HashMap<i64, CrossSigningDevice>,
}

/// Result of `query_cross_signing_keys`: `user_id → CrossSigningUser`.
///
/// Users with no cross-signing keys are absent from the map.
pub type CrossSigningQuery = HashMap<i64, CrossSigningUser>;

/// Result of `reset_cross_signing_keys`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetResult {
    /// Users whose view of this user's trust is now stale and who were
    /// notified via `cross_signing_reset`.
    pub affected_users: Vec<i64>,
}

/// Payload of a `cross_signing_signature_added` event.
///
/// Emitted by the server to a target user when another user signs their
/// MSK with their USK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningSignatureAdded {
    /// User who added the signature.
    pub signer_user_id: i64,
    /// Key type of the signer (`"user_signing"` for MSK targets).
    pub key_type: String,
    /// What was signed (`"master"`).
    pub target: String,
    /// Base64-encoded Ed25519 signature.
    pub signature: String,
}

/// Payload of a `cross_signing_reset` event.
///
/// Emitted to users whose USK signature on a reset user's MSK is now invalid,
/// or who previously verified the reset user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossSigningReset {
    /// User whose cross-signing keys were reset.
    pub user_id: i64,
}
