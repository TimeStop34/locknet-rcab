//! Key backup wire types.
//!
//! Backup storage is a server-side key-value store: `versions` are named
//! buckets, each holding opaque encrypted `items`. The server never sees the
//! plaintext (or the recovery key); see
//! [`crate::api::low::helpers::LockNetBackupHelper`] for the encrypt/decrypt
//! flow.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One backup version as returned by `backup_versions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersion {
    /// Monotonic version number (1, 2, 3, …) per user.
    pub version: i32,
    /// Algorithm identifier, e.g. `"ln.encryption.backup.v1"`.
    pub algorithm: String,
    /// Server-stored, client-defined metadata. For `locknet-rcab` this
    /// contains `public_key` — a SHA-256 fingerprint of the derived backup
    /// secret, used to detect wrong recovery keys before decrypting items.
    pub auth_data: serde_json::Value,
    /// Creation timestamp, if the server recorded one.
    pub created_at: Option<DateTime<Utc>>,
}

/// A backup version together with all its items, as returned by
/// `backup_get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersionData {
    /// Version number.
    pub version: i32,
    /// Algorithm identifier.
    pub algorithm: String,
    /// Server-stored client metadata (see [`BackupVersion::auth_data`]).
    pub auth_data: serde_json::Value,
    /// Encrypted items, keyed by `"<chat_id>:<megolm_session_id>"`.
    ///
    /// Each value is an opaque JSON object (for `locknet-rcab`:
    /// `{"nonce": "<b64>", "ciphertext": "<b64>"}`).
    pub items: HashMap<String, serde_json::Value>,
}
