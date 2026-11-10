//! Device keys and one-time keys helper.

use serde_json::json;
use crate::api::low::command::{dispatch, CmdSender};
use crate::api::low::models::*;
use crate::core::errors::Result;

/// Wraps the `/api/v1/keys` WebSocket methods.
///
/// Obtained via [`crate::LockNetLowAgent::keys`].
pub struct LockNetKeysHelper { pub(crate) cmd_tx: CmdSender }

impl LockNetKeysHelper {
    /// Upload device identity keys and one-time keys.
    ///
    /// The server stores `curve25519_key` and `ed25519_key` on the session
    /// and appends the OTKs to the per-session OTK pool (existing key IDs are
    /// preserved; uploading the same ID twice is a no-op).
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Timeout`] if the request times out.
    pub async fn upload(&self, keys: DeviceKeys) -> Result<OtkCounts> {
        dispatch(&self.cmd_tx, json!({ "type": "upload_keys", "data": keys })).await
    }

    /// Query identity keys for the given users.
    ///
    /// Returns a map `user_id → session_id → DeviceIdentity`. Only sessions
    /// that have uploaded both `curve25519_key` and `ed25519_key` are
    /// included; users without such sessions are absent from the result.
    pub async fn query(&self, user_ids: Vec<i64>) -> Result<QueryKeysResult> {
        dispatch(&self.cmd_tx, json!({ "type": "query_keys", "data": { "user_ids": user_ids } })).await
    }

    /// Atomically claim one one-time key from a specific session.
    ///
    /// The key is removed from the server pool, so each call returns a
    /// distinct key. Used to bootstrap new outbound Olm sessions.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `session_not_found` if
    ///   `session_id` does not belong to `user_id`.
    /// - [`crate::LockNetError::Server`] with code `no_one_time_keys` if the
    ///   session has no remaining keys for `algorithm` (defaults to
    ///   `"curve25519"`).
    pub async fn claim_one_time_key(&self, user_id: i64, session_id: i64, algorithm: Option<String>) -> Result<Otk> {
        dispatch(&self.cmd_tx, json!({
            "type": "claim_one_time_key",
            "data": { "user_id": user_id, "session_id": session_id, "algorithm": algorithm.unwrap_or_else(|| "curve25519".to_string()) }
        })).await
    }
}