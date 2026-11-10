//! Cross-signing and `send_to_device` helper.

use serde_json::json;
use crate::api::low::command::{dispatch, dispatch_unit, CmdSender};
use crate::api::low::models::*;
use crate::core::errors::Result;

/// Wraps the `/api/v1/crypto` WebSocket methods.
///
/// Obtained via [`crate::LockNetLowAgent::crypto`]. Most applications should
/// use [`crate::SecurityHelper`] instead, which orchestrates these calls
/// together with the local [`crate::CryptoStore`].
pub struct LockNetCryptoHelper { pub(crate) cmd_tx: CmdSender }

impl LockNetCryptoHelper {
    /// Upload the user's cross-signing keys (MSK, SSK, USK).
    ///
    /// Can only be called once per account. The server validates that SSK
    /// and USK are signed by MSK. To replace keys, call
    /// [`Self::reset_cross_signing_keys`] first.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `cross_signing_already_exists`
    ///   if keys were already uploaded.
    /// - [`crate::LockNetError::Server`] with code `invalid_signature` if the SSK or
    ///   USK signatures do not verify against MSK.
    pub async fn upload_cross_signing_keys(&self, keys: CrossSigningKeys) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({
            "type": "upload_cross_signing_keys",
            "data": { "master_key": keys.master_key, "self_signing_key": keys.self_signing_key, "user_signing_key": keys.user_signing_key }
        })).await
    }

    /// Upload USK and SSK signatures.
    ///
    /// - `user_signatures` — your USK signing another user's MSK. Marks that
    ///   user as trusted (Web of Trust edge).
    /// - `device_signatures` — your SSK signing your own sessions' `ed25519`
    ///   keys.
    ///
    /// The server verifies each signature and emits a
    /// `cross_signing_signature_added` event to the target.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `not_found` if a target MSK or
    ///   session does not exist.
    /// - [`crate::LockNetError::Server`] with code `unauthorized` if trying to sign
    ///   another user's session with your SSK.
    /// - [`crate::LockNetError::Server`] with code `invalid_signature`.
    pub async fn upload_signatures(&self, signatures: Signatures) -> Result<SignaturesAck> {
        dispatch(&self.cmd_tx, json!({
            "type": "upload_signatures",
            "data": { "user_signatures": signatures.user_signatures, "device_signatures": signatures.device_signatures }
        })).await
    }

    /// Query cross-signing keys and signatures for the given users.
    ///
    /// Users who have not uploaded cross-signing keys are absent from the
    /// result.
    pub async fn query_cross_signing_keys(&self, user_ids: Vec<i64>) -> Result<CrossSigningQuery> {
        dispatch(&self.cmd_tx, json!({ "type": "query_cross_signing_keys", "data": { "user_ids": user_ids } })).await
    }

    /// Reset the user's cross-signing keys.
    ///
    /// Requires the account password (UIA). After this call:
    /// - Your MSK, SSK, USK are removed from the server.
    /// - Your USK signatures on other users' MSKs are removed.
    /// - Your SSK signatures on your own sessions are removed.
    /// - Other users who signed your MSK receive `cross_signing_reset`.
    ///
    /// The returned [`ResetResult::affected_users`] lists those notified
    /// users; they will need to re-verify you.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `invalid_password`.
    pub async fn reset_cross_signing_keys(&self, password: impl Into<String>) -> Result<ResetResult> {
        dispatch(&self.cmd_tx, json!({ "type": "reset_cross_signing_keys", "data": { "password": password.into() } })).await
    }

    /// Send encrypted payloads to specific devices.
    ///
    /// `messages` maps `user_id → session_id → OlmPayload`. The server
    /// delivers each payload to the target device if the session belongs to
    /// that user and is still active; otherwise the entry is counted as
    /// `dropped` in the result.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Timeout`] if the request times out.
    pub async fn send_to_device(&self, messages: ToDeviceMessages) -> Result<ToDeviceAck> {
        dispatch(&self.cmd_tx, json!({ "type": "send_to_device", "data": { "messages": messages } })).await
    }
}