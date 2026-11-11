//! Security helper: Web of Trust, cross-signing, SAS/QR verification, key backup.
//!
//! [`SecurityHelper`] is the entry point for all trust-related operations on
//! [`crate::LockNetAgent`]. It orchestrates the low-level cryptographic flows
//! from [`crate::api::low::helpers`] with the agent's cache
//! (`crate::api::high::state::ClientState`) and updates the verified-sets
//! and Web-of-Trust graph on success.

use super::event::HighEvent;
use super::models::User;
use super::state::ClientState;
use crate::api::high::trust::TrustGraph;
use crate::api::high::verification::sas::{SasEmoji, SasFlow, SasStatus, SasStep};
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::helpers::backup::{BackupExportResult, BackupImportResult, RecoveryKey};
use crate::api::low::models::{
    BackupVersion, BackupVersionData, CrossSigningKey, CrossSigningKeys, Signatures,
};
use crate::core::crypto::signature::{sign_b64, verify_b64, CrossSigningKeysPrivate};
use crate::core::errors::{LockNetError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Trust and verification operations for a [`crate::LockNetAgent`].
///
/// Obtained via [`crate::LockNetAgent::security`].
///
/// Responsibilities:
///
/// - **Web of Trust** — [`Self::is_user_verified`] resolves transitive trust
///   via cross-signing signatures, with caching and invalidation on
///   signature-add / reset events.
/// - **Cross-signing** — [`Self::setup_cross_signing`] generates the user's
///   MSK/SSK/USK and uploads the public halves; [`Self::reset_cross_signing`]
///   wipes them.
/// - **SAS / QR verification** — drives the full flows from
///   [`crate::api::low::helpers::verification`] and, on success, updates the
///   verified-sets and invalidates the WoT cache.
/// - **Key backup** — wraps [`crate::api::low::helpers::backup`] for
///   exporting and importing Megolm history with a recovery key.
pub struct SecurityHelper {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) state: Arc<RwLock<ClientState>>,
    pub(crate) event_tx: broadcast::Sender<HighEvent>,
}

impl SecurityHelper {
    /// Check whether `user_id` is trusted via the Web of Trust.
    ///
    /// Trust is transitive: starting from our own `user_id` as the root, a
    /// user is trusted if there is a chain `us -> A -> B -> ... -> user_id`
    /// of USK-to-MSK signatures. `us` is always trusted.
    ///
    /// A direct signature counts as a chain of length 1.
    ///
    /// Results are cached in `state.reachable_users`; the cache is
    /// invalidated on [`HighEvent::CrossSigningReset`], on receipt of
    /// `cross_signing_signature_added`, and after successful SAS or QR
    /// verification.
    ///
    /// The trust graph is rebuilt from
    /// [`crate::api::low::helpers::LockNetCryptoHelper::query_cross_signing_keys`]
    /// on cache miss. Every edge is re-verified with Ed25519 — the server
    /// cannot forge trust.
    pub async fn is_user_verified(&self, user_id: i64) -> bool {
        if user_id == self.low.user_id() {
            return true;
        }

        // Fast path: local verified-set or cached reachable-set.
        {
            let st = self.state.read().await;
            if st.verified_users.contains(&user_id) {
                return true;
            }
            if let Some(set) = st.cached_reachable() {
                return set.contains(&user_id);
            }
        }

        // Slow path: rebuild the graph and BFS from us.
        let mut candidates: Vec<i64> = {
            let st = self.state.read().await;
            st.users.keys().copied().collect()
        };
        // Always include self and the target — the cache may be empty before
        // the first event.
        if !candidates.contains(&self.low.user_id()) {
            candidates.push(self.low.user_id());
        }
        if !candidates.contains(&user_id) {
            candidates.push(user_id);
        }

        let graph = match TrustGraph::build(&self.low, &candidates).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(?e, "trust graph build failed");
                return false;
            }
        };
        let reachable = graph.reachable_from(self.low.user_id());
        let contains = reachable.contains(&user_id);

        {
            let mut st = self.state.write().await;
            st.set_reachable(reachable);
        }

        contains
    }

    /// Check whether a specific session of `user_id` is verified.
    ///
    /// Session verification means the user's self-signing key (SSK) has
    /// signed the session's `ed25519` key. This is weaker than
    /// [`Self::is_user_verified`] (which requires WoT) but is the
    /// appropriate check for session-level operations like group key fan-out
    /// with [`crate::core::policies::MegolmRotationVisibility::OnlyVerifiedSessions`].
    ///
    /// The local verified-set is checked first; if the session is not there,
    /// the cross-signing keys are re-queried from the server and the SSK
    /// signature is re-verified.
    pub async fn is_session_verified(&self, user_id: i64, session_id: i64) -> bool {
        {
            let state = self.state.read().await;
            if state.verified_sessions.contains_key(&session_id) {
                return true;
            }
        }
        let query = match self
            .low
            .crypto()
            .query_cross_signing_keys(vec![user_id])
            .await
        {
            Ok(q) => q,
            Err(_) => return false,
        };
        let entry = match query.get(&user_id) {
            Some(e) => e,
            None => return false,
        };
        let ssk_pub = match entry.self_signing_key.as_ref() {
            Some(k) => k.key.clone(),
            None => return false,
        };
        let device = match entry.devices.get(&session_id) {
            Some(d) => d,
            None => return false,
        };
        let sig = match device
            .signatures
            .get(&user_id.to_string())
            .and_then(|m| m.get("self_signing"))
        {
            Some(s) => s.clone(),
            None => return false,
        };
        let ed = match &device.ed25519_key {
            s if s.is_empty() => return false,
            s => s.clone(),
        };
        verify_b64(&ssk_pub, &ed, &sig).is_ok()
    }

    /// Resolve a user from the local cache, or return a placeholder
    /// [`User::unknown`] if not cached.
    pub async fn user_info(&self, user_id: i64) -> Result<User> {
        let state = self.state.read().await;
        Ok(state
            .users
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| User::unknown(user_id)))
    }

    /// Generate and upload the user's cross-signing keys.
    ///
    /// Creates fresh MSK, SSK, and USK; signs SSK and USK with MSK; uploads
    /// the public halves to the server; signs the current device's ed25519
    /// key with SSK; stores the private keys in the local
    /// [`crate::CryptoStore`].
    ///
    /// Can only be called **once** per account. To start over, call
    /// [`Self::reset_cross_signing`] first.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::AlreadyConnected`] if keys already exist locally.
    /// - [`LockNetError::Server`] with code `cross_signing_already_exists`
    ///   if the server has keys for this user.
    /// - [`LockNetError::Server`] with code `invalid_signature` if the SSK or
    ///   USK signatures do not verify.
    pub async fn setup_cross_signing(&self) -> Result<()> {
        if self.low.store().cross_signing_keys().await.is_some() {
            return Err(LockNetError::AlreadyConnected);
        }
        let keys = CrossSigningKeysPrivate::generate();
        let user_id = self.low.user_id();
        let msk_pub = keys.msk_pub_b64();
        let ssk_pub = keys.ssk_pub_b64();
        let usk_pub = keys.usk_pub_b64();
        let ssk_sig = sign_b64(&keys.msk, &ssk_pub)?;
        let usk_sig = sign_b64(&keys.msk, &usk_pub)?;
        let mut ssk_sigs = std::collections::HashMap::new();
        let mut inner = std::collections::HashMap::new();
        inner.insert("master".to_string(), ssk_sig);
        ssk_sigs.insert(user_id.to_string(), inner);
        let mut usk_sigs = std::collections::HashMap::new();
        let mut inner2 = std::collections::HashMap::new();
        inner2.insert("master".to_string(), usk_sig);
        usk_sigs.insert(user_id.to_string(), inner2);
        let payload = CrossSigningKeys {
            master_key: CrossSigningKey {
                key: msk_pub,
                signatures: std::collections::HashMap::new(),
            },
            self_signing_key: CrossSigningKey {
                key: ssk_pub.clone(),
                signatures: ssk_sigs,
            },
            user_signing_key: CrossSigningKey {
                key: usk_pub,
                signatures: usk_sigs,
            },
        };
        self.low.crypto().upload_cross_signing_keys(payload).await?;
        let ed_b64 = {
            let account = self.low.store().account().await;
            let acc = account.lock().await;
            acc.ed25519_public_b64()
        };
        let device_sig = sign_b64(&keys.ssk, &ed_b64)?;
        let mut device_sigs = std::collections::HashMap::new();
        device_sigs.insert(self.low.session_id(), device_sig);
        self.low
            .crypto()
            .upload_signatures(Signatures {
                user_signatures: std::collections::HashMap::new(),
                device_signatures: device_sigs,
            })
            .await?;
        self.low
            .store()
            .cross_signing_keys_put(Arc::new(keys))
            .await;
        Ok(())
    }

    /// Reset the user's cross-signing keys.
    ///
    /// Requires the account password (UIA). The server removes the MSK, SSK,
    /// USK, all USK signatures on other users' MSKs, and all SSK signatures
    /// on the user's own sessions. Other users who had signed this user's
    /// MSK receive a `cross_signing_reset` event and will need to re-verify.
    ///
    /// On success, the local verified-users, verified-sessions, and WoT cache
    /// are also cleared, and the private keys are removed from the local
    /// [`crate::CryptoStore`].
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `invalid_password`.
    pub async fn reset_cross_signing(&self, password: impl Into<String>) -> Result<()> {
        self.low.crypto().reset_cross_signing_keys(password).await?;
        self.low.store().cross_signing_keys_clear().await;
        let mut state = self.state.write().await;
        state.verified_users.clear();
        state.verified_sessions.clear();
        state.invalidate_trust_graph();
        Ok(())
    }

    // ---- SAS ----

    async fn async_our_keys_and_ed(&self) -> Result<(String, String)> {
        let keys =
            self.low.store().cross_signing_keys().await.ok_or_else(|| {
                LockNetError::InvalidResponse("setup_cross_signing required".into())
            })?;
        let msk_b64 = keys.msk_pub_b64();
        let ed_b64 = {
            let account = self.low.store().account().await;
            let acc = account.lock().await;
            acc.ed25519_public_b64()
        };
        Ok((msk_b64, ed_b64))
    }

    async fn fetch_peer_keys(&self, user_id: i64, session_id: i64) -> Result<(String, String)> {
        let keys = self.low.keys().query(vec![user_id]).await?;
        let ed = keys
            .get(&user_id)
            .and_then(|m| m.get(&session_id))
            .map(|d| d.ed25519_key.clone())
            .ok_or_else(|| {
                LockNetError::InvalidArgument(format!(
                    "peer session {session_id} ed25519 not found"
                ))
            })?;
        let cs = self
            .low
            .crypto()
            .query_cross_signing_keys(vec![user_id])
            .await?;
        let msk = cs
            .get(&user_id)
            .map(|u| u.master_key.key.clone())
            .ok_or_else(|| {
                LockNetError::InvalidArgument(format!("peer {user_id} master key not found"))
            })?;
        Ok((ed, msk))
    }

    async fn resolve_user_for_session(&self, sender_session: i64) -> Option<i64> {
        let candidates: Vec<i64> = {
            let st = self.state.read().await;
            st.users.keys().copied().collect()
        };
        if candidates.is_empty() {
            return None;
        }
        let sessions = self.low.keys().query(candidates.clone()).await.ok()?;
        for uid in candidates {
            if let Some(map) = sessions.get(&uid) {
                if map.contains_key(&sender_session) {
                    return Some(uid);
                }
            }
        }
        None
    }

    /// Start a SAS verification as the initiator.
    ///
    /// Requires [`Self::setup_cross_signing`] to have been called. The flow
    /// is registered in the agent's state under a generated transaction ID;
    /// drive it with [`Self::sas_next`] and [`Self::emoji_confirm`].
    ///
    /// Returns the transaction ID.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidResponse`] if cross-signing is not set up.
    pub async fn sas_start(&self, user_id: i64, session_id: i64) -> Result<String> {
        let (msk_b64, ed_b64) = self.async_our_keys_and_ed().await?;
        let flow = SasFlow::start(
            self.low.clone(),
            self.event_tx.subscribe(),
            user_id,
            session_id,
            msk_b64,
            ed_b64,
        )
        .await?;
        let txid = flow.transaction_id().to_string();
        let handle = Arc::new(tokio::sync::Mutex::new(flow));
        {
            let mut st = self.state.write().await;
            st.active_sas.insert(txid.clone(), handle);
        }
        Ok(txid)
    }

    /// Accept a pending SAS `start` from `txid`.
    ///
    /// The `start` must have been received and registered via
    /// [`crate::HighEvent::SasMessage`] first. Sends `accept` and `key`
    /// immediately.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no pending start exists for
    ///   `txid`, or if the initiator's user ID cannot be resolved.
    pub async fn sas_accept(&self, txid: &str) -> Result<()> {
        let pending = {
            let mut st = self.state.write().await;
            st.pending_sas_starts.remove(txid)
        }
        .ok_or_else(|| {
            LockNetError::InvalidArgument(format!("no pending SAS start with txid {txid}"))
        })?;

        let peer_uid = match pending.from_user {
            Some(u) => u,
            None => self
                .resolve_user_for_session(pending.from_session)
                .await
                .ok_or_else(|| {
                    LockNetError::InvalidArgument(
                        "cannot resolve initiator user_id (no shared context)".into(),
                    )
                })?,
        };

        let (msk_b64, ed_b64) = self.async_our_keys_and_ed().await?;
        let flow = SasFlow::start_as_responder(
            self.low.clone(),
            self.event_tx.subscribe(),
            txid.to_string(),
            peer_uid,
            pending.from_session,
            msk_b64,
            ed_b64,
        )
        .await?;

        let handle = Arc::new(tokio::sync::Mutex::new(flow));
        {
            let mut st = self.state.write().await;
            st.active_sas.insert(txid.to_string(), handle);
        }
        Ok(())
    }

    /// Decline a pending SAS `start`.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no pending start exists for
    ///   `txid`.
    pub async fn sas_decline(&self, txid: &str) -> Result<()> {
        let mut st = self.state.write().await;
        if st.pending_sas_starts.remove(txid).is_some() {
            return Ok(());
        }
        drop(st);
        Err(LockNetError::InvalidArgument(format!(
            "no pending SAS start with txid {txid}"
        )))
    }

    /// Cancel an active or pending SAS flow.
    ///
    /// Safe to call in any state; aborts the flow if it exists and removes it
    /// from the agent's tracking.
    pub async fn sas_cancel(&self, txid: &str) -> Result<()> {
        let handle = {
            let mut st = self.state.write().await;
            st.pending_sas_starts.remove(txid);
            st.active_sas.remove(txid)
        };
        if let Some(h) = handle {
            let mut guard = h.lock().await;
            guard.abort().await?;
        }
        Ok(())
    }

    /// Advance a SAS flow one step.
    ///
    /// On [`SasStep::Verified`], the peer's session is added to the
    /// verified-sessions set, the peer's user is added to the verified-users
    /// set, the WoT cache is invalidated (our USK signature on their MSK may
    /// now exist server-side), and [`HighEvent::SessionVerified`] /
    /// [`HighEvent::UserVerified`] are emitted.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no active flow exists for
    ///   `txid`.
    pub async fn sas_next(&self, txid: &str) -> Result<SasStep> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!("no active SAS with txid {txid}")))?;

        let mut guard = handle.lock().await;
        let step = guard.next().await?;
        if matches!(step, SasStep::Verified) {
            let peer_uid = guard.peer_user_id();
            let peer_sid = guard.peer_session_id();
            drop(guard);

            {
                let mut st = self.state.write().await;
                st.verified_sessions.insert(peer_sid, peer_uid);
                st.verified_users.insert(peer_uid);
                // New USK -> peer.MSK edge may exist; invalidate WoT cache.
                st.invalidate_trust_graph();
            }
            let _ = self.event_tx.send(HighEvent::SessionVerified {
                user_id: peer_uid,
                session_id: peer_sid,
            });
            let _ = self
                .event_tx
                .send(HighEvent::UserVerified { user_id: peer_uid });
        }
        Ok(step)
    }

    /// Get the emoji computed by a SAS flow, if the flow is ready for
    /// confirmation.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no active flow exists.
    pub async fn emojis_get(&self, txid: &str) -> Result<Option<Vec<SasEmoji>>> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!("no active SAS with txid {txid}")))?;
        let guard = handle.lock().await;
        Ok(guard.emoji().map(|s| s.to_vec()))
    }

    /// Confirm (or reject) the SAS emoji.
    ///
    /// On accept, looks up the peer's public ed25519 and MSK (needed for MAC
    /// verification) and sends our MAC. The flow then waits for the peer's
    /// MAC via [`Self::sas_next`].
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no active flow exists, or if
    ///   the peer's keys cannot be resolved.
    pub async fn emoji_confirm(&self, txid: &str, accept: bool) -> Result<()> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!("no active SAS with txid {txid}")))?;

        let mut guard = handle.lock().await;
        if accept {
            let peer_uid = guard.peer_user_id();
            let peer_sid = guard.peer_session_id();
            let (peer_ed, peer_msk) = self.fetch_peer_keys(peer_uid, peer_sid).await?;
            guard.set_peer_keys(peer_ed, peer_msk);
        }
        guard.confirm_emoji(accept).await
    }

    /// Alias for [`Self::emoji_confirm`].
    pub async fn sas_confirm(&self, txid: &str, accept: bool) -> Result<()> {
        self.emoji_confirm(txid, accept).await
    }

    /// Remove a SAS flow from the agent's tracking without aborting it.
    pub async fn sas_remove(&self, txid: &str) {
        let mut st = self.state.write().await;
        st.active_sas.remove(txid);
        st.pending_sas_starts.remove(txid);
    }

    /// Current status of a SAS flow, if it exists.
    pub async fn sas_status(&self, txid: &str) -> Option<SasStatus> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }?;
        let guard = handle.lock().await;
        Some(guard.check_status())
    }

    // ---- QR ----

    /// Show a QR code (displayer side).
    ///
    /// Returns the QR string to render and a transaction ID. Drive the flow
    /// with [`Self::qr_next`] and [`Self::qr_exchange_mac`].
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidResponse`] if cross-signing is not set up.
    pub async fn qr_display(
        &self,
        mode: crate::api::high::verification::qr::QrMode,
        peer_user: i64,
        peer_session: i64,
    ) -> Result<(crate::api::high::verification::qr::QrCode, String)> {
        let (msk_b64, ed_b64) = self.async_our_keys_and_ed().await?;
        let (code, flow) = crate::api::high::verification::qr::QrFlow::display(
            mode,
            self.low.clone(),
            self.event_tx.subscribe(),
            peer_user,
            peer_session,
            msk_b64,
            ed_b64,
        )
        .await?;
        let txid = flow.transaction_id().to_string();
        let handle = Arc::new(tokio::sync::Mutex::new(flow));
        {
            let mut st = self.state.write().await;
            st.active_qr.insert(txid.clone(), handle);
        }
        Ok((code, txid))
    }

    /// Scan a QR code (scanner side).
    ///
    /// Returns a transaction ID; the flow is already in `WaitingConfirm`
    /// state. Drive it with [`Self::qr_next`] and [`Self::qr_exchange_mac`].
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if `qr_raw` is malformed.
    /// - [`LockNetError::InvalidResponse`] if cross-signing is not set up.
    pub async fn qr_scan(&self, qr_raw: &str, peer_user: i64, peer_session: i64) -> Result<String> {
        let (msk_b64, ed_b64) = self.async_our_keys_and_ed().await?;
        let flow = crate::api::high::verification::qr::QrFlow::scan(
            qr_raw,
            self.low.clone(),
            self.event_tx.subscribe(),
            peer_user,
            peer_session,
            msk_b64,
            ed_b64,
        )
        .await?;
        let txid = flow.transaction_id().to_string();
        let handle = Arc::new(tokio::sync::Mutex::new(flow));
        {
            let mut st = self.state.write().await;
            st.active_qr.insert(txid.clone(), handle);
        }
        Ok(txid)
    }

    /// Advance a QR flow one step.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no active flow exists, or if
    ///   `next` is called in the wrong state.
    pub async fn qr_next(&self, txid: &str) -> Result<crate::api::high::verification::qr::QrStep> {
        let handle = {
            let st = self.state.read().await;
            st.active_qr.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!("no active QR with txid {txid}")))?;
        let mut guard = handle.lock().await;
        guard.next().await
    }

    /// Exchange QR MACs and verify the peer.
    ///
    /// The peer key to MAC is resolved automatically: for
    /// [`crate::api::high::verification::qr::QrMode::UserToUser`], the peer's
    /// MSK; for self-device modes, the peer's ed25519.
    ///
    /// On [`crate::api::high::verification::qr::QrStep::Verified`], the
    /// peer's session and user are added to the verified-sets, the WoT cache
    /// is invalidated, and [`HighEvent::SessionVerified`] /
    /// [`HighEvent::UserVerified`] are emitted.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if no active flow exists, the
    ///   handshake is not complete, or the peer's keys cannot be resolved.
    pub async fn qr_exchange_mac(
        &self,
        txid: &str,
    ) -> Result<crate::api::high::verification::qr::QrStep> {
        let handle = {
            let st = self.state.read().await;
            st.active_qr.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!("no active QR with txid {txid}")))?;

        let mut guard = handle.lock().await;
        let peer_uid = guard.peer_user_id();
        let peer_sid = guard.peer_session_id();
        let mode = guard.mode();

        let peer_key = match mode {
            crate::api::high::verification::qr::QrMode::UserToUser => {
                let cs = self
                    .low
                    .crypto()
                    .query_cross_signing_keys(vec![peer_uid])
                    .await?;
                cs.get(&peer_uid)
                    .map(|u| u.master_key.key.clone())
                    .ok_or_else(|| {
                        LockNetError::InvalidArgument(format!("peer {peer_uid} msk not found"))
                    })?
            }
            crate::api::high::verification::qr::QrMode::SelfDeviceTrusted
            | crate::api::high::verification::qr::QrMode::SelfDeviceUntrusted => {
                let keys = self.low.keys().query(vec![peer_uid]).await?;
                keys.get(&peer_uid)
                    .and_then(|m| m.get(&peer_sid))
                    .map(|d| d.ed25519_key.clone())
                    .ok_or_else(|| {
                        LockNetError::InvalidArgument(format!("peer {peer_uid} ed25519 not found"))
                    })?
            }
        };

        let step = guard.exchange_mac(peer_key).await?;

        if matches!(step, crate::api::high::verification::qr::QrStep::Verified) {
            drop(guard);
            let user_id = peer_uid;
            let session_id = peer_sid;
            {
                let mut st = self.state.write().await;
                st.verified_sessions.insert(session_id, user_id);
                st.verified_users.insert(user_id);
                st.invalidate_trust_graph();
            }
            let _ = self.event_tx.send(HighEvent::SessionVerified {
                user_id,
                session_id,
            });
            let _ = self.event_tx.send(HighEvent::UserVerified { user_id });
        }

        Ok(step)
    }

    /// Cancel an active QR flow.
    ///
    /// Safe to call in any state.
    pub async fn qr_cancel(&self, txid: &str) -> Result<()> {
        let handle = {
            let mut st = self.state.write().await;
            st.active_qr.remove(txid)
        };
        if let Some(h) = handle {
            let mut guard = h.lock().await;
            guard.cancel().await?;
        }
        Ok(())
    }

    // ---- Backup ----

    /// Export every known Megolm inbound session to a new backup version.
    ///
    /// See [`crate::api::low::helpers::LockNetBackupHelper::export`] for
    /// details.
    pub async fn backup_export(&self, recovery_key: &RecoveryKey) -> Result<BackupExportResult> {
        self.low.backup().export(recovery_key).await
    }

    /// Import Megolm sessions from a backup version.
    ///
    /// See [`crate::api::low::helpers::LockNetBackupHelper::import`] for
    /// details.
    pub async fn backup_import(
        &self,
        version: i32,
        recovery_key: &RecoveryKey,
    ) -> Result<BackupImportResult> {
        self.low.backup().import(version, recovery_key).await
    }

    /// Generate a fresh [`RecoveryKey`] and export everything in one call.
    ///
    /// Returns `(recovery_key, result)`. **The caller must persist the
    /// recovery key** — losing it means losing access to all backed-up
    /// history.
    pub async fn backup_export_default(&self) -> Result<(RecoveryKey, BackupExportResult)> {
        let rk = RecoveryKey::generate()?;
        let result = self.backup_export(&rk).await?;
        Ok((rk, result))
    }

    /// List existing backup versions.
    pub async fn backup_versions(&self) -> Result<Vec<BackupVersion>> {
        self.low.backup().versions().await
    }

    /// Fetch a backup version with all its items.
    pub async fn backup_get(&self, version: i32) -> Result<BackupVersionData> {
        self.low.backup().get(version).await
    }

    /// Delete a backup version and all its items.
    pub async fn backup_delete(&self, version: i32) -> Result<()> {
        self.low.backup().delete(version).await
    }

    /// Explicitly invalidate the Web-of-Trust cache.
    ///
    /// The agent invalidates the cache automatically on
    /// [`crate::HighEvent::CrossSigningReset`], on incoming
    /// `cross_signing_signature_added` events, and after successful SAS / QR
    /// verification. Call this manually only if you upload USK signatures
    /// directly via [`crate::api::low::helpers::LockNetCryptoHelper`] — the
    /// server does not notify the signer about their own signatures.
    pub async fn invalidate_trust_cache(&self) {
        let mut st = self.state.write().await;
        st.invalidate_trust_graph();
    }

    // ---- Cross-signing key export / import ----

    /// Export the local cross-signing private keys (MSK, SSK, USK).
    ///
    /// This is intended for **self-device** migration: a user who already
    /// has cross-signing set up on device A exports the keys and imports
    /// them on device B (through a channel the application trusts: local
    /// file, encrypted backup, OS keychain, QR-based manual transfer, etc.).
    ///
    /// **Security warning:** the returned value contains **private** keys.
    /// Never transmit it over the network in plaintext. The application is
    /// responsible for moving it to the new device securely.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidResponse`] if cross-signing is not set up
    ///   on this device (call [`Self::setup_cross_signing`] first).
    pub async fn export_cross_signing_keys(&self) -> Result<CrossSigningKeysPrivate> {
        let keys = self.low.store().cross_signing_keys().await.ok_or_else(|| {
            LockNetError::InvalidResponse(
                "cross-signing not set up on this device; call setup_cross_signing first".into(),
            )
        })?;
        Ok((*keys).clone())
    }

    /// Import cross-signing private keys from another device of the same user.
    ///
    /// Verifies that the imported MSK matches the master key the server has
    /// on file for this user. This prevents accidentally importing keys that
    /// belong to someone else (or stale keys after a reset on another device).
    ///
    /// On success, the keys are persisted to the local store and the WoT
    /// cache is invalidated.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if the imported MSK does not match
    ///   the MSK on the server, or if the server has no MSK on file for this
    ///   user (i.e. cross-signing was reset elsewhere).
    /// - [`LockNetError::AlreadyConnected`] if this device already has
    ///   cross-signing keys. Call [`Self::reset_cross_signing`] first, or use
    ///   a fresh login on a new device.
    pub async fn import_cross_signing_keys(&self, keys: CrossSigningKeysPrivate) -> Result<()> {
        if self.low.store().cross_signing_keys().await.is_some() {
            return Err(LockNetError::AlreadyConnected);
        }

        let our_uid = self.low.user_id();
        let query = self
            .low
            .crypto()
            .query_cross_signing_keys(vec![our_uid])
            .await?;
        let server_msk = query
            .get(&our_uid)
            .map(|u| u.master_key.key.clone())
            .ok_or_else(|| {
                LockNetError::InvalidArgument(
                    "server has no master key for this user — cross-signing may have been reset"
                        .into(),
                )
            })?;

        if keys.msk_pub_b64() != server_msk {
            return Err(LockNetError::InvalidArgument(format!(
                "imported MSK does not match server MSK for user {our_uid} \
                 (server: {server_msk}, imported: {})",
                keys.msk_pub_b64()
            )));
        }

        self.low
            .store()
            .cross_signing_keys_put(Arc::new(keys))
            .await;

        {
            let mut st = self.state.write().await;
            st.invalidate_trust_graph();
        }

        Ok(())
    }

    /// Sign another session's `ed25519` key with this user's SSK and upload
    /// the signature.
    ///
    /// The target must belong to the **same user** as the caller (a
    /// self-device). This is the final step of mode-1 QR verification: after
    /// the QR handshake proves the target device really holds that ed25519
    /// key, we sign it with our SSK to mark it as a trusted self-device.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidResponse`] if this device has no SSK.
    /// - [`LockNetError::InvalidArgument`] if the target session does not
    ///   exist, does not belong to the caller's user, or has no `ed25519` key.
    /// - Server errors propagated from `upload_signatures` (e.g.
    ///   `unauthorized` if the target belongs to another user).
    pub async fn sign_device_session(
        &self,
        target_user_id: i64,
        target_session_id: i64,
    ) -> Result<()> {
        if target_user_id != self.low.user_id() {
            return Err(LockNetError::InvalidArgument(
                "sign_device_session: target must belong to the same user".into(),
            ));
        }

        let keys = self
            .low
            .store()
            .cross_signing_keys()
            .await
            .ok_or_else(|| {
                LockNetError::InvalidResponse(
                    "cross-signing not set up on this device; call setup_cross_signing or import_cross_signing_keys first"
                        .into(),
                )
            })?;

        let sessions = self.low.keys().query(vec![target_user_id]).await?;
        let target_ed = sessions
            .get(&target_user_id)
            .and_then(|m| m.get(&target_session_id))
            .map(|d| d.ed25519_key.clone())
            .ok_or_else(|| {
                LockNetError::InvalidArgument(format!(
                    "target session {target_session_id} of user {target_user_id} not found in query_keys"
                ))
            })?;

        let sig = sign_b64(&keys.ssk, &target_ed)?;

        self.low
            .crypto()
            .upload_signatures(Signatures {
                user_signatures: HashMap::new(),
                device_signatures: [(target_session_id, sig)].into_iter().collect(),
            })
            .await?;

        Ok(())
    }
}
