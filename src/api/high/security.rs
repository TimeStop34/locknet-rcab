use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use crate::api::low::agent::LockNetLowAgent;
use crate::api::high::trust::TrustGraph;
use crate::api::high::verification::sas::{SasFlow, SasStep, SasStatus, SasEmoji};
use crate::api::low::helpers::backup::{BackupExportResult, BackupImportResult, RecoveryKey};
use crate::api::low::models::{BackupVersion, BackupVersionData, CrossSigningKey, CrossSigningKeys, Signatures};
use crate::core::crypto::signature::{sign_b64, verify_b64, CrossSigningKeysPrivate};
use crate::core::errors::{LockNetError, Result};
use super::event::HighEvent;
use super::models::User;
use super::state::ClientState;

pub struct SecurityHelper {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) state: Arc<RwLock<ClientState>>,
    pub(crate) event_tx: broadcast::Sender<HighEvent>,
}

impl SecurityHelper {
                                            pub async fn is_user_verified(&self, user_id: i64) -> bool {
        if user_id == self.low.user_id() {
            return true;
        }

        {
            let st = self.state.read().await;
            if st.verified_users.contains(&user_id) {
                return true;
            }
            if let Some(set) = st.cached_reachable() {
                return set.contains(&user_id);
            }
        }

        let mut candidates: Vec<i64> = {
            let st = self.state.read().await;
            st.users.keys().copied().collect()
        };
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

    pub async fn is_session_verified(&self, user_id: i64, session_id: i64) -> bool {
        { let state = self.state.read().await; if state.verified_sessions.contains(&session_id) { return true; } }
        let query = match self.low.crypto().query_cross_signing_keys(vec![user_id]).await { Ok(q) => q, Err(_) => return false };
        let entry = match query.get(&user_id) { Some(e) => e, None => return false };
        let ssk_pub = match entry.self_signing_key.as_ref() { Some(k) => k.key.clone(), None => return false };
        let device = match entry.devices.get(&session_id) { Some(d) => d, None => return false };
        let sig = match device.signatures.get(&user_id.to_string()).and_then(|m| m.get("self_signing")) { Some(s) => s.clone(), None => return false };
        let ed = match &device.ed25519_key { s if s.is_empty() => return false, s => s.clone() };
        verify_b64(&ssk_pub, &ed, &sig).is_ok()
    }

    pub async fn user_info(&self, user_id: i64) -> Result<User> {
        let state = self.state.read().await;
        Ok(state.users.get(&user_id).cloned().unwrap_or_else(|| User::unknown(user_id)))
    }

    pub async fn setup_cross_signing(&self) -> Result<()> {
        if self.low.store().cross_signing_keys().await.is_some() { return Err(LockNetError::AlreadyConnected); }
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
            master_key: CrossSigningKey { key: msk_pub, signatures: std::collections::HashMap::new() },
            self_signing_key: CrossSigningKey { key: ssk_pub.clone(), signatures: ssk_sigs },
            user_signing_key: CrossSigningKey { key: usk_pub, signatures: usk_sigs },
        };
        self.low.crypto().upload_cross_signing_keys(payload).await?;
        let ed_b64 = { let account = self.low.store().account().await; let acc = account.lock().await; acc.ed25519_public_b64() };
        let device_sig = sign_b64(&keys.ssk, &ed_b64)?;
        let mut device_sigs = std::collections::HashMap::new();
        device_sigs.insert(self.low.session_id(), device_sig);
        self.low.crypto().upload_signatures(Signatures { user_signatures: std::collections::HashMap::new(), device_signatures: device_sigs }).await?;
        self.low.store().cross_signing_keys_put(Arc::new(keys)).await;
        Ok(())
    }

    pub async fn reset_cross_signing(&self, password: impl Into<String>) -> Result<()> {
        self.low.crypto().reset_cross_signing_keys(password).await?;
        self.low.store().cross_signing_keys_clear().await;
        let mut state = self.state.write().await;
        state.verified_users.clear();
        state.verified_sessions.clear();
        state.invalidate_trust_graph();
        Ok(())
    }


    async fn async_our_keys_and_ed(&self) -> Result<(String, String)> {
        let keys = self.low.store().cross_signing_keys().await
            .ok_or_else(|| LockNetError::InvalidResponse("setup_cross_signing required".into()))?;
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
            .ok_or_else(|| LockNetError::InvalidArgument(format!(
                "peer session {session_id} ed25519 not found"
            )))?;
        let cs = self.low.crypto().query_cross_signing_keys(vec![user_id]).await?;
        let msk = cs
            .get(&user_id)
            .map(|u| u.master_key.key.clone())
            .ok_or_else(|| LockNetError::InvalidArgument(format!(
                "peer {user_id} master key not found"
            )))?;
        Ok((ed, msk))
    }

    async fn resolve_user_for_session(&self, sender_session: i64) -> Option<i64> {
        let candidates: Vec<i64> = {
            let st = self.state.read().await;
            st.users.keys().copied().collect()
        };
        if candidates.is_empty() { return None; }
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
        { let mut st = self.state.write().await; st.active_sas.insert(txid.clone(), handle); }
        Ok(txid)
    }

    pub async fn sas_accept(&self, txid: &str) -> Result<()> {
        let pending = {
            let mut st = self.state.write().await;
            st.pending_sas_starts.remove(txid)
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!(
            "no pending SAS start with txid {txid}"
        )))?;

        let peer_uid = match pending.from_user {
            Some(u) => u,
            None => self.resolve_user_for_session(pending.from_session).await
                .ok_or_else(|| LockNetError::InvalidArgument(
                    "cannot resolve initiator user_id (no shared context)".into()
                ))?,
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
        { let mut st = self.state.write().await; st.active_sas.insert(txid.to_string(), handle); }
        Ok(())
    }

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

    pub async fn sas_next(&self, txid: &str) -> Result<SasStep> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!(
            "no active SAS with txid {txid}"
        )))?;

        let mut guard = handle.lock().await;
        let step = guard.next().await?;
        if matches!(step, SasStep::Verified) {
            let peer_uid = guard.peer_user_id();
            let peer_sid = guard.peer_session_id();
            drop(guard);

            {
                let mut st = self.state.write().await;
                st.verified_sessions.insert(peer_sid);
                st.verified_users.insert(peer_uid);
                st.invalidate_trust_graph();
            }
            let _ = self.event_tx.send(HighEvent::SessionVerified {
                user_id: peer_uid,
                session_id: peer_sid,
            });
            let _ = self.event_tx.send(HighEvent::UserVerified { user_id: peer_uid });
        }
        Ok(step)
    }

    pub async fn emojis_get(&self, txid: &str) -> Result<Option<Vec<SasEmoji>>> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!(
            "no active SAS with txid {txid}"
        )))?;
        let guard = handle.lock().await;
        Ok(guard.emoji().map(|s| s.to_vec()))
    }

    pub async fn emoji_confirm(&self, txid: &str, accept: bool) -> Result<()> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!(
            "no active SAS with txid {txid}"
        )))?;

        let mut guard = handle.lock().await;
        if accept {
            let peer_uid = guard.peer_user_id();
            let peer_sid = guard.peer_session_id();
            let (peer_ed, peer_msk) = self.fetch_peer_keys(peer_uid, peer_sid).await?;
            guard.set_peer_keys(peer_ed, peer_msk);
        }
        guard.confirm_emoji(accept).await
    }

    pub async fn sas_confirm(&self, txid: &str, accept: bool) -> Result<()> {
        self.emoji_confirm(txid, accept).await
    }

    pub async fn sas_remove(&self, txid: &str) {
        let mut st = self.state.write().await;
        st.active_sas.remove(txid);
        st.pending_sas_starts.remove(txid);
    }

    pub async fn sas_status(&self, txid: &str) -> Option<SasStatus> {
        let handle = {
            let st = self.state.read().await;
            st.active_sas.get(txid).cloned()
        }?;
        let guard = handle.lock().await;
        Some(guard.check_status())
    }


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
        { let mut st = self.state.write().await; st.active_qr.insert(txid.clone(), handle); }
        Ok((code, txid))
    }

    pub async fn qr_scan(
        &self,
        qr_raw: &str,
        peer_user: i64,
        peer_session: i64,
    ) -> Result<String> {
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
        { let mut st = self.state.write().await; st.active_qr.insert(txid.clone(), handle); }
        Ok(txid)
    }

    pub async fn qr_next(&self, txid: &str) -> Result<crate::api::high::verification::qr::QrStep> {
        let handle = {
            let st = self.state.read().await;
            st.active_qr.get(txid).cloned()
        }
        .ok_or_else(|| LockNetError::InvalidArgument(format!("no active QR with txid {txid}")))?;
        let mut guard = handle.lock().await;
        guard.next().await
    }

    pub async fn qr_exchange_mac(&self, txid: &str) -> Result<crate::api::high::verification::qr::QrStep> {
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
                let cs = self.low.crypto().query_cross_signing_keys(vec![peer_uid]).await?;
                cs.get(&peer_uid).map(|u| u.master_key.key.clone())
                    .ok_or_else(|| LockNetError::InvalidArgument(format!("peer {peer_uid} msk not found")))?
            }
            crate::api::high::verification::qr::QrMode::SelfDeviceTrusted
            | crate::api::high::verification::qr::QrMode::SelfDeviceUntrusted => {
                let keys = self.low.keys().query(vec![peer_uid]).await?;
                keys.get(&peer_uid).and_then(|m| m.get(&peer_sid))
                    .map(|d| d.ed25519_key.clone())
                    .ok_or_else(|| LockNetError::InvalidArgument(format!("peer {peer_uid} ed25519 not found")))?
            }
        };

        let step = guard.exchange_mac(peer_key).await?;

        if matches!(step, crate::api::high::verification::qr::QrStep::Verified) {
            drop(guard);
            let user_id = peer_uid;
            let session_id = peer_sid;
            {
                let mut st = self.state.write().await;
                st.verified_sessions.insert(session_id);
                st.verified_users.insert(user_id);
                st.invalidate_trust_graph();
            }
            let _ = self.event_tx.send(HighEvent::SessionVerified { user_id, session_id });
            let _ = self.event_tx.send(HighEvent::UserVerified { user_id });
        }

        Ok(step)
    }

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


    pub async fn backup_export(&self, recovery_key: &RecoveryKey) -> Result<BackupExportResult> {
        self.low.backup().export(recovery_key).await
    }

    pub async fn backup_import(
        &self,
        version: i32,
        recovery_key: &RecoveryKey,
    ) -> Result<BackupImportResult> {
        self.low.backup().import(version, recovery_key).await
    }

            pub async fn backup_export_default(&self) -> Result<(RecoveryKey, BackupExportResult)> {
        let rk = RecoveryKey::generate();
        let result = self.backup_export(&rk).await?;
        Ok((rk, result))
    }

    pub async fn backup_versions(&self) -> Result<Vec<BackupVersion>> {
        self.low.backup().versions().await
    }

    pub async fn backup_get(&self, version: i32) -> Result<BackupVersionData> {
        self.low.backup().get(version).await
    }

    pub async fn backup_delete(&self, version: i32) -> Result<()> {
        self.low.backup().delete(version).await
    }

                        pub async fn invalidate_trust_cache(&self) {
        let mut st = self.state.write().await;
        st.invalidate_trust_graph();
    }
}