//! `ln.encryption.key_request` flow.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::api::low::event::Event;
use crate::api::low::helpers::megolm::LockNetMegolmHelper;
use crate::api::low::helpers::olm::LockNetOlmHelper;
use crate::core::errors::{LockNetError, Result};

const LN_KEY_REQUEST: &str = "ln.encryption.key_request";
const LN_KEY_REQUEST_DONE: &str = "ln.encryption.key_request_done";
const LN_KEY_DENIED: &str = "ln.encryption.key_denied";
const LN_GROUP_KEY: &str = "ln.encryption.group_key";

const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// An `ln.encryption.key_request` received from another session.
#[derive(Debug, Clone)]
pub struct IncomingKeyRequest {
    /// Transaction ID assigned by the requester.
    pub transaction_id: String,
    /// The requesting session.
    pub from_session: i64,
    /// Chats the requester wants keys for.
    pub chat_ids: Vec<i64>,
    /// `"chat_id:megolm_session_id"` items the requester already has.
    pub have: Vec<String>,
}

/// Wraps the responder and requester sides of `ln.encryption.key_request`.
///
/// Obtained via [`crate::LockNetLowAgent::key_sharing`].
///
/// **Two users on the same client:**
///
/// - Low-level tests and standalone flows use [`Self::request`], which returns
///   a [`KeyRequestFlow`] that decrypts incoming payloads itself.
/// - In a running [`crate::LockNetAgent`], only the agent should decrypt
///   `to_device` events. Use [`Self::send_request_only`] and listen to
///   `HighEvent::KeyRequest*` instead — otherwise both will compete for the
///   stateful Olm session.
pub struct LockNetKeySharingHelper {
    pub(crate) event_tx: broadcast::Sender<Event>,
    pub(crate) olm: Arc<LockNetOlmHelper>,
    pub(crate) megolm: Arc<LockNetMegolmHelper>,
    pub(crate) our_session_id: i64,
}

impl LockNetKeySharingHelper {
    /// Build a standalone requester flow (see the struct docs for caveats).
    pub async fn request(
        &self,
        to_user: i64,
        to_session: i64,
        chat_ids: Vec<i64>,
    ) -> Result<KeyRequestFlow> {
        KeyRequestFlow::new(
            self.event_tx.subscribe(),
            self.olm.clone(),
            self.megolm.clone(),
            self.our_session_id,
            to_user,
            to_session,
            chat_ids,
        )
        .await
    }

    /// Send `ln.encryption.key_request` and return the transaction ID.
    ///
    /// Does **not** subscribe to events: the caller is expected to listen to
    /// `HighEvent::KeyRequest{Imported,Done,Denied}`, emitted by
    /// [`crate::LockNetAgent`] after it has decrypted the reply.
    pub async fn send_request_only(
        &self,
        to_user: i64,
        to_session: i64,
        chat_ids: Vec<i64>,
    ) -> Result<String> {
        let txid = generate_txid()?;

        let have: Vec<String> = {
            let store = olm_store_via_megolm(&self.megolm);
            store
                .megolm_inbound_all()
                .await
                .into_iter()
                .filter(|(cid, _)| chat_ids.contains(cid))
                .map(|(cid, mid)| format!("{cid}:{mid}"))
                .collect()
        };

        let content = json!({
            "type": LN_KEY_REQUEST,
            "content": {
                "transaction_id": txid,
                "chat_ids": chat_ids,
                "have": have,
            }
        });

        self.olm
            .send(to_user, to_session, content.to_string())
            .wait()
            .await?;

        Ok(txid)
    }

    /// Wait for the first `ln.encryption.key_request`.
    ///
    /// `rx` must be subscribed **before** the peer sends the request.
    pub async fn wait_request(
        &self,
        rx: &mut broadcast::Receiver<Event>,
        timeout: Duration,
    ) -> Result<IncomingKeyRequest> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(LockNetError::Timeout(timeout));
            }

            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(Event::ToDevice(payload))) => {
                    let sender_session = payload.sender_session_id;
                    if let Some(pt) = self.olm.decrypt(payload).wait().await? {
                        if let Ok(val) = serde_json::from_str::<Value>(&pt) {
                            if val.get("type").and_then(|v| v.as_str()) == Some(LN_KEY_REQUEST) {
                                let content = val.get("content").ok_or_else(|| {
                                    LockNetError::InvalidResponse("key_request: no content".into())
                                })?;
                                let transaction_id = content
                                    .get("transaction_id")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        LockNetError::InvalidResponse(
                                            "key_request: no transaction_id".into(),
                                        )
                                    })?
                                    .to_string();
                                let chat_ids = parse_chat_ids(content)?;
                                let have = parse_have(content)?;
                                return Ok(IncomingKeyRequest {
                                    transaction_id,
                                    from_session: sender_session,
                                    chat_ids,
                                    have,
                                });
                            }
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Err(LockNetError::Timeout(timeout)),
            }
        }
    }

    /// Send one `ln.encryption.group_key` reply (with the shared
    /// `group_data` blob, if any).
    pub async fn send_group_key(
        &self,
        to_user: i64,
        to_session: i64,
        transaction_id: String,
        chat_id: i64,
        megolm_session_id: String,
        session_key: String,
    ) -> Result<()> {
        let content = crate::api::low::helpers::megolm::build_group_key_content(
            &self.megolm.store,
            chat_id,
            megolm_session_id,
            session_key,
            Some(transaction_id),
        )
        .await;
        let pt = json!({
            "type": LN_GROUP_KEY,
            "content": content,
        })
        .to_string();
        self.olm.send(to_user, to_session, pt).wait().await
    }

    /// Send `ln.encryption.key_request_done`.
    pub async fn send_done(
        &self,
        to_user: i64,
        to_session: i64,
        transaction_id: String,
        count: u32,
    ) -> Result<()> {
        let content = json!({
            "type": LN_KEY_REQUEST_DONE,
            "content": {
                "transaction_id": transaction_id,
                "count": count,
            }
        });
        self.olm
            .send(to_user, to_session, content.to_string())
            .wait()
            .await
    }

    /// Send `ln.encryption.key_denied`.
    pub async fn send_denied(
        &self,
        to_user: i64,
        to_session: i64,
        transaction_id: String,
        reason: String,
    ) -> Result<()> {
        let content = json!({
            "type": LN_KEY_DENIED,
            "content": {
                "transaction_id": transaction_id,
                "reason": reason,
            }
        });
        self.olm
            .send(to_user, to_session, content.to_string())
            .wait()
            .await
    }
}

/// A single step of a requester flow.
#[derive(Debug)]
pub enum KeyRequestStep {
    /// One `group_key` was received and imported.
    GroupKeyImported {
        /// Chat the key belongs to.
        chat_id: i64,
        /// Megolm session ID.
        megolm_session_id: String,
    },
    /// The responder finished sending keys.
    Done {
        /// Total keys imported in this flow.
        total_imported: u32,
    },
    /// The responder refused.
    Denied {
        /// Reason sent by the responder.
        reason: String,
    },
    /// The flow was cancelled locally.
    Cancelled(String),
}

#[derive(Debug, Clone)]
enum InternalState {
    Waiting,
    Done { total: u32 },
    Denied(String),
    Cancelled(String),
}

/// Standalone requester flow.
///
/// **Warning:** this flow decrypts incoming `to_device` payloads directly.
/// If a [`crate::LockNetAgent`] is running on the same client, it will also
/// try to decrypt those payloads and the two will race for the stateful Olm
/// session. Use [`LockNetKeySharingHelper::send_request_only`] when an agent
/// is running.
pub struct KeyRequestFlow {
    txid: String,
    #[allow(dead_code)]
    to_user: i64,
    #[allow(dead_code)]
    to_session: i64,
    chat_ids: Vec<i64>,
    olm: Arc<LockNetOlmHelper>,
    megolm: Arc<LockNetMegolmHelper>,
    event_rx: broadcast::Receiver<Event>,
    imported_count: u32,
    state: InternalState,
}

impl KeyRequestFlow {
    async fn new(
        event_rx: broadcast::Receiver<Event>,
        olm: Arc<LockNetOlmHelper>,
        megolm: Arc<LockNetMegolmHelper>,
        our_session_id: i64,
        to_user: i64,
        to_session: i64,
        chat_ids: Vec<i64>,
    ) -> Result<Self> {
        let txid = generate_txid()?;

        let have: Vec<String> = {
            let store = olm_store_via_megolm(&megolm);
            store
                .megolm_inbound_all()
                .await
                .into_iter()
                .filter(|(cid, _)| chat_ids.contains(cid))
                .map(|(cid, mid)| format!("{cid}:{mid}"))
                .collect()
        };

        let content = json!({
            "type": LN_KEY_REQUEST,
            "content": {
                "transaction_id": txid,
                "chat_ids": chat_ids,
                "have": have,
            }
        });

        olm.send(to_user, to_session, content.to_string())
            .wait()
            .await?;

        let _ = our_session_id;

        Ok(Self {
            txid,
            to_user,
            to_session,
            chat_ids,
            olm,
            megolm,
            event_rx,
            imported_count: 0,
            state: InternalState::Waiting,
        })
    }

    /// Transaction ID of this request.
    pub fn transaction_id(&self) -> &str {
        &self.txid
    }

    /// Chats requested in this flow.
    pub fn chat_ids(&self) -> &[i64] {
        &self.chat_ids
    }

    /// Number of keys imported so far.
    pub fn imported_count(&self) -> u32 {
        self.imported_count
    }

    /// Advance the flow by one step.
    ///
    /// Blocks until the next `group_key`, `done`, or `denied` message
    /// arrives. Returns the terminal state ([`KeyRequestStep::Done`],
    /// [`KeyRequestStep::Denied`], [`KeyRequestStep::Cancelled`]) once
    /// reached; subsequent calls return it again.
    pub async fn next(&mut self) -> Result<KeyRequestStep> {
        match self.state.clone() {
            InternalState::Done { total } => {
                return Ok(KeyRequestStep::Done {
                    total_imported: total,
                })
            }
            InternalState::Denied(reason) => return Ok(KeyRequestStep::Denied { reason }),
            InternalState::Cancelled(reason) => return Ok(KeyRequestStep::Cancelled(reason)),
            InternalState::Waiting => {}
        }

        let deadline = tokio::time::Instant::now() + DEFAULT_WAIT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(LockNetError::Timeout(DEFAULT_WAIT_TIMEOUT));
            }

            match tokio::time::timeout(remaining, self.event_rx.recv()).await {
                Ok(Ok(Event::ToDevice(payload))) => {
                    if let Some(pt) = self.olm.decrypt(payload).wait().await? {
                        if let Some(step) = self.handle_plaintext(&pt).await? {
                            return Ok(step);
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Err(LockNetError::Timeout(DEFAULT_WAIT_TIMEOUT)),
            }
        }
    }

    async fn handle_plaintext(&mut self, pt: &str) -> Result<Option<KeyRequestStep>> {
        let val: Value = match serde_json::from_str(pt) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match msg_type {
            LN_GROUP_KEY => {
                let content = val
                    .get("content")
                    .ok_or_else(|| LockNetError::InvalidResponse("group_key: no content".into()))?;
                let chat_id = content
                    .get("chat_id")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| LockNetError::InvalidResponse("group_key: no chat_id".into()))?;
                let megolm_session_id = content
                    .get("megolm_session_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        LockNetError::InvalidResponse("group_key: no megolm_session_id".into())
                    })?
                    .to_string();
                let session_key = content
                    .get("session_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        LockNetError::InvalidResponse("group_key: no session_key".into())
                    })?
                    .to_string();

                self.megolm
                    .import(chat_id, megolm_session_id.clone(), session_key)
                    .await?;

                crate::api::low::helpers::megolm::apply_group_data_to_store(
                    &self.megolm.store,
                    chat_id,
                    content,
                )
                .await?;

                self.imported_count += 1;

                Ok(Some(KeyRequestStep::GroupKeyImported {
                    chat_id,
                    megolm_session_id,
                }))
            }
            LN_KEY_REQUEST_DONE => {
                let total = self.imported_count;
                self.state = InternalState::Done { total };
                Ok(Some(KeyRequestStep::Done {
                    total_imported: total,
                }))
            }
            LN_KEY_DENIED => {
                let reason = val
                    .pointer("/content/reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("denied")
                    .to_string();
                self.state = InternalState::Denied(reason.clone());
                Ok(Some(KeyRequestStep::Denied { reason }))
            }
            _ => Ok(None),
        }
    }

    /// Cancel the flow locally.
    pub async fn cancel(&mut self) -> Result<()> {
        if matches!(
            self.state,
            InternalState::Done { .. } | InternalState::Denied(_) | InternalState::Cancelled(_)
        ) {
            return Ok(());
        }
        self.state = InternalState::Cancelled("cancelled by user".into());
        Ok(())
    }
}

fn parse_chat_ids(content: &Value) -> Result<Vec<i64>> {
    let arr = content
        .get("chat_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| LockNetError::InvalidResponse("key_request: no chat_ids".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let id = v.as_i64().ok_or_else(|| {
            LockNetError::InvalidResponse("key_request: chat_ids must be i64".into())
        })?;
        out.push(id);
    }
    Ok(out)
}

fn parse_have(content: &Value) -> Result<Vec<String>> {
    let arr = content.get("have").and_then(|v| v.as_array());
    match arr {
        None => Ok(Vec::new()),
        Some(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                let s = v.as_str().ok_or_else(|| {
                    LockNetError::InvalidResponse("key_request: have items must be strings".into())
                })?;
                out.push(s.to_string());
            }
            Ok(out)
        }
    }
}

fn olm_store_via_megolm(megolm: &LockNetMegolmHelper) -> Arc<dyn crate::core::crypto::CryptoStore> {
    megolm.store.clone()
}

fn generate_txid() -> Result<String> {
    crate::core::crypto::random::random_txid()
}
