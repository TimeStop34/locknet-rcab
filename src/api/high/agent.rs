//! [`LockNetAgent`] — the stateful high-level agent.
//!
//! This is the main entry point for applications that want an
//! object-oriented API on top of [`crate::api::low`]. The agent:
//!
//! - Maintains an internal cache of chats, users, invites, and messages.
//! - Spawns a background task (`start_process`) that turns
//!   raw [`crate::api::low::Event`]s into [`HighEvent`]s, decrypts
//!   `to_device` payloads, and drives multi-step E2EE flows (group key
//!   fan-out, key requests, policy sync).
//! - Exposes object-oriented handles: [`Chat`] for group operations,
//!   [`crate::SecurityHelper`] for trust and verification.
//!
//! ## Architectural invariant
//!
//! The agent is the **sole Olm decryptor** in high-level mode. Low-level
//! helpers that decrypt `to_device` payloads (such as
//! [`crate::api::low::helpers::LockNetKeySharingHelper::request`]) must
//! **not** be used concurrently with an active agent on the same client —
//! they would race on the stateful Olm session and silently drop payloads.
//! The verification flows in [`crate::api::high::verification`] obey this:
//! they consume [`HighEvent::SasMessage`] / [`HighEvent::QrMessage`] rather
//! than raw `to_device` events.
//!
//! ## Getting an agent
//!
//! Agents are created lazily: [`crate::LockNetClient::get_agent`] creates the
//! agent on first call and returns the cached `Arc` thereafter. Applications
//! that only use the low-level API never pay for the agent's background task.

use super::event::HighEvent;
use super::models::{Chat, Group, Invite, Message, Reaction, User};
use super::security::SecurityHelper;
use super::state::{ClientState, PendingSasStart};
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::event::Event as LowEvent;
use crate::core::errors::{LockNetError, Result};
use crate::core::policies::{HistoryVisibility, MegolmRotationVisibility};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;

/// Stateful, object-oriented LockNet agent.
///
/// Wraps a [`LockNetLowAgent`] with a cache, event processing, and E2EE
/// flow orchestration. Obtained via [`crate::LockNetClient::get_agent`].
///
/// # Examples
///
/// ```rust,no_run
/// use locknet_rcab::{Credentials, LockNetClient, LockNetConfig};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = LockNetConfig::new("https://locknet.example.com", "example.com")?;
/// let mut client = LockNetClient::new(config);
/// client
///     .connection_request(Credentials::Login {
///         username: "alice".into(),
///         password: "secret".into(),
///     })
///     .await?;
///
/// let agent = client.get_agent().expect("agent");
/// let chat = agent.chat(42).await?;
/// chat.send("hello").await?;
///
/// let mut events = agent.subscribe();
/// while let Ok(evt) = events.recv().await {
///     println!("event: {evt:?}");
/// }
/// # Ok(())
/// # }
/// ```
pub struct LockNetAgent {
    pub(crate) low: Arc<LockNetLowAgent>,
    pub(crate) state: Arc<RwLock<ClientState>>,
    pub(crate) event_tx: broadcast::Sender<HighEvent>,
    pub(crate) security: Arc<SecurityHelper>,
    process_handle: Option<JoinHandle<()>>,
}

impl LockNetAgent {
    /// Create a new agent for the given low-level agent.
    ///
    /// Spawns the background event-processing task. Called by
    /// [`crate::LockNetClient::get_agent`]; not part of the public API.
    pub(crate) fn new(low: Arc<LockNetLowAgent>) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        let state = Arc::new(RwLock::new(ClientState::new(
            low.user_id(),
            low.session_id(),
        )));
        let security = Arc::new(SecurityHelper {
            low: low.clone(),
            state: state.clone(),
            event_tx: event_tx.clone(),
        });
        let mut agent = Self {
            low,
            state,
            event_tx,
            security,
            process_handle: None,
        };
        agent.start_process();
        agent
    }

    /// Spawn the background task that consumes low-level events.
    ///
    /// The task runs until the low-level subscription channel closes (i.e.
    /// the underlying runner shuts down) or until [`Self::shutdown`] is
    /// called. Every event is passed through `process_event`, which updates
    /// the internal cache and emits [`HighEvent`]s.
    fn start_process(&mut self) {
        let low = self.low.clone();
        let state = self.state.clone();
        let event_tx = self.event_tx.clone();
        let security = self.security.clone();
        let mut rx = low.subscribe();
        let handle = tokio::spawn(async move {
            while let Ok(evt) = rx.recv().await {
                if let Err(e) = process_event(&low, &state, &event_tx, &security, evt).await {
                    tracing::warn!(?e, "high process error");
                }
            }
        });
        self.process_handle = Some(handle);
    }

    /// Abort the background event-processing task.
    ///
    /// Called by [`crate::LockNetClient::disconnect`] before the low-level
    /// runner shuts down.
    pub(crate) async fn shutdown(&self) {
        if let Some(h) = self.process_handle.as_ref() {
            h.abort();
        }
    }

    // ---- identity ----

    /// Server-side user ID of the authenticated user.
    pub fn user_id(&self) -> i64 {
        self.low.user_id()
    }

    /// Server-side session ID of the current device.
    pub fn session_id(&self) -> i64 {
        self.low.session_id()
    }

    /// Resolve the current user from the local cache, inserting a placeholder
    /// if not yet cached.
    pub async fn user(&self) -> User {
        let mut st = self.state.write().await;
        st.resolve_user(self.low.user_id())
    }

    // ---- chats ----

    /// List all chats the current user is a member of.
    ///
    /// Returns the cached list if non-empty; otherwise triggers
    /// [`Self::refresh_chats`].
    ///
    /// # Errors
    ///
    /// Propagates the error from [`Self::refresh_chats`] on a cache miss.
    pub async fn chats(&self) -> Result<Vec<Chat>> {
        let cached = self.cached_chats();
        if !cached.is_empty() {
            return Ok(cached);
        }
        self.refresh_chats().await
    }

    /// Snapshot of the cached chats without any network round-trip.
    ///
    /// Returns an empty `Vec` if the cache is currently locked by another
    /// task (the function uses `try_read`).
    pub fn cached_chats(&self) -> Vec<Chat> {
        let st = match self.state.try_read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        st.groups
            .values()
            .map(|g| {
                Chat::new(
                    self.low.clone(),
                    g.clone(),
                    self.state.clone(),
                    self.event_tx.clone(),
                    self.security.clone(),
                )
            })
            .collect()
    }

    /// Re-fetch the group list from the server, update the cache, and return
    /// the updated chats.
    ///
    /// For each group, the local `encrypted_group_data` blob is compared to
    /// the server's; if the server blob is newer, it is decrypted, the policy
    /// is updated, and the local cache is replaced.
    ///
    /// # Errors
    ///
    /// Propagates transport errors from [`crate::api::low::helpers::LockNetGroupsHelper::list`].
    pub async fn refresh_chats(&self) -> Result<Vec<Chat>> {
        let groups = self.low.groups().list().await?;
        let mut out = Vec::with_capacity(groups.len());
        for dto in groups {
            let g = {
                let mut st = self.state.write().await;
                let g = st.group_to_domain(&dto, &self.low).await;
                st.groups.insert(g.id, g.clone());
                g
            };
            out.push(Chat::new(
                self.low.clone(),
                g,
                self.state.clone(),
                self.event_tx.clone(),
                self.security.clone(),
            ));
        }
        Ok(out)
    }

    /// Get a chat handle by ID.
    ///
    /// Returns the cached handle if the group is already known; otherwise
    /// fetches metadata from the server (which also decrypts the policy blob
    /// if the `group_data_key` is available).
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `group_not_found` if the group
    ///   does not exist, or is private and the caller is not a member.
    pub async fn chat(&self, chat_id: i64) -> Result<Chat> {
        if let Some(c) = self.cached_chat(chat_id) {
            return Ok(c);
        }
        let info = self.low.groups().info(chat_id).await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&info, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(
            self.low.clone(),
            g,
            self.state.clone(),
            self.event_tx.clone(),
            self.security.clone(),
        ))
    }

    fn cached_chat(&self, chat_id: i64) -> Option<Chat> {
        let st = self.state.try_read().ok()?;
        st.groups.get(&chat_id).map(|g| {
            Chat::new(
                self.low.clone(),
                g.clone(),
                self.state.clone(),
                self.event_tx.clone(),
                self.security.clone(),
            )
        })
    }

    // ---- group management ----

    /// Open a direct (1-to-1) chat with `other_user_id`.
    ///
    /// The other user receives a [`HighEvent::InviteReceived`] event and must
    /// accept it via [`Self::accept_invite`] before being added as a member.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `self_direct` if
    ///   `other_user_id` equals the current user.
    /// - [`LockNetError::Server`] with code `user_not_found`.
    pub async fn open_direct(&self, other_user_id: i64) -> Result<Chat> {
        let group = self.low.groups().create_direct(other_user_id).await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&group, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(
            self.low.clone(),
            g,
            self.state.clone(),
            self.event_tx.clone(),
            self.security.clone(),
        ))
    }

    /// Create a group.
    ///
    /// `participants` receive [`HighEvent::InviteReceived`] events, not
    /// membership; they must accept via [`Self::accept_invite`]. The caller
    /// is the only member until invites are accepted.
    ///
    /// The group's initial policies are set from
    /// [`crate::LockNetConfig::default_history_visibility`] and
    /// [`crate::LockNetConfig::default_megolm_rotation_visibility`]. The
    /// policy blob is uploaded to the server on the first send.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `duplicate_participants`,
    ///   `creator_in_participants`, `public_id_required`,
    ///   `public_id_taken`, or `users_not_found`.
    pub async fn create_group(
        &self,
        name: impl Into<String>,
        is_public: bool,
        public_id: Option<String>,
        participants: Vec<i64>,
    ) -> Result<Chat> {
        let group = self
            .low
            .groups()
            .create(name, is_public, public_id, participants)
            .await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&group, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(
            self.low.clone(),
            g,
            self.state.clone(),
            self.event_tx.clone(),
            self.security.clone(),
        ))
    }

    /// Join a public group by its `public_id`.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `group_not_public` if the group
    ///   does not exist or is private.
    /// - [`LockNetError::Server`] with code `already_member`.
    pub async fn join_group(&self, public_id: impl Into<String>) -> Result<Chat> {
        let group = self.low.groups().join(public_id).await?;
        let g = {
            let mut st = self.state.write().await;
            let g = st.group_to_domain(&group, &self.low).await;
            st.groups.insert(g.id, g.clone());
            g
        };
        Ok(Chat::new(
            self.low.clone(),
            g,
            self.state.clone(),
            self.event_tx.clone(),
            self.security.clone(),
        ))
    }

    /// Leave a group.
    ///
    /// If the caller is the creator, the group is deleted and every member
    /// loses access.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `not_member` or `group_not_found`.
    pub async fn leave_chat(&self, chat_id: i64) -> Result<()> {
        self.low.groups().leave(chat_id).await?;
        let mut st = self.state.write().await;
        st.groups.remove(&chat_id);
        Ok(())
    }

    // ---- invitations ----

    /// List pending invitations for the current user.
    ///
    /// Results are merged into the cache; the returned invites are the same
    /// objects that appear in [`HighEvent::InviteReceived`].
    ///
    /// # Errors
    ///
    /// Propagates transport errors from
    /// [`crate::api::low::helpers::LockNetGroupsHelper::invites`].
    pub async fn invites(&self) -> Result<Vec<Invite>> {
        let invites = self.low.groups().invites().await?;
        let mut st = self.state.write().await;
        let mut out = Vec::with_capacity(invites.len());
        for dto in invites {
            let inv = st.invite_to_domain(&dto);
            st.invites.insert(inv.id, inv.clone());
            out.push(inv);
        }
        Ok(out)
    }

    /// Accept an invitation, becoming a member of the group.
    ///
    /// After acceptance the invite is removed from the cache and the group is
    /// re-fetched from the server (picking up the current member list and
    /// policy).
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if `invite_id` is not in the local
    ///   cache after a refresh.
    /// - [`LockNetError::Server`] with code `invite_not_found` or
    ///   `already_member`.
    pub async fn accept_invite(&self, invite_id: i64) -> Result<Chat> {
        let group_id = {
            let st = self.state.read().await;
            st.invites.get(&invite_id).map(|i| i.group.id)
        };
        let group_id = match group_id {
            Some(gid) => gid,
            None => {
                let _ = self.invites().await?;
                let st = self.state.read().await;
                st.invites
                    .get(&invite_id)
                    .map(|i| i.group.id)
                    .ok_or_else(|| {
                        LockNetError::InvalidArgument(format!("invite {invite_id} not found"))
                    })?
            }
        };

        self.low.groups().accept_invite(invite_id).await?;
        {
            let mut st = self.state.write().await;
            st.invites.remove(&invite_id);
        }
        self.chat(group_id).await
    }

    /// Decline an invitation.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Server`] with code `invite_not_found`.
    pub async fn decline_invite(&self, invite_id: i64) -> Result<()> {
        self.low.groups().decline_invite(invite_id).await?;
        let mut st = self.state.write().await;
        st.invites.remove(&invite_id);
        Ok(())
    }

    // ---- users ----

    /// Resolve a user from the local cache, or return a placeholder
    /// [`User::unknown`] if not cached.
    ///
    /// User metadata is currently populated only by group membership data;
    /// there is no standalone user-info endpoint on the server yet.
    pub async fn user_info(&self, user_id: i64) -> Result<User> {
        let mut st = self.state.write().await;
        Ok(st.resolve_user(user_id))
    }

    /// Cached user, if present. Returns `None` if the cache is locked or the
    /// user is not cached.
    pub fn cached_user(&self, user_id: i64) -> Option<User> {
        let st = self.state.try_read().ok()?;
        st.users.get(&user_id).cloned()
    }

    /// Cached message, if present. Returns `None` if the message has not been
    /// observed yet in the current session.
    pub fn cached_message(&self, message_id: i64) -> Option<Message> {
        let st = self.state.try_read().ok()?;
        st.messages.get(&message_id).cloned()
    }

    // ---- events / services ----

    /// Subscribe to high-level events.
    ///
    /// Returns a broadcast receiver for [`HighEvent`]s. Events are dropped for
    /// slow subscribers once the internal buffer (1024) is full — callers
    /// should drain the channel promptly or handle
    /// [`tokio::sync::broadcast::error::RecvError::Lagged`].
    pub fn subscribe(&self) -> broadcast::Receiver<HighEvent> {
        self.event_tx.subscribe()
    }

    /// The trust/verification helper.
    ///
    /// See [`SecurityHelper`] for cross-signing setup, SAS / QR flows, and
    /// key backup.
    pub fn security(&self) -> Arc<SecurityHelper> {
        self.security.clone()
    }

    /// Escape hatch to the low-level agent.
    ///
    /// Use only for operations that are not covered by the high-level API, or
    /// for advanced scenarios where explicit control over each request is
    /// required. **Do not** call low-level decryptors (`olm.decrypt`,
    /// `key_sharing.request`, SAS/QR flows from `api::low`) while the agent is
    /// active — they would race for the stateful Olm session.
    pub fn low(&self) -> Arc<LockNetLowAgent> {
        self.low.clone()
    }
}

/// Build a minimal [`Group`] placeholder for a chat that is not yet cached.
///
/// Used when a `message_create` / `message_update` arrives before
/// [`LockNetAgent::refresh_chats`] has run. The placeholder has empty members
/// and no policy — it is enough to construct a [`Chat`] handle for the event.
fn stub_group(chat_id: i64) -> Group {
    Group {
        id: chat_id,
        public_id: None,
        name: format!("chat {chat_id}"),
        is_public: false,
        created_by: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        members: Vec::new(),
        member_count: 0,
        encrypted_group_data: None,
        group_data: None,
    }
}

/// Decrypt the text of an [`crate::api::low::models::Encrypted`] payload.
///
/// Handles both `ln.plaintext.v1` (public groups: base64-encoded UTF-8) and
/// `ln.encryption.megolm.v1` (via [`crate::api::low::helpers::LockNetMegolmHelper::decrypt`]).
///
/// Returns `None` on any failure (unknown algorithm, missing Megolm key,
/// malformed base64, invalid UTF-8). Callers treat `None` as "pending
/// decryption" and record the message ID for later retry.
async fn decrypt_text(
    low: &LockNetLowAgent,
    chat_id: i64,
    enc: &crate::api::low::models::Encrypted,
) -> Option<String> {
    if enc.algorithm == "ln.plaintext.v1" {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&enc.ciphertext)
            .ok()?;
        String::from_utf8(bytes).ok()
    } else {
        low.megolm().decrypt(chat_id, enc).await.ok().flatten()
    }
}

/// Resolve a sender's session ID to a user ID by scanning the member lists of
/// `chat_ids`.
///
/// Used by [`respond_key_request`] when the `ln.encryption.key_request`
/// payload does not carry the sender's user ID. The server rewrites
/// `sender_session_id` from the authenticated session, so it is trustworthy —
/// we only need to find which user it belongs to.
///
/// Returns `None` if `chat_ids` is empty, no member has that session, or any
/// network request fails.
async fn resolve_user_by_session(
    low: &Arc<LockNetLowAgent>,
    chat_ids: &[i64],
    target_session: i64,
) -> Option<i64> {
    let mut candidates: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for cid in chat_ids {
        if let Ok(info) = low.groups().info(*cid).await {
            if let Some(members) = info.members {
                for m in members {
                    candidates.insert(m.user_id);
                }
            }
        }
    }
    if candidates.is_empty() {
        return None;
    }
    let candidates_vec: Vec<i64> = candidates.into_iter().collect();
    let sessions = low.keys().query(candidates_vec.clone()).await.ok()?;
    for uid in candidates_vec {
        if let Some(map) = sessions.get(&uid) {
            if map.contains_key(&target_session) {
                return Some(uid);
            }
        }
    }
    None
}

/// Respond to an incoming `ln.encryption.key_request`.
///
/// Applies the [`HistoryVisibility`] policy of every requested chat:
///
/// - [`HistoryVisibility::AfterJoin`] — reject the entire request with
///   `history_visibility_policy`.
/// - [`HistoryVisibility::AllVerifiedSessions`] — grant only if the requester
///   passes [`SecurityHelper::is_session_verified`].
/// - [`HistoryVisibility::AllVerifiedUsers`] — grant only if the requester
///   passes both [`SecurityHelper::is_session_verified`] and
///   [`SecurityHelper::is_user_verified`] (Web of Trust).
///
/// Sessions for which the policy denies access are filtered out of the reply;
/// if **all** requested chats are denied, a single `key_denied` is sent.
///
/// Runs in a detached task (spawned by [`process_event`]) so that a slow
/// responder does not block the event loop.
#[tracing::instrument(skip(low, state, event_tx, have), fields(txid = %txid))]
async fn respond_key_request(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    sender_session: i64,
    txid: String,
    chat_ids: Vec<i64>,
    have: Vec<String>,
) {
    let sender_user = match resolve_user_by_session(low, &chat_ids, sender_session).await {
        Some(u) => u,
        None => {
            tracing::warn!(
                sender_session,
                "key_request: cannot resolve user_id, ignoring"
            );
            return;
        }
    };

    let security = SecurityHelper {
        low: low.clone(),
        state: state.clone(),
        event_tx: event_tx.clone(),
    };

    let mut allowed_chats = Vec::new();
    let mut has_after_join = false;

    for chat_id in &chat_ids {
        let history_vis = low
            .store()
            .group_data_state(*chat_id)
            .await
            .map(|s| s.data.history_visibility)
            .unwrap_or(HistoryVisibility::AfterJoin);

        if history_vis == HistoryVisibility::AfterJoin {
            has_after_join = true;
            continue;
        }

        let allowed = match history_vis {
            HistoryVisibility::AllVerifiedSessions => {
                security
                    .is_session_verified(sender_user, sender_session)
                    .await
            }
            HistoryVisibility::AllVerifiedUsers => {
                security
                    .is_session_verified(sender_user, sender_session)
                    .await
                    && security.is_user_verified(sender_user).await
            }
            _ => false,
        };

        if allowed {
            allowed_chats.push(*chat_id);
        }
    }

    if allowed_chats.is_empty() {
        let reason = if has_after_join {
            "history_visibility_policy"
        } else {
            "not verified"
        };
        let _ = low
            .key_sharing()
            .send_denied(sender_user, sender_session, txid, reason.into())
            .await;
        return;
    }

    let have_set: std::collections::HashSet<String> = have.into_iter().collect();

    let mut to_send: Vec<(i64, String, String)> = Vec::new();
    for (cid, mid) in low.store().megolm_inbound_all().await {
        if !allowed_chats.contains(&cid) {
            continue;
        }
        let key = format!("{}:{}", cid, mid);
        if have_set.contains(&key) {
            continue;
        }
        if let Some(session) = low.store().megolm_inbound(cid, &mid).await {
            let mut s = session.lock().await;
            let first = s.first_known_index();
            if let Some(exported) = s.export_at(first) {
                to_send.push((cid, mid, exported.to_base64()));
            }
        }
    }

    if to_send.is_empty() {
        if let Err(e) = low
            .key_sharing()
            .send_done(sender_user, sender_session, txid, 0)
            .await
        {
            tracing::warn!(?e, "send_done(0) failed");
        }
        return;
    }

    let mut sent = 0u32;
    for (cid, mid, key) in to_send {
        if let Err(e) = low
            .key_sharing()
            .send_group_key(sender_user, sender_session, txid.clone(), cid, mid, key)
            .await
        {
            tracing::warn!(?e, "send_group_key failed");
            continue;
        }
        sent += 1;
    }

    if let Err(e) = low
        .key_sharing()
        .send_done(sender_user, sender_session, txid, sent)
        .await
    {
        tracing::warn!(?e, "send_done failed");
    }
}

/// Retry decryption for messages currently in `pending_decrypt[chat_id]`.
///
/// Called after a `group_key` is imported (via [`process_event`]). For every
/// pending message, tries [`crate::api::low::helpers::LockNetMegolmHelper::decrypt`]
/// with the now-available inbound session. Successful decryptions:
///
/// - update [`Message::text`] in the cache,
/// - remove the message from `pending_decrypt`,
/// - emit [`HighEvent::MessageDecrypted`] for each.
///
/// Failures are ignored — the message stays in `pending_decrypt` for the next
/// attempt (e.g. another `group_key` may arrive later).
async fn try_decrypt_pending(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    chat_id: i64,
) {
    let pending: Vec<(i64, crate::api::low::models::Encrypted)> = {
        let st = state.read().await;
        st.pending_decrypt_for(chat_id)
            .into_iter()
            .filter_map(|mid| {
                st.messages
                    .get(&mid)
                    .and_then(|m| m.encrypted_payload.clone())
                    .map(|enc| (mid, enc))
            })
            .collect()
    };

    if pending.is_empty() {
        return;
    }

    let mut decrypted: Vec<(i64, String)> = Vec::new();
    for (mid, enc) in pending {
        if let Ok(Some(text)) = low.megolm().decrypt(chat_id, &enc).await {
            decrypted.push((mid, text));
        }
    }

    if decrypted.is_empty() {
        return;
    }

    {
        let mut st = state.write().await;
        for (mid, text) in &decrypted {
            if let Some(m) = st.messages.get_mut(mid) {
                m.text = Some(text.clone());
            }
        }
        let decrypted_ids: std::collections::HashSet<i64> =
            decrypted.iter().map(|(id, _)| *id).collect();
        st.retain_pending_decrypt(chat_id, |mid| !decrypted_ids.contains(&mid));
    }

    for (mid, text) in decrypted {
        let _ = event_tx.send(HighEvent::MessageDecrypted {
            chat_id,
            message_id: mid,
            text,
        });
    }
}

/// Process a single low-level event.
///
/// Updates the internal cache and emits [`HighEvent`]s. This is the heart of the
/// agent's event-driven behavior. Variants:
///
/// - **`MessageCreate` / `MessageUpdate` / `MessageDelete`** — decrypt text
///   (or mark deleted), cache, emit [`HighEvent::NewMessage`] /
///   [`HighEvent::MessageUpdated`] / [`HighEvent::MessageDeleted`].
/// - **`ReactionAdd` / `ReactionRemove`** — update aggregation in
///   `state.messages`, emit [`HighEvent::ReactionAdded`] /
///   [`HighEvent::ReactionRemoved`].
/// - **`GroupCreated` / `GroupInviteCreated`** — cache the group/invite,
///   emit [`HighEvent::GroupCreated`] / [`HighEvent::InviteReceived`].
/// - **`GroupMembershipChanged`** — if the local policy is known, rotate the
///   Megolm outbound session and fan out the new key to remaining eligible
///   members; if the caller is the creator, push the updated policy blob to
///   the server. Emits [`HighEvent::GroupMembershipChanged`].
/// - **`GroupDataUpdated`** — re-fetch the group, decrypt the new policy,
///   emit [`HighEvent::PolicyChanged`].
/// - **`ToDevice`** — decrypt with Olm, then dispatch by payload type:
///   `group_key` → import inbound session, decrypt policy blob, emit
///   [`HighEvent::KeyImported`] (and [`HighEvent::KeyRequestImported`] if the
///   payload carries a `transaction_id`), retry pending decryptions;
///   `key_request` → emit [`HighEvent::KeyRequestReceived`] and spawn
///   [`respond_key_request`]; `key_request_done` / `key_denied` → emit the
///   corresponding `HighEvent::KeyRequest*`; verification messages → emit
///   [`HighEvent::SasMessage`] / [`HighEvent::QrMessage`]; SAS `start` is
///   additionally recorded in `state.pending_sas_starts`.
/// - **`CrossSigningReset` / `CrossSigningSignatureAdded`** — invalidate the
///   Web-of-Trust cache; on reset also drop the user from `verified_users`
///   and emit [`HighEvent::CrossSigningReset`].
/// - **`Reconnected` / `SessionExpired`** — forwarded as
///   [`HighEvent::Reconnected`] / [`HighEvent::SessionExpired`].
/// - **`Unknown`** — ignored.
///
/// The agent is the sole Olm decryptor for `to_device` — this is what
/// prevents races on the stateful Olm session.
async fn process_event(
    low: &Arc<LockNetLowAgent>,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &broadcast::Sender<HighEvent>,
    security: &Arc<SecurityHelper>,
    evt: LowEvent,
) -> Result<()> {
    match evt {
        LowEvent::MessageCreate(mc) => {
            tracing::trace!(
                chat_id = mc.chat_id,
                message_id = mc.message_id,
                "message_create"
            );
            let text = decrypt_text(low, mc.chat_id, &mc.encrypted).await;

            let mut st = state.write().await;
            let msg = st.message_create_to_domain(&mc, text);
            st.messages.insert(msg.id, msg.clone());
            let chat = st
                .groups
                .get(&mc.chat_id)
                .map(|g| {
                    Chat::new(
                        low.clone(),
                        g.clone(),
                        state.clone(),
                        event_tx.clone(),
                        security.clone(),
                    )
                })
                .unwrap_or_else(|| {
                    Chat::new(
                        low.clone(),
                        stub_group(mc.chat_id),
                        state.clone(),
                        event_tx.clone(),
                        security.clone(),
                    )
                });
            drop(st);

            let _ = event_tx.send(HighEvent::NewMessage { chat, message: msg });
        }
        LowEvent::MessageUpdate(u) => {
            tracing::trace!(
                chat_id = u.chat_id,
                message_id = u.message_id,
                "message_update"
            );
            let text = decrypt_text(low, u.chat_id, &u.encrypted).await;

            let mut st = state.write().await;
            let msg_opt = if let Some(m) = st.messages.get_mut(&u.message_id) {
                m.encrypted_payload = Some(u.encrypted.clone());
                m.edited_at = Some(u.edited_at);
                if text.is_some() {
                    m.text = text;
                }
                Some(m.clone())
            } else {
                None
            };
            let chat = st
                .groups
                .get(&u.chat_id)
                .map(|g| {
                    Chat::new(
                        low.clone(),
                        g.clone(),
                        state.clone(),
                        event_tx.clone(),
                        security.clone(),
                    )
                })
                .unwrap_or_else(|| {
                    Chat::new(
                        low.clone(),
                        stub_group(u.chat_id),
                        state.clone(),
                        event_tx.clone(),
                        security.clone(),
                    )
                });
            drop(st);

            if let Some(message) = msg_opt {
                let _ = event_tx.send(HighEvent::MessageUpdated { chat, message });
            }
        }
        LowEvent::MessageDelete(d) => {
            tracing::trace!(
                chat_id = d.chat_id,
                message_id = d.message_id,
                "message_delete"
            );
            let mut st = state.write().await;
            if let Some(m) = st.messages.get_mut(&d.message_id) {
                m.deleted = true;
                m.encrypted_payload = None;
                m.text = None;
            }
            drop(st);
            let _ = event_tx.send(HighEvent::MessageDeleted {
                chat_id: d.chat_id,
                message_id: d.message_id,
            });
        }
        LowEvent::ReactionAdd(r) => {
            tracing::trace!(
                chat_id = r.chat_id,
                message_id = r.message_id,
                user_id = r.user_id,
                "reaction_add"
            );
            let mut st = state.write().await;
            let user = st.resolve_user(r.user_id);
            if let Some(m) = st.messages.get_mut(&r.message_id) {
                if let Some(re) = m.reactions.iter_mut().find(|x| x.emoji == r.emoji) {
                    if !re.user_ids.contains(&r.user_id) {
                        re.user_ids.push(r.user_id);
                        re.count = re.user_ids.len();
                    }
                } else {
                    m.reactions.push(Reaction {
                        emoji: r.emoji.clone(),
                        user_ids: vec![r.user_id],
                        count: 1,
                    });
                }
            }
            drop(st);
            let _ = event_tx.send(HighEvent::ReactionAdded {
                chat_id: r.chat_id,
                message_id: r.message_id,
                user,
                emoji: r.emoji,
            });
        }
        LowEvent::ReactionRemove(r) => {
            tracing::trace!(
                chat_id = r.chat_id,
                message_id = r.message_id,
                user_id = r.user_id,
                "reaction_remove"
            );
            let mut st = state.write().await;
            let user = st.resolve_user(r.user_id);
            if let Some(m) = st.messages.get_mut(&r.message_id) {
                if let Some(idx) = m.reactions.iter().position(|x| x.emoji == r.emoji) {
                    let re = &mut m.reactions[idx];
                    re.user_ids.retain(|uid| *uid != r.user_id);
                    re.count = re.user_ids.len();
                    if re.count == 0 {
                        m.reactions.remove(idx);
                    }
                }
            }
            drop(st);
            let _ = event_tx.send(HighEvent::ReactionRemoved {
                chat_id: r.chat_id,
                message_id: r.message_id,
                user,
                emoji: r.emoji,
            });
        }
        LowEvent::GroupCreated(gc) => {
            tracing::trace!(chat_id = gc.group.id, "group_created");
            let g = {
                let mut st = state.write().await;
                let g = st.group_to_domain(&gc.group, low).await;
                st.groups.insert(g.id, g.clone());
                g
            };
            let _ = event_tx.send(HighEvent::GroupCreated { group: g });
        }
        LowEvent::GroupInviteCreated(gi) => {
            tracing::trace!(
                chat_id = gi.group_id,
                invite_id = gi.invite_id,
                "group_invite_created"
            );
            let mut st = state.write().await;
            let inv = st.invite_from_push(&gi);
            st.invites.insert(inv.id, inv.clone());
            drop(st);
            let _ = event_tx.send(HighEvent::InviteReceived { invite: inv });
        }
        LowEvent::GroupMembershipChanged(mc) => {
            tracing::trace!(chat_id = mc.group_id, user_id = mc.user_id, change = ?mc.change, "group_membership_changed");
            let user = {
                let mut st = state.write().await;
                let u = st.resolve_user(mc.user_id);
                st.groups.remove(&mc.group_id);
                u
            };

            let has_local_policy = low.store().group_data_state(mc.group_id).await.is_some();

            if has_local_policy {
                if let Ok(group_dto) = low.groups().info(mc.group_id).await {
                    if !group_dto.is_public {
                        let mut participant_ids: Vec<i64> = group_dto
                            .members
                            .as_ref()
                            .map(|list| list.iter().map(|m| m.user_id).collect())
                            .unwrap_or_default();

                        if matches!(mc.change, crate::api::low::models::MembershipChange::Left) {
                            participant_ids.retain(|uid| *uid != mc.user_id);
                        }

                        if !participant_ids.is_empty() {
                            if let Ok(info) = low.megolm().rotate(mc.group_id).await {
                                let policy = low
                                    .store()
                                    .group_data_state(mc.group_id)
                                    .await
                                    .map(|s| s.data.megolm_rotation_visibility)
                                    .unwrap_or(MegolmRotationVisibility::OnlyVerifiedUsers);
                                if let Err(e) = crate::api::high::group_key::fan_out_group_key(
                                    low,
                                    mc.group_id,
                                    &participant_ids,
                                    &info,
                                    policy,
                                    security,
                                )
                                .await
                                {
                                    tracing::warn!(?e, "membership rotation fan-out failed");
                                }

                                if let Ok(fresh) = low.groups().info(mc.group_id).await {
                                    if fresh.created_by == low.user_id() {
                                        if let Some(state_gd) =
                                            low.store().group_data_state(mc.group_id).await
                                        {
                                            if fresh.encrypted_group_data.as_deref()
                                                != Some(state_gd.blob.as_str())
                                            {
                                                let _ = low
                                                    .groups()
                                                    .update_group_data(mc.group_id, &state_gd.blob)
                                                    .await;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::debug!(
                    group_id = mc.group_id,
                    "membership changed but no local policy — skipping rotation (need key_request)"
                );
            }

            let _ = event_tx.send(HighEvent::GroupMembershipChanged {
                group_id: mc.group_id,
                change: mc.change,
                user,
            });
        }
        LowEvent::GroupDataUpdated { group_id } => {
            tracing::trace!(chat_id = group_id, "group_data_updated");
            if let Ok(dto) = low.groups().info(group_id).await {
                let g = {
                    let mut st = state.write().await;
                    if !st.groups.contains_key(&group_id) {
                        return Ok(());
                    }
                    let g = st.group_to_domain(&dto, low).await;
                    st.groups.insert(g.id, g.clone());
                    g
                };
                let _ = event_tx.send(HighEvent::PolicyChanged { group_id: g.id });
            }
        }
        LowEvent::ToDevice(payload) => {
            tracing::trace!(
                sender_session = payload.sender_session_id,
                sender_key = %payload.sender_key,
                "to_device"
            );
            let sender_session = payload.sender_session_id;
            if let Ok(Some(pt)) = low.olm().decrypt(payload).wait().await {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&pt) {
                    let t = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match t {
                        "ln.encryption.group_key" => {
                            let txid = val
                                .pointer("/content/transaction_id")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let chat_id = val.pointer("/content/chat_id").and_then(|v| v.as_i64());
                            let megolm_id = val
                                .pointer("/content/megolm_session_id")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            if low.megolm().decrypt_group_key(&pt).await.is_ok() {
                                if let (Some(cid), Some(mid)) = (chat_id, megolm_id) {
                                    let _ = event_tx.send(HighEvent::KeyImported {
                                        chat_id: cid,
                                        megolm_session_id: mid.clone(),
                                    });
                                    if let Some(tx) = txid {
                                        let _ = event_tx.send(HighEvent::KeyRequestImported {
                                            txid: tx,
                                            chat_id: cid,
                                            megolm_session_id: mid,
                                        });
                                    }
                                    try_decrypt_pending(low, state, event_tx, cid).await;
                                }
                            }
                        }
                        "ln.encryption.key_request_done" => {
                            let txid = val
                                .pointer("/content/transaction_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let count = val
                                .pointer("/content/count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let _ = event_tx.send(HighEvent::KeyRequestDone {
                                txid,
                                total_imported: count,
                            });
                        }
                        "ln.encryption.key_denied" => {
                            let txid = val
                                .pointer("/content/transaction_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let reason = val
                                .pointer("/content/reason")
                                .and_then(|v| v.as_str())
                                .unwrap_or("denied")
                                .to_string();
                            let _ = event_tx.send(HighEvent::KeyRequestDenied { txid, reason });
                        }
                        "ln.encryption.key_request" => {
                            let content = val.get("content").cloned().unwrap_or_default();
                            let chat_ids: Vec<i64> = content
                                .get("chat_ids")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
                                .unwrap_or_default();
                            let txid = content
                                .get("transaction_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let have: Vec<String> = content
                                .get("have")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let _ = event_tx.send(HighEvent::KeyRequestReceived {
                                from_user: 0,
                                from_session: sender_session,
                                chat_ids: chat_ids.clone(),
                            });

                            let low2 = low.clone();
                            let state2 = state.clone();
                            let event_tx2 = event_tx.clone();
                            tokio::spawn(async move {
                                respond_key_request(
                                    &low2,
                                    &state2,
                                    &event_tx2,
                                    sender_session,
                                    txid,
                                    chat_ids,
                                    have,
                                )
                                .await;
                            });
                        }
                        t if t.starts_with("ln.encryption.key.verification.qr.") => {
                            let _ = event_tx.send(HighEvent::QrMessage {
                                sender_user: 0,
                                sender_session,
                                content: val,
                            });
                        }
                        t if t.starts_with("ln.encryption.key.verification.") => {
                            if t == "ln.encryption.key.verification.start" {
                                let txid = val
                                    .pointer("/content/transaction_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if !txid.is_empty() {
                                    let mut st = state.write().await;
                                    st.pending_sas_starts.insert(
                                        txid,
                                        PendingSasStart {
                                            from_user: None,
                                            from_session: sender_session,
                                        },
                                    );
                                }
                            }
                            let _ = event_tx.send(HighEvent::SasMessage {
                                sender_user: 0,
                                sender_session,
                                content: val,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        LowEvent::CrossSigningReset(r) => {
            tracing::trace!(user_id = r.user_id, "cross_signing_reset");
            // 1. Cleanup local trust state, collect affected private chats.
            let affected_chats: Vec<i64> = {
                let mut st = state.write().await;
                st.verified_users.remove(&r.user_id);
                // Drop every session of this user from the verified-set —
                // otherwise `is_session_verified` would keep returning stale
                // `true` from cache, and `OnlyVerifiedSessions` fan-out would
                // continue delivering new keys to the compromised device.
                st.verified_sessions.retain(|_, uid| *uid != r.user_id);
                st.invalidate_trust_graph();
                st.groups
                    .values()
                    .filter(|g| !g.is_public && g.members.iter().any(|m| m.user.id == r.user_id))
                    .map(|g| g.id)
                    .collect()
            };

            // 2. For chats where the reset user was a member and the policy
            //    gates keys by verification, rotate Megolm and re-fan-out.
            //    Under a compromised device, the old session key is known to
            //    the attacker; without rotation, they'd keep decrypting new
            //    messages even after the reset.
            for chat_id in affected_chats {
                let Some(policy_state) = low.store().group_data_state(chat_id).await else {
                    // No policy blob locally — cannot rotate safely (we don't
                    // know the current visibility rules).
                    continue;
                };
                let policy = policy_state.data.megolm_rotation_visibility;
                if !matches!(
                    policy,
                    MegolmRotationVisibility::OnlyVerifiedSessions
                        | MegolmRotationVisibility::OnlyVerifiedUsers
                ) {
                    // `AllMembers`: reset does not change who gets keys.
                    continue;
                }

                let Ok(info) = low.megolm().rotate(chat_id).await else {
                    tracing::warn!(chat_id, "cs-reset: megolm rotate failed");
                    continue;
                };

                let Ok(dto) = low.groups().info(chat_id).await else {
                    continue;
                };
                let participant_ids: Vec<i64> = dto
                    .members
                    .as_ref()
                    .map(|list| list.iter().map(|m| m.user_id).collect())
                    .unwrap_or_default();
                if participant_ids.is_empty() {
                    continue;
                }

                if let Err(e) = crate::api::high::group_key::fan_out_group_key(
                    low,
                    chat_id,
                    &participant_ids,
                    &info,
                    policy,
                    security,
                )
                .await
                {
                    tracing::warn!(?e, chat_id, "cs-reset: fan-out after rotation failed");
                }
            }

            let _ = event_tx.send(HighEvent::CrossSigningReset { user_id: r.user_id });
        }
        LowEvent::Reconnected => {
            tracing::trace!("reconnected");
            let _ = event_tx.send(HighEvent::Reconnected);
        }
        LowEvent::SessionExpired => {
            tracing::trace!("session expired");
            let _ = event_tx.send(HighEvent::SessionExpired);
        }
        LowEvent::CrossSigningSignatureAdded(_) => {
            let mut st = state.write().await;
            st.invalidate_trust_graph();
        }
        LowEvent::Unknown { .. } => {}
    }
    Ok(())
}
