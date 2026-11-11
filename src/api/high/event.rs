//! High-level events emitted by [`crate::LockNetAgent`].
//!
//! Unlike [`crate::api::low::Event`] (raw wire events), these are already
//! translated into domain objects: messages carry their decrypted text (if
//! available), chats have resolved member lists, and all multi-step flows
//! (key requests, verification) are surfaced as discrete progress events.

use super::models::{Chat, Group, Invite, Message, User};
use crate::api::low::models::MembershipChange;

/// An event broadcast by [`crate::LockNetAgent`].
///
/// Marked `#[non_exhaustive]`: new variants may be added without a breaking
/// change.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum HighEvent {
    /// A new message arrived in `chat`.
    NewMessage { chat: Chat, message: Message },

    /// A message was edited.
    MessageUpdated { chat: Chat, message: Message },

    /// A message was soft-deleted.
    MessageDeleted { chat_id: i64, message_id: i64 },

    /// A reaction was added.
    ReactionAdded {
        chat_id: i64,
        message_id: i64,
        user: User,
        emoji: String,
    },

    /// A reaction was removed.
    ReactionRemoved {
        chat_id: i64,
        message_id: i64,
        user: User,
        emoji: String,
    },

    /// A group was created.
    GroupCreated { group: Group },

    /// A user joined or left a group.
    GroupMembershipChanged {
        group_id: i64,
        change: MembershipChange,
        user: User,
    },

    /// An invitation to a group was received.
    InviteReceived { invite: Invite },

    /// The server indicated that a group's `encrypted_group_data` was
    /// updated. Re-fetch the chat (e.g. via [`crate::LockNetAgent::chat`]) to
    /// pick up the new policy.
    PolicyChanged { group_id: i64 },

    /// A user is now trusted via the Web of Trust (directly or transitively).
    UserVerified { user_id: i64 },

    /// A specific session is now verified.
    SessionVerified { user_id: i64, session_id: i64 },

    /// A user reset their cross-signing keys; cached trust data is stale.
    CrossSigningReset { user_id: i64 },

    /// A SAS protocol message arrived (start / accept / key / mac).
    SasMessage {
        sender_user: i64,
        sender_session: i64,
        content: serde_json::Value,
    },

    /// A QR protocol message arrived (scanned / confirm / mac).
    QrMessage {
        sender_user: i64,
        sender_session: i64,
        content: serde_json::Value,
    },

    /// A Megolm inbound session was imported into the local store.
    KeyImported {
        chat_id: i64,
        megolm_session_id: String,
    },

    /// A previously-undecryptable message is now decrypted (after a key
    /// arrived). `state.messages` is already updated; this event is purely
    /// for UI notification.
    MessageDecrypted {
        chat_id: i64,
        message_id: i64,
        text: String,
    },

    /// Another session sent an `ln.encryption.key_request`.
    KeyRequestReceived {
        from_user: i64,
        from_session: i64,
        chat_ids: Vec<i64>,
    },

    /// One reply to our own `key_request` was imported.
    KeyRequestImported {
        txid: String,
        chat_id: i64,
        megolm_session_id: String,
    },

    /// Our `key_request` was answered (`done`).
    KeyRequestDone { txid: String, total_imported: u32 },

    /// Our `key_request` was refused.
    KeyRequestDenied { txid: String, reason: String },

    /// The initial session was established.
    Connected { user_id: i64, session_id: i64 },

    /// The runner reconnected after a disconnect.
    Reconnected,

    /// The runner disconnected.
    Disconnected { reason: String },

    /// The session expired and could not be refreshed.
    SessionExpired,
}
