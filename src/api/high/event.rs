use crate::api::low::models::MembershipChange;

use super::models::{Chat, Group, Invite, Message, User};

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum HighEvent {
    NewMessage {
        chat: Chat,
        message: Message,
    },
    MessageUpdated {
        chat: Chat,
        message: Message,
    },
    MessageDeleted {
        chat_id: i64,
        message_id: i64,
    },
    ReactionAdded {
        chat_id: i64,
        message_id: i64,
        user: User,
        emoji: String,
    },
    ReactionRemoved {
        chat_id: i64,
        message_id: i64,
        user: User,
        emoji: String,
    },
    GroupCreated {
        group: Group,
    },
    GroupMembershipChanged {
        group_id: i64,
        change: MembershipChange,
        user: User,
    },
    InviteReceived {
        invite: Invite,
    },
    UserVerified {
        user_id: i64,
    },
    SessionVerified {
        user_id: i64,
        session_id: i64,
    },
    CrossSigningReset {
        user_id: i64,
    },
    SasMessage {
        sender_user: i64,
        sender_session: i64,
        content: serde_json::Value,
    },
    QrMessage {
        sender_user: i64,
        sender_session: i64,
        content: serde_json::Value,
    },
    KeyImported {
        chat_id: i64,
        megolm_session_id: String,
    },
    KeyRequestReceived {
        from_user: i64,
        from_session: i64,
        chat_ids: Vec<i64>,
    },
    Connected {
        user_id: i64,
        session_id: i64,
    },
    Reconnected,
    Disconnected {
        reason: String,
    },
    SessionExpired,
}