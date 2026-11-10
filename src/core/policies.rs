//! E2EE group policies.
//!
//! Policies are group metadata that must remain unreadable by the server.
//! They live locally in [`crate::core::crypto::CryptoStore`] and are
//! transmitted as an opaque `encrypted_group_data` blob (see [`GroupData`]).
//! The server stores and distributes the blob, but cannot read or tamper
//! with it without detection (XSalsa20-Poly1305 tag).

use serde::{Deserialize, Serialize};

/// Who is allowed to read the chat history.
///
/// Enforced client-side when answering `key_request` calls (see
/// `api::high::security`). The server cannot enforce these rules; a
/// malicious server can withhold keys, but cannot grant access that the
/// policy forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    /// History from before a session joined is never shared.
    ///
    /// `key_request` for older Megolm sessions is rejected with code
    /// `history_visibility_policy`.
    AfterJoin,

    /// Share history with any session whose `ed25519` key is signed by its
    /// owner's SSK (session-level verification).
    AllVerifiedSessions,

    /// Share history only with sessions that are session-verified **and**
    /// whose owner is trusted via the Web of Trust (transitive `USK → MSK`
    /// chain from our user).
    #[default]
    AllVerifiedUsers,
}

/// Which sessions receive a Megolm key on rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MegolmRotationVisibility {
    /// Every session of every group member.
    AllMembers,

    /// Only sessions whose `ed25519` key is signed by their owner's SSK.
    OnlyVerifiedSessions,

    /// Only sessions that are both session-verified and whose owner is
    /// trusted via the Web of Trust.
    #[default]
    OnlyVerifiedUsers,
}

/// Policy metadata for a group.
///
/// Serialized and encrypted with a `group_data_key` (delivered via
/// `ln.encryption.group_key`); the resulting blob is stored as
/// [`crate::api::low::models::Group::encrypted_group_data`]. The server
/// stores and distributes the blob as an opaque string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupData {
    /// Monotonic version. Clients reject blobs with a version lower than the
    /// locally cached one (anti-replay).
    pub version: u32,

    /// See [`HistoryVisibility`].
    pub history_visibility: HistoryVisibility,

    /// See [`MegolmRotationVisibility`].
    pub megolm_rotation_visibility: MegolmRotationVisibility,

    /// When this version was created.
    pub rotated_at: chrono::DateTime<chrono::Utc>,
}

/// Locally cached policy state for a group.
///
/// Holds the symmetric key that encrypts [`GroupData`] together with the
/// decrypted contents and the current blob. Rotated together with the
/// Megolm outbound session.
#[derive(Debug, Clone)]
pub struct GroupDataState {
    /// 32-byte symmetric key derived from the `group_data_key` in the
    /// `ln.encryption.group_key` payload.
    pub key: [u8; 32],

    /// Decrypted contents.
    pub data: GroupData,

    /// Encrypted blob produced by
    /// [`crate::core::crypto::group_data::encrypt_group_data`].
    /// Sent to the server as `Group.encrypted_group_data`; forwarded in the
    /// `group_key` payload as `content.group_data`.
    pub blob: String,
}

/// Metadata for Megolm outbound session auto-rotation.
///
/// Persisted in the [`crate::core::crypto::CryptoStore`] alongside the
/// session itself.
/// [`crate::api::low::helpers::megolm::LockNetMegolmHelper::ensure_session`]
/// checks `messages_sent >= count || now - created_at >= ttl` and rotates
/// the session when a threshold is crossed.
#[derive(Debug, Clone)]
pub struct MegolmOutboundMeta {
    /// Session identifier.
    pub session_id: String,

    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Number of messages encrypted with this session.
    pub messages_sent: u64,
}