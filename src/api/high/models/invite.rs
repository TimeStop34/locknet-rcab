//! Group invitations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use super::group::Group;
use super::user::User;

/// An invitation to join a group.
///
/// Produced by [`crate::LockNetAgent::invites`] or received via
/// [`crate::HighEvent::InviteReceived`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Invite ID (used to accept or decline).
    pub id: i64,
    /// The group being joined. May be partially populated (metadata only,
    /// no members) if the group is not yet in the local cache.
    pub group: Group,
    /// Who sent the invitation.
    pub inviter: User,
    /// When the invitation was created.
    pub created_at: Option<DateTime<Utc>>,
}