//! Groups and invitations helper.

use serde_json::json;
use crate::api::low::command::{dispatch, dispatch_unit, CmdSender};
use crate::api::low::models::*;
use crate::core::errors::Result;

/// Wraps the `/api/v1/groups` WebSocket methods.
///
/// Obtained via [`crate::LockNetLowAgent::groups`].
pub struct LockNetGroupsHelper { pub(crate) cmd_tx: CmdSender }

impl LockNetGroupsHelper {
    /// Create a group.
    ///
    /// The creator is the only member until invitations are accepted.
    /// `participant_ids` receive `group_invite_created` events, not
    /// membership. If `is_public` is `true`, `public_id` must be provided
    /// and unique across the server.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `duplicate_participants` if
    ///   `participant_ids` contains duplicates.
    /// - [`crate::LockNetError::Server`] with code `creator_in_participants` if the
    ///   creator appears in `participant_ids`.
    /// - [`crate::LockNetError::Server`] with code `public_id_required` if
    ///   `is_public` is `true` and `public_id` is `None`.
    /// - [`crate::LockNetError::Server`] with code `public_id_taken` if another
    ///   group already uses `public_id`.
    /// - [`crate::LockNetError::Server`] with code `users_not_found` if any ID in
    ///   `participant_ids` does not exist.
    pub async fn create(&self, name: impl Into<String>, is_public: bool, public_id: Option<String>, participant_ids: Vec<i64>) -> Result<Group> {
        #[derive(serde::Deserialize)] struct W { group: Group }
        let w: W = dispatch(&self.cmd_tx, json!({
            "type": "create_group",
            "data": { "name": name.into(), "is_public": is_public, "public_id": public_id, "participant_ids": participant_ids }
        })).await?;
        Ok(w.group)
    }

    /// Open a direct (1-to-1) chat with `other_user_id`.
    ///
    /// The other user receives a `group_invite_created` event. The group is
    /// private, not public.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `self_direct` if
    ///   `other_user_id` equals the current user.
    /// - [`crate::LockNetError::Server`] with code `user_not_found`.
    pub async fn create_direct(&self, other_user_id: i64) -> Result<Group> {
        #[derive(serde::Deserialize)] struct W { group: Group }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "create_direct", "data": { "user_id": other_user_id } })).await?;
        Ok(w.group)
    }

    /// Join a public group by `public_id`.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `group_not_public` if the group
    ///   does not exist or is not public.
    /// - [`crate::LockNetError::Server`] with code `already_member`.
    pub async fn join(&self, public_id: impl Into<String>) -> Result<Group> {
        #[derive(serde::Deserialize)] struct W { group: Group }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "join_group", "data": { "public_id": public_id.into() } })).await?;
        Ok(w.group)
    }

    /// Leave a group.
    ///
    /// If the caller is the creator, the group is deleted and every member
    /// loses access.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `not_member`.
    /// - [`crate::LockNetError::Server`] with code `group_not_found`.
    pub async fn leave(&self, group_id: i64) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "leave_group", "data": { "group_id": group_id } })).await
    }

    /// List all groups the current user is a member of.
    pub async fn list(&self) -> Result<Vec<Group>> {
        #[derive(serde::Deserialize)] struct W { groups: Vec<Group> }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "get_groups", "data": {} })).await?;
        Ok(w.groups)
    }

    /// Fetch a single group's metadata.
    ///
    /// For a public group the caller is not a member of, `members` is `None`
    /// (but `member_count` is set). For a private group, non-members get
    /// `group_not_found`.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `group_not_found` if the group
    ///   does not exist, or is private and the caller is not a member.
    pub async fn info(&self, group_id: i64) -> Result<Group> {
        #[derive(serde::Deserialize)] struct W { group: Group }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "get_group_info", "data": { "group_id": group_id } })).await?;
        Ok(w.group)
    }

    /// List pending invitations for the current user.
    pub async fn invites(&self) -> Result<Vec<Invite>> {
        #[derive(serde::Deserialize)] struct W { invites: Vec<Invite> }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "get_invites", "data": {} })).await?;
        Ok(w.invites)
    }

    /// Accept an invitation, becoming a member of the group.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `invite_not_found` if the invite
    ///   does not exist, was already processed, or the group was deleted.
    /// - [`crate::LockNetError::Server`] with code `already_member`.
    pub async fn accept_invite(&self, invite_id: i64) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "accept_invite", "data": { "invite_id": invite_id } })).await
    }

    /// Decline an invitation.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `invite_not_found` if the invite
    ///   does not exist or was already processed.
    pub async fn decline_invite(&self, invite_id: i64) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "decline_invite", "data": { "invite_id": invite_id } })).await
    }

    /// Upload a new `encrypted_group_data` blob for `group_id`.
    ///
    /// Only the group creator may call this. The server treats the blob as an
    /// opaque string: it cannot read or validate its contents. Other members
    /// receive a `group_data_updated` event.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::Server`] with code `group_not_found`.
    /// - [`crate::LockNetError::Server`] with code `forbidden` if the caller is not
    ///   the creator.
    pub async fn update_group_data(&self, group_id: i64, encrypted_group_data: impl Into<String>) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({
            "type": "update_group_data",
            "data": { "group_id": group_id, "encrypted_group_data": encrypted_group_data.into() }
        })).await
    }
}