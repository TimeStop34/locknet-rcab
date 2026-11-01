use serde_json::json;
use tokio::sync::mpsc;

use crate::api::low::command::{dispatch, dispatch_unit, Cmd};
use crate::api::low::models::*;
use crate::core::errors::Result;

pub struct LockNetGroupsHelper {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
}

impl LockNetGroupsHelper {
    pub async fn create(
        &self,
        name: impl Into<String>,
        is_public: bool,
        public_id: Option<String>,
        participant_ids: Vec<i64>,
    ) -> Result<Group> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            group: Group,
        }
        let w: Wrapper = dispatch(
            &self.cmd_tx,
            json!({
                "type": "create_group",
                "data": {
                    "name": name.into(),
                    "is_public": is_public,
                    "public_id": public_id,
                    "participant_ids": participant_ids,
                }
            }),
        )
        .await?;
        Ok(w.group)
    }

    pub async fn create_direct(&self, other_user_id: i64) -> Result<Group> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            group: Group,
        }
        let w: Wrapper = dispatch(
            &self.cmd_tx,
            json!({ "type": "create_direct", "data": { "user_id": other_user_id } }),
        )
        .await?;
        Ok(w.group)
    }

    pub async fn join(&self, public_id: impl Into<String>) -> Result<Group> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            group: Group,
        }
        let w: Wrapper = dispatch(
            &self.cmd_tx,
            json!({ "type": "join_group", "data": { "public_id": public_id.into() } }),
        )
        .await?;
        Ok(w.group)
    }

    pub async fn leave(&self, group_id: i64) -> Result<()> {
        dispatch_unit(
            &self.cmd_tx,
            json!({ "type": "leave_group", "data": { "group_id": group_id } }),
        )
        .await
    }

    pub async fn list(&self) -> Result<Vec<Group>> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            groups: Vec<Group>,
        }
        let w: Wrapper = dispatch(&self.cmd_tx, json!({ "type": "get_groups", "data": {} })).await?;
        Ok(w.groups)
    }

    pub async fn info(&self, group_id: i64) -> Result<Group> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            group: Group,
        }
        let w: Wrapper = dispatch(
            &self.cmd_tx,
            json!({ "type": "get_group_info", "data": { "group_id": group_id } }),
        )
        .await?;
        Ok(w.group)
    }

    pub async fn invites(&self) -> Result<Vec<Invite>> {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            invites: Vec<Invite>,
        }
        let w: Wrapper = dispatch(&self.cmd_tx, json!({ "type": "get_invites", "data": {} })).await?;
        Ok(w.invites)
    }

    pub async fn accept_invite(&self, invite_id: i64) -> Result<()> {
        dispatch_unit(
            &self.cmd_tx,
            json!({ "type": "accept_invite", "data": { "invite_id": invite_id } }),
        )
        .await
    }

    pub async fn decline_invite(&self, invite_id: i64) -> Result<()> {
        dispatch_unit(
            &self.cmd_tx,
            json!({ "type": "decline_invite", "data": { "invite_id": invite_id } }),
        )
        .await
    }
}