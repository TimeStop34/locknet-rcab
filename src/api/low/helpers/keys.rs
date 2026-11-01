use serde_json::json;
use tokio::sync::mpsc;

use crate::api::low::command::{dispatch, Cmd};
use crate::api::low::models::*;
use crate::core::errors::Result;

pub struct LockNetKeysHelper {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
}

impl LockNetKeysHelper {
    pub async fn upload(&self, keys: DeviceKeys) -> Result<OtkCounts> {
        dispatch(&self.cmd_tx, json!({ "type": "upload_keys", "data": keys })).await
    }

    pub async fn query(&self, user_ids: Vec<i64>) -> Result<QueryKeysResult> {
        dispatch(
            &self.cmd_tx,
            json!({ "type": "query_keys", "data": { "user_ids": user_ids } }),
        )
        .await
    }

    pub async fn claim_one_time_key(
        &self,
        user_id: i64,
        session_id: i64,
        algorithm: Option<String>,
    ) -> Result<Otk> {
        dispatch(
            &self.cmd_tx,
            json!({
                "type": "claim_one_time_key",
                "data": {
                    "user_id": user_id,
                    "session_id": session_id,
                    "algorithm": algorithm.unwrap_or_else(|| "curve25519".to_string()),
                }
            }),
        )
        .await
    }
}