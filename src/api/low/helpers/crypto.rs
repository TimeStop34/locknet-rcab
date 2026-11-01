use serde_json::json;
use tokio::sync::mpsc;

use crate::api::low::command::{dispatch, dispatch_unit, Cmd};
use crate::api::low::models::*;
use crate::core::errors::Result;

pub struct LockNetCryptoHelper {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
}

impl LockNetCryptoHelper {
    pub async fn upload_cross_signing_keys(&self, keys: CrossSigningKeys) -> Result<()> {
        dispatch_unit(
            &self.cmd_tx,
            json!({
                "type": "upload_cross_signing_keys",
                "data": {
                    "master_key": keys.master_key,
                    "self_signing_key": keys.self_signing_key,
                    "user_signing_key": keys.user_signing_key,
                }
            }),
        )
        .await
    }

    pub async fn upload_signatures(&self, signatures: Signatures) -> Result<SignaturesAck> {
        dispatch(
            &self.cmd_tx,
            json!({
                "type": "upload_signatures",
                "data": {
                    "user_signatures": signatures.user_signatures,
                    "device_signatures": signatures.device_signatures,
                }
            }),
        )
        .await
    }

    pub async fn query_cross_signing_keys(&self, user_ids: Vec<i64>) -> Result<CrossSigningQuery> {
        dispatch(
            &self.cmd_tx,
            json!({ "type": "query_cross_signing_keys", "data": { "user_ids": user_ids } }),
        )
        .await
    }

    pub async fn reset_cross_signing_keys(
        &self,
        password: impl Into<String>,
    ) -> Result<ResetResult> {
        dispatch(
            &self.cmd_tx,
            json!({ "type": "reset_cross_signing_keys", "data": { "password": password.into() } }),
        )
        .await
    }

    pub async fn send_to_device(&self, messages: ToDeviceMessages) -> Result<ToDeviceAck> {
        dispatch(
            &self.cmd_tx,
            json!({ "type": "send_to_device", "data": { "messages": messages } }),
        )
        .await
    }
}