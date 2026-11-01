use std::collections::HashMap;
use serde_json::json;
use tokio::sync::mpsc;
use crate::api::low::command::{dispatch, dispatch_unit, Cmd};
use crate::api::low::models::*;
use crate::core::errors::Result;

pub struct LockNetBackupHelper { pub(crate) cmd_tx: mpsc::Sender<Cmd> }

impl LockNetBackupHelper {
    pub async fn versions(&self) -> Result<Vec<BackupVersion>> {
        #[derive(serde::Deserialize)] struct W { versions: Vec<BackupVersion> }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "backup_versions", "data": {} })).await?;
        Ok(w.versions)
    }
    pub async fn new_version(&self, algorithm: impl Into<String>, auth_data: serde_json::Value) -> Result<i32> {
        #[derive(serde::Deserialize)] struct W { version: i32 }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "backup_new", "data": { "algorithm": algorithm.into(), "auth_data": auth_data } })).await?;
        Ok(w.version)
    }
    pub async fn put(&self, version: i32, items: HashMap<String, serde_json::Value>) -> Result<u32> {
        #[derive(serde::Deserialize)] struct W { count: u32 }
        let w: W = dispatch(&self.cmd_tx, json!({ "type": "backup_put", "data": { "version": version, "items": items } })).await?;
        Ok(w.count)
    }
    pub async fn get(&self, version: i32) -> Result<BackupVersionData> {
        dispatch(&self.cmd_tx, json!({ "type": "backup_get", "data": { "version": version } })).await
    }
    pub async fn delete(&self, version: i32) -> Result<()> {
        dispatch_unit(&self.cmd_tx, json!({ "type": "backup_delete", "data": { "version": version } })).await
    }
}