use std::sync::{Arc, OnceLock};

use base64::Engine;
use chrono::Utc;
use serde_json::json;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::api::high::agent::LockNetAgent;
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::command::{dispatch, Cmd, CmdSender};
use crate::api::low::event::Event;
use crate::api::session::{Credentials, LockNetSessionContext};
use crate::core::config::LockNetConfig;
use crate::core::crypto::{CryptoStore, InMemoryStore};
use crate::core::errors::{LockNetError, Result};
use crate::core::transport::http;

struct RunnerHandle {
    shutdown: mpsc::Sender<Cmd>,
    join: JoinHandle<()>,
}

pub struct LockNetClient {
    config: LockNetConfig,
    http: reqwest::Client,
    session: Arc<Mutex<Option<LockNetSessionContext>>>,
    low_agent: Option<Arc<LockNetLowAgent>>,
    high_agent: OnceLock<Arc<LockNetAgent>>,
    runner: Option<RunnerHandle>,
    event_tx: broadcast::Sender<Event>,
    store: Arc<dyn CryptoStore>,
}

impl LockNetClient {
    pub fn new(config: LockNetConfig) -> Self {
        Self::with_store(config, Arc::new(InMemoryStore::new()))
    }

    pub fn with_store(config: LockNetConfig, store: Arc<dyn CryptoStore>) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        let http = reqwest::Client::builder()
            .timeout(config.http_timeout)
            .user_agent(config.user_agent.clone())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("reqwest client");

        Self {
            config,
            http,
            session: Arc::new(Mutex::new(None)),
            low_agent: None,
            high_agent: OnceLock::new(),
            runner: None,
            event_tx,
            store,
        }
    }

    pub fn config(&self) -> &LockNetConfig { &self.config }

    pub fn session(&self) -> Option<LockNetSessionContext> {
        self.session.try_lock().ok().and_then(|g| g.clone())
    }

    pub fn get_low_agent(&self) -> Option<Arc<LockNetLowAgent>> { self.low_agent.clone() }

    pub fn get_agent(&self) -> Option<Arc<LockNetAgent>> {
        let low = self.low_agent.as_ref()?;
        let agent = self
            .high_agent
            .get_or_init(|| Arc::new(LockNetAgent::new(low.clone())));
        Some(agent.clone())
    }

    pub fn store(&self) -> Arc<dyn CryptoStore> { self.store.clone() }

    pub async fn connection_request(&mut self, creds: Credentials) -> Result<LockNetSessionContext> {
        if self.runner.is_some() {
            self.disconnect().await?;
        }

        let is_fresh = matches!(creds, Credentials::Login { .. } | Credentials::Register { .. });

        let (user_id, ajwt, rjwt) = match creds {
            Credentials::Login { username, password } => {
                let r = http::login(&self.config, &self.http, &username, &password).await?;
                (r.user_id, r.access_token, r.refresh_token)
            }
            Credentials::Register { username, password, display_name } => {
                let r = http::register(&self.config, &self.http, &username, &password, display_name.as_deref()).await?;
                (r.user_id, r.access_token, r.refresh_token)
            }
            Credentials::Session { refresh_jwt } => {
                let r = http::refresh(&self.config, &self.http, &refresh_jwt).await?;
                let user_id = extract_sub(&r.access_token)?;
                (user_id, r.access_token, r.refresh_token)
            }
        };

        let (raw_cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(256);
        let cmd_tx = CmdSender::new(raw_cmd_tx.clone(), self.config.request_timeout);
        let (auth_ok_tx, auth_ok_rx) = tokio::sync::oneshot::channel::<Result<i64>>();

        let join = crate::core::runner::spawn(
            self.config.clone(),
            self.http.clone(),
            cmd_rx,
            self.event_tx.clone(),
            self.session.clone(),
            ajwt.clone(),
            Some(auth_ok_tx),
        );

        let session_id = match auth_ok_rx.await {
            Ok(Ok(sid)) if sid != 0 => sid,
            Ok(Ok(_)) => {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                let _ = raw_cmd_tx.send(Cmd::Shutdown { reply: tx }).await;
                return Err(LockNetError::InvalidResponse("server did not return session_id in auth_ok".into()));
            }
            Ok(Err(e)) => {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                let _ = raw_cmd_tx.send(Cmd::Shutdown { reply: tx }).await;
                return Err(e);
            }
            Err(_) => return Err(LockNetError::RunnerDown),
        };

        let ctx = LockNetSessionContext {
            user_id,
            session_id,
            ajwt,
            rjwt,
            rtime: Utc::now(),
            space: self.config.space.clone(),
            vname: None,
            image: None,
        };
        *self.session.lock().await = Some(ctx.clone());

        let low_agent = Arc::new(LockNetLowAgent::new(
            user_id,
            session_id,
            cmd_tx.clone(),
            self.event_tx.clone(),
            self.store.clone(),
            self.config.default_history_visibility,
            self.config.default_megolm_rotation_visibility,
            self.config.megolm_rotation_message_count,
            self.config.megolm_rotation_ttl_secs,
        ));

        if is_fresh {
            let device_keys = {
                let account = self.store.account().await;
                let mut acc = account.lock().await;
                acc.generate_one_time_keys(50);
                let otks = acc.one_time_keys_b64();
                let keys = crate::api::low::models::DeviceKeys {
                    curve25519_key: acc.curve25519_public_b64(),
                    ed25519_key: acc.ed25519_public_b64(),
                    one_time_keys: otks,
                    signatures: std::collections::HashMap::new(),
                };
                acc.mark_keys_as_published();
                drop(acc);
                self.store.save_account().await;
                keys
            };

            let upload: Result<crate::api::low::models::OtkCounts> =
                dispatch(&cmd_tx, json!({ "type": "upload_keys", "data": device_keys })).await;

            if let Err(e) = upload {
                let (tx, _rx) = tokio::sync::oneshot::channel();
                let _ = raw_cmd_tx.send(Cmd::Shutdown { reply: tx }).await;
                *self.session.lock().await = None;
                return Err(e);
            }
        }

        if self.config.sync_on_connect {
            let _ = low_agent.events().sync_until_empty(100).await;
        }

        self.runner = Some(RunnerHandle { shutdown: raw_cmd_tx, join });
        self.low_agent = Some(low_agent);

        Ok(ctx)
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(high) = self.high_agent.take() {
            high.shutdown().await;
        }
        self.low_agent = None;
        if let Some(handle) = self.runner.take() {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _ = handle.shutdown.send(Cmd::Shutdown { reply: tx }).await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle.join).await;
        }
        *self.session.lock().await = None;
        Ok(())
    }
}

fn extract_sub(jwt: &str) -> Result<i64> {
    let payload = jwt.split('.').nth(1)
        .ok_or_else(|| LockNetError::InvalidResponse("jwt: no payload".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)
        .map_err(|_| LockNetError::InvalidResponse("jwt: bad b64".into()))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    v.get("sub").and_then(|s| s.as_str()).and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| LockNetError::InvalidResponse("jwt: no sub".into()))
}