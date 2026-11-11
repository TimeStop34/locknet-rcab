//! WebSocket runner: a single connection loop with automatic reconnect.
//!
//! One [`crate::LockNetClient`] spawns exactly one runner. The runner:
//!
//! 1. Opens the WebSocket and performs the initial `auth` handshake.
//! 2. Dispatches server replies to pending requests by `id`.
//! 3. Forwards all unrecognized pushes to the `event_tx` broadcast channel.
//! 4. Keeps the connection alive with periodic ping frames.
//! 5. On disconnect, refreshes the access token and reconnects with
//!    exponential backoff until success or session expiry.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::api::low::command::{Cmd, ReplyHandler};
use crate::api::low::event::Event;
use crate::api::session::LockNetSessionContext;
use crate::core::config::LockNetConfig;
use crate::core::errors::{LockNetError, Result};
use crate::core::transport::{http, ws};

/// Map of in-flight request IDs to their reply handlers.
pub(crate) type Pending = Arc<Mutex<HashMap<String, Box<dyn ReplyHandler>>>>;

/// Shared session context (access token, refresh token, expiry).
pub(crate) type Session = Arc<Mutex<Option<LockNetSessionContext>>>;

/// Spawn the WebSocket runner task.
///
/// The returned [`JoinHandle`] resolves when the runner stops, either because
/// a [`Cmd::Shutdown`] was sent through the command channel or because the
/// session expired and could not be refreshed.
///
/// If `auth_ok_tx` is `Some`, the runner uses it to signal the outcome of the
/// **initial** `auth` handshake back to the caller (`Ok(session_id)` or
/// `Err(e)`). Subsequent reconnects do not use this channel; reconnect
/// failures are surfaced via [`Event::Reconnected`] / [`Event::SessionExpired`]
/// on `event_tx`.
pub(crate) fn spawn(
    config: LockNetConfig,
    http: reqwest::Client,
    cmd_rx: mpsc::Receiver<Cmd>,
    event_tx: broadcast::Sender<Event>,
    session: Session,
    initial_ajwt: String,
    auth_ok_tx: Option<oneshot::Sender<Result<i64>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(
            config,
            http,
            cmd_rx,
            event_tx.clone(),
            session,
            initial_ajwt,
            auth_ok_tx,
        )
        .await
        {
            tracing::warn!(?e, "runner stopped");
            let _ = event_tx.send(Event::SessionExpired);
        }
    })
}

async fn run(
    config: LockNetConfig,
    http: reqwest::Client,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    event_tx: broadcast::Sender<Event>,
    session: Session,
    initial_ajwt: String,
    mut auth_ok_tx: Option<oneshot::Sender<Result<i64>>>,
) -> Result<()> {
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let mut req_counter: u64 = 0;
    let mut ajwt = initial_ajwt;
    let mut backoff = config.reconnect_backoff_initial;
    let mut first_attempt = true;

    loop {
        let result = run_once(
            &config,
            &mut cmd_rx,
            &event_tx,
            &pending,
            &mut req_counter,
            &mut auth_ok_tx,
            &mut ajwt,
        )
        .await;
        drain_pending(&pending).await;

        match result {
            Ok(()) => return Ok(()),
            Err(e) if first_attempt => {
                if let Some(tx) = auth_ok_tx.take() {
                    let _ = tx.send(Err(e.clone_for_runner()));
                }
                return Err(e);
            }
            Err(_) => {}
        }

        tokio::time::sleep(backoff).await;
        backoff = next_backoff(backoff, config.reconnect_backoff_max);

        match refresh_ajwt(&config, &http, &session).await {
            Ok(new_ajwt) => {
                ajwt = new_ajwt;
                let _ = event_tx.send(Event::Reconnected);
                backoff = config.reconnect_backoff_initial;
            }
            Err(LockNetError::SessionExpired) => {
                let _ = event_tx.send(Event::SessionExpired);
                return Err(LockNetError::SessionExpired);
            }
            Err(e) => {
                tracing::warn!(?e, "refresh failed, will retry");
            }
        }
        first_attempt = false;
    }
}

async fn run_once(
    config: &LockNetConfig,
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    event_tx: &broadcast::Sender<Event>,
    pending: &Pending,
    req_counter: &mut u64,
    auth_ok_tx: &mut Option<oneshot::Sender<Result<i64>>>,
    ajwt: &mut String,
) -> Result<()> {
    let ws = ws::connect(config).await?;
    run_ws(
        config,
        ws,
        cmd_rx,
        event_tx,
        pending,
        req_counter,
        auth_ok_tx,
        ajwt,
    )
    .await
}

async fn run_ws(
    config: &LockNetConfig,
    mut ws: ws::Ws,
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    event_tx: &broadcast::Sender<Event>,
    pending: &Pending,
    req_counter: &mut u64,
    auth_ok_tx: &mut Option<oneshot::Sender<Result<i64>>>,
    ajwt: &mut String,
) -> Result<()> {
    let auth_msg = json!({ "type": "auth", "id": "auth-1", "data": { "token": ajwt } });
    ws.send(WsMessage::Text(auth_msg.to_string().into()))
        .await
        .map_err(LockNetError::Ws)?;

    let mut ping = tokio::time::interval(config.ws_ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut authenticated = false;

    loop {
        tokio::select! {
            msg = ws.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => return Err(LockNetError::Ws(e)),
                    None => return Err(LockNetError::RunnerDown),
                };
                let text = match msg {
                    WsMessage::Text(t) => t,
                    WsMessage::Ping(p) => { let _ = ws.send(WsMessage::Pong(p)).await; continue; }
                    WsMessage::Pong(_) => continue,
                    WsMessage::Close(_) => return Err(LockNetError::RunnerDown),
                    _ => continue,
                };
                let val: Value = match serde_json::from_str(text.as_str()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

                if msg_type == "auth_ok" {
                    authenticated = true;
                    if let Some(tx) = auth_ok_tx.take() {
                        let session_id = val.pointer("/data/session_id").and_then(|v| v.as_i64()).unwrap_or(0);
                        let _ = tx.send(Ok(session_id));
                    }
                    continue;
                }

                if msg_type == "error" {
                    let id = val.get("id").and_then(|v| v.as_str()).map(String::from);
                    if let Some(id) = id {
                        if let Some(reply) = pending.lock().await.remove(&id) {
                            let code = val.pointer("/data/id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                            let message = val.pointer("/data/error").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            reply.resolve_err(LockNetError::Server { code, message });
                            continue;
                        }
                    }
                    if !authenticated {
                        let code = val.pointer("/data/id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                        let message = val.pointer("/data/error").and_then(|v| v.as_str()).unwrap_or("auth failed").to_string();
                        if let Some(tx) = auth_ok_tx.take() {
                            let _ = tx.send(Err(LockNetError::Server { code: code.clone(), message: message.clone() }));
                        }
                        return Err(LockNetError::Unauthorized(format!("{code}: {message}")));
                    }
                    let _ = event_tx.send(Event::parse(val));
                    continue;
                }

                let id = val.get("id").and_then(|v| v.as_str()).map(String::from);
                if let Some(id) = id {
                    if let Some(reply) = pending.lock().await.remove(&id) {
                        reply.resolve_ok(val.get("data").cloned().unwrap_or(Value::Null));
                        continue;
                    }
                }
                let _ = event_tx.send(Event::parse(val));
            }
            cmd = cmd_rx.recv(), if authenticated => {
                match cmd {
                    Some(Cmd::Shutdown { reply }) => {
                        let _ = reply.send(());
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    Some(Cmd::Request { mut payload, reply }) => {
                        *req_counter += 1;
                        let req_id = format!("r{}", *req_counter);
                        if let Some(obj) = payload.as_object_mut() {
                            obj.insert("id".into(), json!(req_id));
                        }
                        pending.lock().await.insert(req_id, reply);
                        if let Err(e) = ws.send(WsMessage::Text(payload.to_string().into())).await {
                            return Err(LockNetError::Ws(e));
                        }
                    }
                    None => {
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                }
            }
            _ = ping.tick() => {
                if let Err(e) = ws.send(WsMessage::Ping(Vec::new().into())).await {
                    return Err(LockNetError::Ws(e));
                }
            }
        }
    }
}

async fn drain_pending(pending: &Pending) {
    let mut map = pending.lock().await;
    for (_, reply) in map.drain() {
        reply.resolve_err(LockNetError::RunnerDown);
    }
}

/// Compute the next reconnect delay: `current * 2`, capped at `max`.
///
/// Exposed as `pub(crate)` so the doubling and capping behavior can be
/// unit-tested without actually sleeping or triggering network errors.
pub(crate) fn next_backoff(
    current: std::time::Duration,
    max: std::time::Duration,
) -> std::time::Duration {
    (current * 2).min(max)
}

async fn refresh_ajwt(
    config: &LockNetConfig,
    http: &reqwest::Client,
    session: &Session,
) -> Result<String> {
    let rjwt = {
        let s = session.lock().await;
        s.as_ref()
            .map(|c| c.rjwt.clone())
            .ok_or(LockNetError::NotConnected)?
    };
    let resp = http::refresh(config, http, &rjwt).await?;
    {
        let mut s = session.lock().await;
        if let Some(ctx) = s.as_mut() {
            ctx.ajwt = resp.access_token.clone();
            ctx.rjwt = resp.refresh_token;
            ctx.rtime = chrono::Utc::now();
        }
    }
    Ok(resp.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn backoff_doubles() {
        let max = Duration::from_secs(60);
        assert_eq!(
            next_backoff(Duration::from_secs(1), max),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(2), max),
            Duration::from_secs(4)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(4), max),
            Duration::from_secs(8)
        );
    }

    #[test]
    fn backoff_caps_at_max() {
        let max = Duration::from_secs(60);
        assert_eq!(
            next_backoff(Duration::from_secs(40), max),
            Duration::from_secs(60)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(60), max),
            Duration::from_secs(60)
        );
        assert_eq!(
            next_backoff(Duration::from_secs(120), max),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn backoff_with_zero_current_is_zero() {
        let max = Duration::from_secs(60);
        assert_eq!(next_backoff(Duration::ZERO, max), Duration::ZERO);
    }

    #[test]
    fn backoff_with_max_zero() {
        let max = Duration::ZERO;
        assert_eq!(next_backoff(Duration::from_secs(5), max), Duration::ZERO);
    }
}
