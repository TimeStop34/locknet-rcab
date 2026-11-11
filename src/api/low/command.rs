//! Request dispatch to the WebSocket runner.
//!
//! Requests travel from API methods through an `mpsc` channel to the runner,
//! which assigns an `id`, sends the JSON envelope, and resolves a
//! [`oneshot`] reply when the matching response arrives (or the configured
//! timeout expires).

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::core::errors::LockNetError;

/// Type-erased reply handler stored in the runner's `pending` map.
///
/// Implemented for `oneshot::Sender<Result<T>>` so the runner can resolve
/// replies without knowing the concrete response type.
pub(crate) trait ReplyHandler: Send {
    /// Deliver a successful response payload.
    fn resolve_ok(self: Box<Self>, value: Value);
    /// Deliver an error (transport, timeout, or server error).
    fn resolve_err(self: Box<Self>, err: LockNetError);
}

impl<T: DeserializeOwned + Send + 'static> ReplyHandler
    for oneshot::Sender<crate::core::errors::Result<T>>
{
    fn resolve_ok(self: Box<Self>, value: Value) {
        match serde_json::from_value::<T>(value) {
            Ok(v) => {
                let _ = self.send(Ok(v));
            }
            Err(e) => {
                let _ = self.send(Err(LockNetError::Json(e)));
            }
        }
    }
    fn resolve_err(self: Box<Self>, err: LockNetError) {
        let _ = self.send(Err(err));
    }
}

/// Commands sent from API methods to the runner.
pub(crate) enum Cmd {
    /// Send a request and resolve `reply` with the server's response.
    Request {
        payload: Value,
        reply: Box<dyn ReplyHandler>,
    },

    /// Shut down the runner gracefully.
    Shutdown { reply: oneshot::Sender<()> },
}

/// Handle to the runner's command channel, carrying a per-request timeout.
///
/// All low-level helpers hold a `CmdSender` (not a raw `mpsc::Sender<Cmd>`)
/// so that [`dispatch`] can apply
/// [`crate::LockNetConfig::request_timeout`] automatically.
#[derive(Clone)]
pub(crate) struct CmdSender {
    tx: mpsc::Sender<Cmd>,
    timeout: Duration,
}

impl CmdSender {
    pub(crate) fn new(tx: mpsc::Sender<Cmd>, timeout: Duration) -> Self {
        Self { tx, timeout }
    }
}

/// Send `payload` to the runner and await the reply.
///
/// The `id` field of `payload` is assigned by the runner, not by the caller.
///
/// # Errors
///
/// - [`LockNetError::RunnerDown`] if the runner channel is closed or the
///   reply future is dropped without a value.
/// - [`LockNetError::Timeout`] if no reply arrives within the configured
///   `request_timeout`.
/// - [`LockNetError::Server`] if the server returned an `error` envelope.
/// - [`LockNetError::Json`] if the payload cannot be deserialized into `T`.
pub(crate) async fn dispatch<T: DeserializeOwned + Send + 'static>(
    cmd_tx: &CmdSender,
    payload: Value,
) -> crate::core::errors::Result<T> {
    let (reply_tx, reply_rx) = oneshot::channel();
    cmd_tx
        .tx
        .send(Cmd::Request {
            payload,
            reply: Box::new(reply_tx),
        })
        .await
        .map_err(|_| LockNetError::RunnerDown)?;

    let timeout = cmd_tx.timeout;
    match tokio::time::timeout(timeout, reply_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(LockNetError::RunnerDown),
        Err(_) => Err(LockNetError::Timeout(timeout)),
    }
}

/// Like [`dispatch`], but discards the response payload.
///
/// Used by methods that only signal success (`delete_message`, `add_reaction`,
/// `upload_cross_signing_keys`, …).
pub(crate) async fn dispatch_unit(
    cmd_tx: &CmdSender,
    payload: Value,
) -> crate::core::errors::Result<()> {
    let _: Value = dispatch(cmd_tx, payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn dispatch_succeeds_when_reply_arrives() {
        let (tx, mut rx) = mpsc::channel::<Cmd>(8);
        let cmd_tx = CmdSender::new(tx, Duration::from_secs(1));

        tokio::spawn(async move {
            if let Some(Cmd::Request { reply, .. }) = rx.recv().await {
                reply.resolve_ok(json!({"ok": true}));
            }
        });

        let result: crate::core::errors::Result<serde_json::Value> =
            dispatch(&cmd_tx, json!({"ping": "ping"})).await;
        let v = result.expect("ok");
        assert_eq!(v["ok"], true);
    }

    #[tokio::test]
    async fn dispatch_returns_runner_down_when_channel_closed() {
        let (tx, rx) = mpsc::channel::<Cmd>(8);
        drop(rx);
        let cmd_tx = CmdSender::new(tx, Duration::from_secs(1));

        let result: crate::core::errors::Result<serde_json::Value> =
            dispatch(&cmd_tx, json!({})).await;
        match result {
            Err(LockNetError::RunnerDown) => {}
            other => panic!("expected RunnerDown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_returns_runner_down_when_reply_dropped() {
        let (tx, mut rx) = mpsc::channel::<Cmd>(8);
        let cmd_tx = CmdSender::new(tx, Duration::from_secs(1));

        tokio::spawn(async move {
            let _ = rx.recv().await;
        });

        let result: crate::core::errors::Result<serde_json::Value> =
            dispatch(&cmd_tx, json!({})).await;
        match result {
            Err(LockNetError::RunnerDown) => {}
            other => panic!("expected RunnerDown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_times_out_when_runner_never_replies() {
        let (tx, mut rx) = mpsc::channel::<Cmd>(8);
        let timeout = Duration::from_millis(150);
        let cmd_tx = CmdSender::new(tx, timeout);

        tokio::spawn(async move {
            let _held = rx.recv().await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let start = tokio::time::Instant::now();
        let result: crate::core::errors::Result<serde_json::Value> =
            dispatch(&cmd_tx, json!({})).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "timeout must fire quickly, took {elapsed:?}"
        );
        match result {
            Err(LockNetError::Timeout(d)) => assert_eq!(d, timeout),
            other => panic!("expected Timeout, got {other:?}"),
        }
    }
}
