use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::core::errors::LockNetError;

pub(crate) trait ReplyHandler: Send {
    fn resolve_ok(self: Box<Self>, value: Value);
    fn resolve_err(self: Box<Self>, err: LockNetError);
}

impl<T: DeserializeOwned + Send + 'static> ReplyHandler for oneshot::Sender<crate::core::errors::Result<T>> {
    fn resolve_ok(self: Box<Self>, value: Value) {
        match serde_json::from_value::<T>(value) {
            Ok(v) => { let _ = self.send(Ok(v)); }
            Err(e) => { let _ = self.send(Err(LockNetError::Json(e))); }
        }
    }
    fn resolve_err(self: Box<Self>, err: LockNetError) {
        let _ = self.send(Err(err));
    }
}

pub(crate) enum Cmd {
    Request { payload: Value, reply: Box<dyn ReplyHandler> },
    Shutdown { reply: oneshot::Sender<()> },
}

/// Обёртка над `mpsc::Sender<Cmd>` с per-request таймаутом.
///
/// Все helpers (`LockNetMessagesHelper` и т.д.) хранят `CmdSender` вместо
/// голого `mpsc::Sender<Cmd>` и вызывают `dispatch(&self.cmd_tx, payload)`.
/// Таймаут берётся из `LockNetConfig::request_timeout` и применяется
/// автоматически.
#[derive(Clone)]
pub(crate) struct CmdSender {
    tx: mpsc::Sender<Cmd>,
    timeout: Duration,
}

impl CmdSender {
    pub(crate) fn new(tx: mpsc::Sender<Cmd>, timeout: Duration) -> Self {
        Self { tx, timeout }
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Отправляет `payload` в runner и ждёт ответ с таймаутом.
///
/// - Runner закрыт → `RunnerDown`.
/// - Runner не ответил за `cmd_tx.timeout()` → `Timeout`.
/// - Runner ответил ошибкой → `Server { code, message }`.
pub(crate) async fn dispatch<T: DeserializeOwned + Send + 'static>(
    cmd_tx: &CmdSender,
    payload: Value,
) -> crate::core::errors::Result<T> {
    let (reply_tx, reply_rx) = oneshot::channel();
    cmd_tx
        .tx
        .send(Cmd::Request { payload, reply: Box::new(reply_tx) })
        .await
        .map_err(|_| LockNetError::RunnerDown)?;

    let timeout = cmd_tx.timeout;
    match tokio::time::timeout(timeout, reply_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(LockNetError::RunnerDown),
        Err(_) => Err(LockNetError::Timeout(timeout)),
    }
}

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
            // Принимаем запрос и дропаем reply, не резолвя.
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
            // Держим reply handler — dispatch должен таймаутнуть.
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