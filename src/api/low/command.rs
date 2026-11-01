use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::oneshot;

use crate::core::errors::LockNetError;

pub(crate) trait ReplyHandler: Send {
    fn resolve_ok(self: Box<Self>, value: Value);
    fn resolve_err(self: Box<Self>, err: LockNetError);
}

impl<T: DeserializeOwned + Send + 'static> ReplyHandler for oneshot::Sender<crate::core::errors::Result<T>> {
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

pub(crate) enum Cmd {
    Request {
        payload: Value,
        reply: Box<dyn ReplyHandler>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

pub(crate) async fn dispatch<T: DeserializeOwned + Send + 'static>(
    cmd_tx: &tokio::sync::mpsc::Sender<Cmd>,
    payload: Value,
) -> crate::core::errors::Result<T> {
    let (reply_tx, reply_rx) = oneshot::channel();
    cmd_tx
        .send(Cmd::Request {
            payload,
            reply: Box::new(reply_tx),
        })
        .await
        .map_err(|_| LockNetError::RunnerDown)?;
    reply_rx.await.map_err(|_| LockNetError::RunnerDown)?
}

pub(crate) async fn dispatch_unit(
    cmd_tx: &tokio::sync::mpsc::Sender<Cmd>,
    payload: Value,
) -> crate::core::errors::Result<()> {
    let _: Value = dispatch(cmd_tx, payload).await?;
    Ok(())
}