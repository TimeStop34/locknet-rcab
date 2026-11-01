use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::{oneshot, Mutex};

use crate::core::errors::{LockNetError, Result};

const STATUS_PENDING: u8 = 0;
const STATUS_READY: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStatus {
    Pending,
    Ready,
}

pub struct SimpleFlow<T> {
    result: Arc<Mutex<Option<Result<T>>>>,
    status: Arc<AtomicU8>,
    rx: oneshot::Receiver<()>,
}

impl<T: Send + 'static> SimpleFlow<T> {
    pub fn spawn<F>(f: F) -> Self
    where
        F: Future<Output = Result<T>> + Send + 'static,
    {
        let result = Arc::new(Mutex::new(None));
        let status = Arc::new(AtomicU8::new(STATUS_PENDING));
        let (tx, rx) = oneshot::channel();

        let result_c = result.clone();
        let status_c = status.clone();

        tokio::spawn(async move {
            let res = f.await;
            *result_c.lock().await = Some(res);
            status_c.store(STATUS_READY, Ordering::SeqCst);
            let _ = tx.send(());
        });

        Self { result, status, rx }
    }

    pub fn check_status(&self) -> FlowStatus {
        if self.status.load(Ordering::SeqCst) == STATUS_READY {
            FlowStatus::Ready
        } else {
            FlowStatus::Pending
        }
    }

    pub fn try_take(&self) -> Option<Result<T>> {
        self.result.try_lock().ok().and_then(|mut g| g.take())
    }

    pub async fn wait(self) -> Result<T> {
        let _ = self.rx.await;
        let mut g = self.result.lock().await;
        g.take().unwrap_or(Err(LockNetError::RunnerDown))
    }
}

impl<T: Send + 'static> Future for SimpleFlow<T> {
    type Output = Result<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.rx).poll(cx) {
            Poll::Ready(_) => match this.result.try_lock() {
                Ok(mut g) => Poll::Ready(g.take().unwrap_or(Err(LockNetError::RunnerDown))),
                Err(_) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            Poll::Pending => Poll::Pending,
        }
    }
}