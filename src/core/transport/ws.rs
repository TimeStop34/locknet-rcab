//! WebSocket transport with configurable TLS.
//!
//! One connection is opened by `crate::core::runner::spawn` and used for
//! the entire lifetime of a [`crate::LockNetClient`]. TLS verification uses
//! the system trust store (OpenSSL / Secure Transport / SChannel) unless
//! [`crate::LockNetConfig::accept_invalid_certs`] is enabled.

use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::core::config::LockNetConfig;
use crate::core::errors::{LockNetError, Result};

/// WebSocket stream type used throughout the crate.
pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Build a `native-tls` connector honoring `config.accept_invalid_certs`.
///
/// The connector uses the system trust store by default (OpenSSL on Linux,
/// Secure Transport on macOS, SChannel on Windows).
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the TLS backend fails to
/// initialize.
pub fn build_connector(config: &LockNetConfig) -> Result<Connector> {
    let mut builder = native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(config.accept_invalid_certs);
    builder.danger_accept_invalid_hostnames(config.accept_invalid_certs);
    let tls = builder
        .build()
        .map_err(|e| LockNetError::InvalidResponse(format!("tls connector: {e}")))?;
    Ok(Connector::NativeTls(tls))
}

/// Open a WebSocket connection to `config.ws_url()`.
///
/// # Errors
///
/// Returns [`LockNetError::Ws`] on transport or handshake failure.
pub async fn connect(config: &LockNetConfig) -> Result<Ws> {
    let connector = build_connector(config)?;
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
        config.ws_url(),
        None,
        false,
        Some(connector),
    )
    .await
    .map_err(LockNetError::Ws)?;
    Ok(ws)
}