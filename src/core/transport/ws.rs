use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::core::config::LockNetConfig;
use crate::core::errors::{LockNetError, Result};

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub fn build_connector(config: &LockNetConfig) -> Result<Connector> {
    let mut builder = native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(config.accept_invalid_certs);
    builder.danger_accept_invalid_hostnames(config.accept_invalid_certs);
    let tls = builder
        .build()
        .map_err(|e| LockNetError::InvalidResponse(format!("tls connector: {e}")))?;
    Ok(Connector::NativeTls(tls))
}

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