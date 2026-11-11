//! WebSocket transport with configurable TLS.
//!
//! One connection is opened by `crate::core::runner::spawn` and used for
//! the entire lifetime of a [`crate::LockNetClient`]. TLS is provided by
//! `rustls` with native root certificates — the same backend used by the
//! HTTP side (`reqwest` with `rustls-tls`), so behaviour is consistent
//! between login/refresh and the WebSocket.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::core::config::LockNetConfig;
use crate::core::errors::{LockNetError, Result};

/// WebSocket stream type used throughout the crate.
pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A `ServerCertVerifier` that accepts every certificate and every TLS
/// signature.
///
/// Used **only** when [`LockNetConfig::accept_invalid_certs`] is `true`
/// (test setups against self-signed servers). Never enable it in
/// production: it disables authentication of the server entirely.
#[derive(Debug)]
struct DangerousVerifier;

impl ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a `rustls::ClientConfig` honoring `config.accept_invalid_certs`.
///
/// - **`false`** (default) — verify against the OS trust store loaded by
///   `rustls-native-certs`. If the store is empty, returns an error with a
///   hint (usually `ca-certificates` is missing on the system).
/// - **`true`** — install `DangerousVerifier`, which accepts any
///   certificate. Intended for tests only.
pub fn build_client_config(config: &LockNetConfig) -> Result<ClientConfig> {
    let builder = ClientConfig::builder();

    if config.accept_invalid_certs {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
            .with_no_client_auth());
    }

    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for cert in native.certs {
        // Individual bad certs are ignored; at least one must be loaded.
        let _ = roots.add(cert);
    }

    if roots.is_empty() {
        return Err(LockNetError::InvalidResponse(
            "no trusted root certificates loaded from the OS \
             (install ca-certificates, or set accept_invalid_certs = true for tests)"
                .into(),
        ));
    }

    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// Build the `tokio-tungstenite` connector wrapping our rustls config.
///
/// # Errors
///
/// Returns [`LockNetError::InvalidResponse`] if the root certificate store
/// could not be built (see [`build_client_config`]).
pub fn build_connector(config: &LockNetConfig) -> Result<Connector> {
    let tls = build_client_config(config)?;
    Ok(Connector::Rustls(Arc::new(tls)))
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
    .await?;
    Ok(ws)
}
