//! QR-code verification flow.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::sync::broadcast;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::low::event::Event;
use crate::api::low::helpers::olm::LockNetOlmHelper;
use crate::core::errors::{LockNetError, Result};

const QR_PREFIX: &str = "LockNetProtocol";
const QR_VERSION: &str = "v1.0";
const QR_HKDF_INFO: &[u8] = b"LOCKNET_ENCRYPTION_QR_VERIFICATION_V1";

const QR_SCANNED: &str = "ln.encryption.key.verification.qr.scanned";
const QR_CONFIRM: &str = "ln.encryption.key.verification.qr.confirm";
const QR_MAC: &str = "ln.encryption.key.verification.qr.mac";

const QR_WAIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Verification mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrMode {
    /// User-to-user verification. MAC covers each side's MSK.
    UserToUser,
    /// Self-device verification where the MSK is already trusted.
    /// MAC covers each device's ed25519.
    SelfDeviceTrusted,
    /// Self-device verification where the MSK is not yet trusted.
    /// Cryptographically identical to [`QrMode::SelfDeviceTrusted`]; the
    /// difference is semantic (whether the MSK is promoted to trusted on
    /// success).
    SelfDeviceUntrusted,
}

impl QrMode {
    fn to_u8(self) -> u8 {
        match self {
            QrMode::UserToUser => 0,
            QrMode::SelfDeviceTrusted => 1,
            QrMode::SelfDeviceUntrusted => 2,
        }
    }

    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(QrMode::UserToUser),
            1 => Ok(QrMode::SelfDeviceTrusted),
            2 => Ok(QrMode::SelfDeviceUntrusted),
            other => Err(LockNetError::InvalidArgument(format!("qr: invalid mode {other}"))),
        }
    }

    fn mac_target(self) -> MacTarget {
        match self {
            QrMode::UserToUser => MacTarget::MasterKey,
            QrMode::SelfDeviceTrusted | QrMode::SelfDeviceUntrusted => MacTarget::Ed25519,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MacTarget {
    MasterKey,
    Ed25519,
}

/// A QR code to render for display.
#[derive(Debug, Clone)]
pub struct QrCode {
    /// Verification mode.
    pub mode: QrMode,
    /// Transaction ID.
    pub transaction_id: String,
    /// Raw QR string (`LockNetProtocol;v1.0;<mode>;<txid>;<eph_pub_b64>;<secret_b64>`).
    pub raw: String,
}

/// Result of a [`QrFlow`] step.
#[derive(Debug)]
pub enum QrStep {
    /// Handshake finished; call [`QrFlow::exchange_mac`] next.
    Confirmed,
    /// Peer's MAC verified; verification is complete.
    Verified,
    /// Flow was cancelled (secret mismatch, MAC mismatch, or `cancel`).
    Cancelled(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QrRole {
    Displayer,
    Scanner,
}

#[derive(Debug, Clone)]
enum InternalState {
    WaitingScanned,
    WaitingConfirm,
    WaitingMac,
    Done,
    Cancelled(String),
}

/// A single QR verification flow.
///
/// Created by [`crate::api::low::helpers::verification::LockNetVerificationHelper::qr_display`]
/// (displayer) or `qr_scan` (scanner). Drive it with [`Self::next`] and
/// [`Self::exchange_mac`].
///
/// The wire protocol is `ln.encryption.key.verification.qr.{scanned,confirm,mac}`,
/// sent through the Olm channel. The shared secret is X25519 using an
/// ephemeral key on each side.
pub struct QrFlow {
    txid: String,
    mode: QrMode,
    role: QrRole,
    to_user: i64,
    to_session: i64,
    our_msk_b64: String,
    our_ed25519_b64: String,

    eph_secret: Option<StaticSecret>,
    peer_eph_pub: Option<PublicKey>,
    shared: Option<[u8; 32]>,
    mac_key: Option<[u8; 32]>,
    scan_secret: Option<[u8; 8]>,

    olm: Arc<LockNetOlmHelper>,
    event_rx: broadcast::Receiver<Event>,
    state: InternalState,
}

impl QrFlow {
    /// Start as the **displayer** (the side that shows the QR code).
    ///
    /// Returns the QR string to render and a flow in `WaitingScanned` state.
    pub async fn display(
        mode: QrMode,
        olm: Arc<LockNetOlmHelper>,
        event_rx: broadcast::Receiver<Event>,
        to_user: i64,
        to_session: i64,
        our_msk_b64: String,
        our_ed25519_b64: String,
    ) -> Result<(QrCode, QrFlow)> {
        let txid = generate_txid();
        let (raw, eph_secret, secret) = qr_generate(mode, &txid);

        let code = QrCode {
            mode,
            transaction_id: txid.clone(),
            raw,
        };

        let flow = QrFlow {
            txid,
            mode,
            role: QrRole::Displayer,
            to_user,
            to_session,
            our_msk_b64,
            our_ed25519_b64,
            eph_secret: Some(eph_secret),
            peer_eph_pub: None,
            shared: None,
            mac_key: None,
            scan_secret: Some(secret),
            olm,
            event_rx,
            state: InternalState::WaitingScanned,
        };

        Ok((code, flow))
    }

    /// Start as the **scanner** (the side that scans the QR code).
    ///
    /// Immediately sends `qr.scanned` to the displayer. The returned flow
    /// is in `WaitingConfirm` state.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if `qr_raw` is malformed.
    pub async fn scan(
        qr_raw: &str,
        olm: Arc<LockNetOlmHelper>,
        event_rx: broadcast::Receiver<Event>,
        to_user: i64,
        to_session: i64,
        our_msk_b64: String,
        our_ed25519_b64: String,
    ) -> Result<QrFlow> {
        let (mode, txid, peer_eph_pub, secret) = qr_parse(qr_raw)?;

        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).expect("getrandom");
        let our_eph_secret = StaticSecret::from(sk_bytes);
        let our_eph_pub = PublicKey::from(&our_eph_secret);

        let shared = our_eph_secret.diffie_hellman(&peer_eph_pub).to_bytes();

        let flow = QrFlow {
            txid: txid.clone(),
            mode,
            role: QrRole::Scanner,
            to_user,
            to_session,
            our_msk_b64,
            our_ed25519_b64,
            eph_secret: None,
            peer_eph_pub: Some(peer_eph_pub),
            shared: Some(shared),
            mac_key: None,
            scan_secret: None,
            olm,
            event_rx,
            state: InternalState::WaitingConfirm,
        };

        flow.send_scanned(&our_eph_pub, &secret).await?;

        Ok(flow)
    }

    /// Transaction ID of this flow.
    pub fn transaction_id(&self) -> &str { &self.txid }

    /// Verification mode.
    pub fn mode(&self) -> QrMode { self.mode }

    /// Derived MAC key, once the handshake is complete.
    pub fn mac_key(&self) -> Option<&[u8; 32]> { self.mac_key.as_ref() }

    /// Drive the flow one step forward.
    ///
    /// - Displayer: waits for `qr.scanned`, verifies the scan secret,
    ///   computes the MAC key, sends `qr.confirm`. Returns [`QrStep::Confirmed`].
    /// - Scanner: waits for `qr.confirm`, computes the MAC key. Returns
    ///   [`QrStep::Confirmed`].
    ///
    /// Then call [`Self::exchange_mac`].
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Timeout`] if the peer does not respond (120s).
    /// - [`LockNetError::RunnerDown`] if the Olm channel is closed.
    /// - [`LockNetError::InvalidResponse`] on malformed peer messages.
    pub async fn next(&mut self) -> Result<QrStep> {
        match self.state.clone() {
            InternalState::WaitingScanned => {
                if self.role != QrRole::Displayer {
                    return Err(LockNetError::InvalidArgument(
                        "next: not in WaitingScanned (role mismatch)".into(),
                    ));
                }

                let content = self.wait_for_qr(QR_SCANNED).await?;
                let peer_pub_b64 = content
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| LockNetError::InvalidResponse("qr.scanned: no public_key".into()))?
                    .to_string();
                let peer_secret_b64 = content
                    .get("secret")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| LockNetError::InvalidResponse("qr.scanned: no secret".into()))?;

                let expected_secret = self
                    .scan_secret
                    .ok_or_else(|| LockNetError::InvalidResponse("scan_secret missing".into()))?;
                let received_secret = decode_b64(peer_secret_b64)?;
                if received_secret.len() != 8 || received_secret != expected_secret {
                    self.state = InternalState::Cancelled("secret mismatch".into());
                    return Ok(QrStep::Cancelled("secret mismatch".into()));
                }

                let peer_pub_bytes = decode_b64(&peer_pub_b64)?;
                if peer_pub_bytes.len() != 32 {
                    self.state = InternalState::Cancelled("invalid peer eph pubkey length".into());
                    return Ok(QrStep::Cancelled("invalid peer eph pubkey length".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&peer_pub_bytes);
                let peer_eph_pub = PublicKey::from(arr);
                self.peer_eph_pub = Some(peer_eph_pub);

                let eph_secret = self
                    .eph_secret
                    .as_ref()
                    .ok_or_else(|| LockNetError::InvalidResponse("eph_secret missing".into()))?;
                let shared = eph_secret.diffie_hellman(&peer_eph_pub).to_bytes();
                self.shared = Some(shared);
                self.mac_key = Some(compute_mac_key(&shared)?);

                self.send_confirm().await?;
                self.state = InternalState::WaitingMac;
                Ok(QrStep::Confirmed)
            }
            InternalState::WaitingConfirm => {
                if self.role != QrRole::Scanner {
                    return Err(LockNetError::InvalidArgument(
                        "next: not in WaitingConfirm (role mismatch)".into(),
                    ));
                }
                let _ = self.wait_for_qr(QR_CONFIRM).await?;
                let shared = self
                    .shared
                    .ok_or_else(|| LockNetError::InvalidResponse("shared missing".into()))?;
                self.mac_key = Some(compute_mac_key(&shared)?);
                self.state = InternalState::WaitingMac;
                Ok(QrStep::Confirmed)
            }
            InternalState::WaitingMac => Err(LockNetError::InvalidArgument(
                "next: handshake finished, use exchange_mac()".into(),
            )),
            InternalState::Done => Ok(QrStep::Verified),
            InternalState::Cancelled(reason) => Ok(QrStep::Cancelled(reason)),
        }
    }

    /// Send our MAC and verify the peer's MAC.
    ///
    /// `peer_key_b64` is the key the peer MACs: for [`QrMode::UserToUser`],
    /// the peer's MSK; for self-device modes, the peer's ed25519.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if called before the handshake
    ///   completes.
    /// - [`LockNetError::Timeout`] if the peer does not respond (120s).
    pub async fn exchange_mac(&mut self, peer_key_b64: String) -> Result<QrStep> {
        if !matches!(self.state, InternalState::WaitingMac) {
            return Err(LockNetError::InvalidArgument(
                "exchange_mac: not in WaitingMac state".into(),
            ));
        }

        let mac_key = self
            .mac_key
            .ok_or_else(|| LockNetError::InvalidResponse("mac_key missing".into()))?;

        let our_key_str = match self.mode.mac_target() {
            MacTarget::MasterKey => self.our_msk_b64.clone(),
            MacTarget::Ed25519 => self.our_ed25519_b64.clone(),
        };
        let our_key_bytes = decode_b64(&our_key_str)?;
        let our_mac = compute_hmac(&mac_key, &our_key_bytes)?;

        let content = json!({
            "transaction_id": self.txid,
            "mac": b64_no_pad(&our_mac),
        });
        self.send_qr_message(QR_MAC, content).await?;

        let recv_content = self.wait_for_qr(QR_MAC).await?;
        let their_mac_b64 = recv_content
            .get("mac")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LockNetError::InvalidResponse("qr.mac: no mac".into()))?;

        let peer_key_bytes = decode_b64(&peer_key_b64)?;
        let expected_mac = compute_hmac(&mac_key, &peer_key_bytes)?;
        let their_mac_bytes = decode_b64(their_mac_b64)?;

        if their_mac_bytes != expected_mac {
            self.state = InternalState::Cancelled("MAC mismatch".into());
            return Ok(QrStep::Cancelled("MAC mismatch".into()));
        }

        self.state = InternalState::Done;
        Ok(QrStep::Verified)
    }

    /// Cancel the flow locally.
    pub async fn cancel(&mut self) -> Result<()> {
        if matches!(self.state, InternalState::Done | InternalState::Cancelled(_)) {
            return Ok(());
        }
        self.state = InternalState::Cancelled("cancelled by user".into());
        Ok(())
    }

    async fn send_scanned(&self, our_eph_pub: &PublicKey, secret: &[u8; 8]) -> Result<()> {
        let content = json!({
            "transaction_id": self.txid,
            "public_key": b64_no_pad(our_eph_pub.as_bytes()),
            "secret": b64_no_pad(secret),
        });
        self.send_qr_message(QR_SCANNED, content).await
    }

    async fn send_confirm(&self) -> Result<()> {
        let content = json!({ "transaction_id": self.txid });
        self.send_qr_message(QR_CONFIRM, content).await
    }

    async fn send_qr_message(&self, kind: &str, content: Value) -> Result<()> {
        let pt = json!({ "type": kind, "content": content }).to_string();
        self.olm.send(self.to_user, self.to_session, pt).wait().await
    }

    async fn wait_for_qr(&mut self, expected_type: &str) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + QR_WAIT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(LockNetError::Timeout(QR_WAIT_TIMEOUT));
            }
            match tokio::time::timeout(remaining, self.event_rx.recv()).await {
                Ok(Ok(Event::ToDevice(payload))) => {
                    if let Some(pt) = self.olm.decrypt(payload).wait().await? {
                        if let Ok(val) = serde_json::from_str::<Value>(&pt) {
                            if val.get("type").and_then(|v| v.as_str()) == Some(expected_type) {
                                let txid = val
                                    .pointer("/content/transaction_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if txid == self.txid {
                                    return Ok(val.get("content").cloned().unwrap_or(Value::Null));
                                }
                            }
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Err(LockNetError::Timeout(QR_WAIT_TIMEOUT)),
            }
        }
    }
}

fn qr_generate(mode: QrMode, txid: &str) -> (String, StaticSecret, [u8; 8]) {
    let mut sk_bytes = [0u8; 32];
    getrandom::getrandom(&mut sk_bytes).expect("getrandom");
    let eph_secret = StaticSecret::from(sk_bytes);
    let eph_pub = PublicKey::from(&eph_secret);

    let mut secret = [0u8; 8];
    getrandom::getrandom(&mut secret).expect("getrandom");

    let raw = format!(
        "{};{};{};{};{};{}",
        QR_PREFIX,
        QR_VERSION,
        mode.to_u8(),
        txid,
        b64_no_pad(eph_pub.as_bytes()),
        b64_no_pad(&secret),
    );

    (raw, eph_secret, secret)
}

fn qr_parse(raw: &str) -> Result<(QrMode, String, PublicKey, [u8; 8])> {
    let parts: Vec<&str> = raw.split(';').collect();
    if parts.len() != 6 {
        return Err(LockNetError::InvalidArgument(format!(
            "qr: expected 6 parts, got {}",
            parts.len()
        )));
    }
    if parts[0] != QR_PREFIX {
        return Err(LockNetError::InvalidArgument(format!(
            "qr: bad prefix {:?}",
            parts[0]
        )));
    }
    if parts[1] != QR_VERSION {
        return Err(LockNetError::InvalidArgument(format!(
            "qr: bad version {:?}",
            parts[1]
        )));
    }
    let mode_u8: u8 = parts[2]
        .parse()
        .map_err(|_| LockNetError::InvalidArgument(format!("qr: bad mode {:?}", parts[2])))?;
    let mode = QrMode::from_u8(mode_u8)?;
    let txid = parts[3].to_string();

    let eph_pub_bytes = decode_b64(parts[4])?;
    if eph_pub_bytes.len() != 32 {
        return Err(LockNetError::InvalidArgument(
            "qr: eph_pub must be 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&eph_pub_bytes);
    let eph_pub = PublicKey::from(arr);

    let secret_bytes = decode_b64(parts[5])?;
    if secret_bytes.len() != 8 {
        return Err(LockNetError::InvalidArgument(
            "qr: secret must be 8 bytes".into(),
        ));
    }
    let mut secret = [0u8; 8];
    secret.copy_from_slice(&secret_bytes);

    Ok((mode, txid, eph_pub, secret))
}

fn compute_mac_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), shared);
    let mut okm = [0u8; 32];
    hk.expand(QR_HKDF_INFO, &mut okm)
        .map_err(|e| LockNetError::InvalidResponse(format!("hkdf qr mac_key: {e}")))?;
    Ok(okm)
}

fn compute_hmac(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|e| LockNetError::InvalidResponse(format!("hmac qr: {e}")))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

fn b64_no_pad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| LockNetError::InvalidResponse(format!("b64: {e}")))
}

fn generate_txid() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("getrandom");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}