//! SAS (emoji) verification flow, driven by [`crate::HighEvent::SasMessage`].

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::sync::broadcast;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::high::event::HighEvent;
use crate::api::low::agent::LockNetLowAgent;
use crate::core::errors::{LockNetError, Result};

const SAS_INFO_PREFIX: &str = "LOCKNET_ENCRYPTION_KEY_VERIFICATION_SAS_V1";
const SAS_START: &str = "ln.encryption.key.verification.start";
const SAS_ACCEPT: &str = "ln.encryption.key.verification.accept";
const SAS_KEY: &str = "ln.encryption.key.verification.key";
const SAS_MAC: &str = "ln.encryption.key.verification.mac";
const SAS_METHOD: &str = "ln.encryption.key.verification.sas.v1";

const SAS_EMOJI: [(&str, &str); 64] = [
    ("🐶", "Dog"),
    ("🐱", "Cat"),
    ("🦁", "Lion"),
    ("🐎", "Horse"),
    ("🦄", "Unicorn"),
    ("🐷", "Pig"),
    ("🐘", "Elephant"),
    ("🐰", "Rabbit"),
    ("🐼", "Panda"),
    ("🐓", "Rooster"),
    ("🐧", "Penguin"),
    ("🐢", "Turtle"),
    ("🐟", "Fish"),
    ("🐙", "Octopus"),
    ("🦋", "Butterfly"),
    ("🌷", "Flower"),
    ("🌳", "Tree"),
    ("🌵", "Cactus"),
    ("🍄", "Mushroom"),
    ("🌏", "Globe"),
    ("🌙", "Moon"),
    ("☁️", "Cloud"),
    ("🔥", "Fire"),
    ("🍌", "Banana"),
    ("🍎", "Apple"),
    ("🍓", "Strawberry"),
    ("🌽", "Corn"),
    ("🍕", "Pizza"),
    ("🎂", "Cake"),
    ("❤️", "Heart"),
    ("🙂", "Smiley"),
    ("🤖", "Robot"),
    ("🎩", "Hat"),
    ("👓", "Glasses"),
    ("🔧", "Spanner"),
    ("🎅", "Santa"),
    ("👍", "Thumbs Up"),
    ("☂️", "Umbrella"),
    ("⌛", "Hourglass"),
    ("⏰", "Clock"),
    ("🎁", "Gift"),
    ("💡", "Light Bulb"),
    ("📕", "Book"),
    ("✏️", "Pencil"),
    ("📎", "Paperclip"),
    ("🔒", "Lock"),
    ("🔑", "Key"),
    ("🔨", "Hammer"),
    ("☎️", "Telephone"),
    ("🏁", "Flag"),
    ("🚂", "Train"),
    ("🚲", "Bicycle"),
    ("✈️", "Aeroplane"),
    ("🚀", "Rocket"),
    ("🎸", "Guitar"),
    ("🎺", "Trumpet"),
    ("🔔", "Bell"),
    ("⚓", "Anchor"),
    ("🎧", "Headphones"),
    ("📁", "Folder"),
    ("📌", "Pin"),
    ("✂️", "Scissors"),
    ("🔐", "Lock with Key"),
    ("🔓", "Unlocked"),
];

/// One emoji from the SAS string.
#[derive(Debug, Clone)]
pub struct SasEmoji {
    /// The emoji character.
    pub symbol: &'static str,
    /// Its name, for accessibility.
    pub name: &'static str,
}

/// Current state of a [`SasFlow`].
#[derive(Debug, Clone)]
pub enum SasStatus {
    /// Initiator sent `start`; waiting for `accept`.
    WaitingAccept,
    /// Both sides exchanged keys; waiting for the peer's `key`.
    WaitingKey,
    /// Emoji are ready; waiting for `confirm_emoji`.
    NeedUserConfirmation { emoji: Vec<SasEmoji> },
    /// Emoji confirmed by both sides; waiting for peer's MAC.
    WaitingMac,
    /// MAC verified successfully.
    Verified,
    /// Flow was cancelled (peer rejected, MAC mismatch, or `abort`).
    Cancelled(String),
}

/// Result of [`SasFlow::next`].
#[derive(Debug)]
pub enum SasStep {
    /// Emoji are ready; call [`SasFlow::confirm_emoji`].
    Emoji(Vec<SasEmoji>),
    /// Both sides verified their MACs; peer is now trusted.
    Verified,
    /// Flow was cancelled.
    Cancelled(String),
}

struct SasHandshake {
    our_secret: StaticSecret,
    our_public: PublicKey,
    shared: Option<[u8; 32]>,
}

impl SasHandshake {
    fn new() -> Result<Self> {
        let sk = crate::core::crypto::random::random_bytes::<32>()?;
        let our_secret = StaticSecret::from(sk);
        let our_public = PublicKey::from(&our_secret);
        Ok(Self {
            our_secret,
            our_public,
            shared: None,
        })
    }

    fn public_b64(&self) -> String {
        b64_no_pad(self.our_public.as_bytes())
    }

    fn set_their_public(&mut self, their_pub_b64: &str) -> Result<()> {
        let raw = decode_b64(their_pub_b64)?;
        if raw.len() != 32 {
            return Err(LockNetError::InvalidResponse(format!(
                "sas peer key must be 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        let their = PublicKey::from(arr);
        self.shared = Some(self.our_secret.diffie_hellman(&their).to_bytes());
        Ok(())
    }

    fn shared_bytes(&self) -> Result<[u8; 32]> {
        self.shared.ok_or_else(|| {
            LockNetError::InvalidResponse("sas shared secret not established".into())
        })
    }

    fn generate_bytes(&self, info: &[u8], len: usize) -> Result<Vec<u8>> {
        let shared = self.shared_bytes()?;
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared);
        let mut okm = vec![0u8; len];
        hk.expand(info, &mut okm)
            .map_err(|e| LockNetError::InvalidResponse(format!("hkdf generate_bytes: {e}")))?;
        Ok(okm)
    }

    fn calculate_mac(&self, input: &[u8], info: &[u8]) -> Result<[u8; 32]> {
        use hmac::{Hmac, Mac};
        let shared = self.shared_bytes()?;
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared);
        let mut key = [0u8; 32];
        hk.expand(info, &mut key)
            .map_err(|e| LockNetError::InvalidResponse(format!("hkdf calculate_mac key: {e}")))?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
            .map_err(|e| LockNetError::InvalidResponse(format!("hmac key: {e}")))?;
        mac.update(input);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
    }
}

fn emoji_indices(bytes: &[u8]) -> [u8; 7] {
    debug_assert!(bytes.len() >= 6);
    let v: u64 = ((bytes[0] as u64) << 40)
        | ((bytes[1] as u64) << 32)
        | ((bytes[2] as u64) << 24)
        | ((bytes[3] as u64) << 16)
        | ((bytes[4] as u64) << 8)
        | (bytes[5] as u64);
    let v = v >> 6;
    let mut out = [0u8; 7];
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = (6 - i as u32) * 6;
        *slot = ((v >> shift) & 0x3F) as u8;
    }
    out
}

/// A single SAS verification flow.
///
/// Created by [`crate::SecurityHelper::sas_start`] (initiator) or
/// `sas_accept` (responder). Drive it with [`Self::next`] and
/// [`Self::confirm_emoji`].
///
/// The wire protocol is `ln.encryption.key.verification.{start,accept,key,mac}`,
/// sent through the Olm channel. Protocol messages arrive as
/// [`HighEvent::SasMessage`]; the flow only reads from that channel, so the
/// agent remains the sole Olm decryptor.
pub struct SasFlow {
    txid: String,
    to_user: i64,
    to_session: i64,
    handshake: Option<SasHandshake>,
    status: SasStatus,
    computed_emoji: Option<Vec<SasEmoji>>,
    low: Arc<LockNetLowAgent>,
    high_rx: broadcast::Receiver<HighEvent>,
    our_msk_b64: String,
    our_ed25519_b64: String,
    peer_ed25519_b64: Option<String>,
    peer_msk_b64: Option<String>,
}

impl SasFlow {
    /// Start a new flow as the initiator.
    ///
    /// Sends `ln.encryption.key.verification.start` immediately. The flow
    /// then waits for `accept`.
    pub async fn start(
        low: Arc<LockNetLowAgent>,
        high_rx: broadcast::Receiver<HighEvent>,
        to_user: i64,
        to_session: i64,
        our_msk_b64: String,
        our_ed25519_b64: String,
    ) -> Result<Self> {
        let txid = generate_txid()?;
        let flow = Self {
            txid: txid.clone(),
            to_user,
            to_session,
            handshake: Some(SasHandshake::new()?),
            status: SasStatus::WaitingAccept,
            computed_emoji: None,
            low,
            high_rx,
            our_msk_b64,
            our_ed25519_b64,
            peer_ed25519_b64: None,
            peer_msk_b64: None,
        };
        flow.send_sas_message(
            SAS_START,
            json!({
                "from_session": to_session.to_string(),
                "method": SAS_METHOD,
                "transaction_id": txid,
                "key_agreement_protocols": ["curve25519"],
                "hashes": ["sha256"],
                "message_authentication_codes": ["hkdf-hmac-sha256"],
                "short_authentication_string": ["emoji"],
            }),
        )
        .await?;
        Ok(flow)
    }

    /// Start a flow as the responder to an incoming `start`.
    ///
    /// Immediately sends `accept` and `key`, then waits for the peer's `key`.
    pub async fn start_as_responder(
        low: Arc<LockNetLowAgent>,
        high_rx: broadcast::Receiver<HighEvent>,
        txid: String,
        to_user: i64,
        to_session: i64,
        our_msk_b64: String,
        our_ed25519_b64: String,
    ) -> Result<Self> {
        let flow = Self {
            txid,
            to_user,
            to_session,
            handshake: Some(SasHandshake::new()?),
            status: SasStatus::WaitingKey,
            computed_emoji: None,
            low,
            high_rx,
            our_msk_b64,
            our_ed25519_b64,
            peer_ed25519_b64: None,
            peer_msk_b64: None,
        };
        flow.send_accept().await?;
        flow.send_key().await?;
        Ok(flow)
    }

    /// Transaction ID of this flow.
    pub fn transaction_id(&self) -> &str {
        &self.txid
    }

    /// The peer's user ID.
    pub fn peer_user_id(&self) -> i64 {
        self.to_user
    }

    /// The peer's session ID.
    pub fn peer_session_id(&self) -> i64 {
        self.to_session
    }

    /// Current status.
    pub fn check_status(&self) -> SasStatus {
        self.status.clone()
    }

    /// Computed emoji, if the flow has reached
    /// [`SasStatus::NeedUserConfirmation`].
    pub fn emoji(&self) -> Option<&[SasEmoji]> {
        self.computed_emoji.as_deref()
    }

    /// Set the peer's public keys (ed25519 identity + cross-signing MSK).
    ///
    /// Required before [`Self::confirm_emoji`] — the MAC verification needs
    /// both to recompute the peer's MACs and detect MITM.
    pub fn set_peer_keys(&mut self, peer_ed25519_b64: String, peer_msk_b64: String) {
        self.peer_ed25519_b64 = Some(peer_ed25519_b64);
        self.peer_msk_b64 = Some(peer_msk_b64);
    }

    /// Drive the flow one step forward.
    ///
    /// Returns [`SasStep::Emoji`] once the emoji are ready, then
    /// [`SasStep::Verified`] (or [`SasStep::Cancelled`]) after
    /// [`Self::confirm_emoji`] and the peer's MAC have been exchanged.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::Timeout`] if the peer does not respond within 30s.
    /// - [`LockNetError::RunnerDown`] if the event channel is closed.
    /// - [`LockNetError::InvalidResponse`] on malformed peer messages.
    #[tracing::instrument(skip(self), fields(txid = %self.txid, peer_user = self.to_user))]
    pub async fn next(&mut self) -> Result<SasStep> {
        loop {
            match &self.status {
                SasStatus::WaitingAccept => {
                    self.wait_for_sas(SAS_ACCEPT).await?;
                    self.send_key().await?;
                    self.status = SasStatus::WaitingKey;
                }
                SasStatus::WaitingKey => {
                    self.wait_for_key().await?;
                    let emoji = self.compute_emoji()?;
                    self.computed_emoji = Some(emoji.clone());
                    self.status = SasStatus::NeedUserConfirmation {
                        emoji: emoji.clone(),
                    };
                    return Ok(SasStep::Emoji(emoji));
                }
                SasStatus::NeedUserConfirmation { .. } => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                SasStatus::WaitingMac => match self.try_recv_mac().await? {
                    Some(true) => {
                        self.status = SasStatus::Verified;
                        return Ok(SasStep::Verified);
                    }
                    Some(false) => {
                        let r = "MAC mismatch".to_string();
                        self.status = SasStatus::Cancelled(r.clone());
                        return Ok(SasStep::Cancelled(r));
                    }
                    None => continue,
                },
                SasStatus::Verified => return Ok(SasStep::Verified),
                SasStatus::Cancelled(r) => return Ok(SasStep::Cancelled(r.clone())),
            }
        }
    }

    /// Confirm (or reject) the emoji, sending our MAC in the accept case.
    ///
    /// # Errors
    ///
    /// - [`LockNetError::InvalidArgument`] if called before the emoji are
    ///   ready, or if [`Self::set_peer_keys`] has not been called for the
    ///   accept case.
    pub async fn confirm_emoji(&mut self, accept: bool) -> Result<()> {
        if !matches!(self.status, SasStatus::NeedUserConfirmation { .. }) {
            return Err(LockNetError::InvalidArgument(
                "confirm_emoji called in wrong state".into(),
            ));
        }
        if !accept {
            self.status = SasStatus::Cancelled("user rejected".into());
            return Ok(());
        }
        if self.peer_ed25519_b64.is_none() || self.peer_msk_b64.is_none() {
            return Err(LockNetError::InvalidArgument(
                "set_peer_keys(ed25519, msk) must be called before confirm_emoji(true)".into(),
            ));
        }
        self.send_mac().await?;
        self.status = SasStatus::WaitingMac;
        Ok(())
    }

    /// Abort the flow, marking it as cancelled.
    pub async fn abort(&mut self) -> Result<()> {
        self.status = SasStatus::Cancelled("aborted".into());
        Ok(())
    }

    async fn send_accept(&self) -> Result<()> {
        self.send_sas_message(
            SAS_ACCEPT,
            json!({
                "transaction_id": self.txid,
                "method": SAS_METHOD,
                "key_agreement_protocol": "curve25519",
                "hash": "sha256",
                "message_authentication_code": "hkdf-hmac-sha256",
                "short_authentication_string": ["emoji"],
            }),
        )
        .await
    }

    async fn send_sas_message(&self, kind: &str, content: Value) -> Result<()> {
        let pt = json!({ "type": kind, "content": content }).to_string();
        self.low
            .olm()
            .send(self.to_user, self.to_session, pt)
            .wait()
            .await
    }

    async fn wait_for_sas(&mut self, expected_type: &str) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(LockNetError::Timeout(Duration::from_secs(30)));
            }
            match tokio::time::timeout(remaining, self.high_rx.recv()).await {
                Ok(Ok(HighEvent::SasMessage { content, .. })) => {
                    let t = content.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if t == expected_type {
                        let txid = content
                            .pointer("/content/transaction_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if txid == self.txid {
                            return Ok(content.get("content").cloned().unwrap_or(Value::Null));
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Err(LockNetError::Timeout(Duration::from_secs(30))),
            }
        }
    }

    async fn send_key(&self) -> Result<()> {
        let hs = self
            .handshake
            .as_ref()
            .ok_or_else(|| LockNetError::InvalidResponse("SAS handshake consumed".into()))?;
        let pub_b64 = hs.public_b64();
        self.send_sas_message(
            SAS_KEY,
            json!({
                "transaction_id": self.txid,
                "key": pub_b64,
            }),
        )
        .await
    }

    async fn wait_for_key(&mut self) -> Result<()> {
        let content = self.wait_for_sas(SAS_KEY).await?;
        let key_b64 = content
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LockNetError::InvalidResponse("no key".into()))?;
        let hs = self
            .handshake
            .as_mut()
            .ok_or_else(|| LockNetError::InvalidResponse("SAS handshake consumed".into()))?;
        hs.set_their_public(key_b64)?;
        Ok(())
    }

    fn compute_emoji(&self) -> Result<Vec<SasEmoji>> {
        let hs = self
            .handshake
            .as_ref()
            .ok_or_else(|| LockNetError::InvalidResponse("SAS handshake not established".into()))?;
        let info = format!("{}{}", SAS_INFO_PREFIX, self.txid);
        let bytes = hs.generate_bytes(info.as_bytes(), 6)?;
        let indices = emoji_indices(&bytes);
        let mut result = Vec::with_capacity(7);
        for idx in indices {
            let (sym, name) = SAS_EMOJI[idx as usize];
            result.push(SasEmoji { symbol: sym, name });
        }
        Ok(result)
    }

    async fn send_mac(&self) -> Result<()> {
        let hs = self
            .handshake
            .as_ref()
            .ok_or_else(|| LockNetError::InvalidResponse("SAS handshake not established".into()))?;
        let ed_mac = hs.calculate_mac(self.our_ed25519_b64.as_bytes(), b"ed25519")?;
        let msk_mac = hs.calculate_mac(self.our_msk_b64.as_bytes(), b"master")?;
        self.send_sas_message(
            SAS_MAC,
            json!({
                "transaction_id": self.txid,
                "mac": {
                    "ed25519": b64_no_pad(&ed_mac),
                    "master":  b64_no_pad(&msk_mac),
                }
            }),
        )
        .await
    }

    async fn try_recv_mac(&mut self) -> Result<Option<bool>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(Some(false));
            }
            match tokio::time::timeout(remaining, self.high_rx.recv()).await {
                Ok(Ok(HighEvent::SasMessage { content, .. })) => {
                    let t = content.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if t == SAS_MAC {
                        let txid = content
                            .pointer("/content/transaction_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if txid != self.txid {
                            continue;
                        }
                        let their_ed = content
                            .pointer("/content/mac/ed25519")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let their_msk = content
                            .pointer("/content/mac/master")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let peer_ed = self.peer_ed25519_b64.clone().ok_or_else(|| {
                            LockNetError::InvalidArgument("peer ed25519 not set".into())
                        })?;
                        let peer_msk = self.peer_msk_b64.clone().ok_or_else(|| {
                            LockNetError::InvalidArgument("peer msk not set".into())
                        })?;

                        let hs = self.handshake.as_ref().ok_or_else(|| {
                            LockNetError::InvalidResponse("SAS handshake not established".into())
                        })?;

                        use subtle::ConstantTimeEq;

                        let expected_ed =
                            b64_no_pad(&hs.calculate_mac(peer_ed.as_bytes(), b"ed25519")?);
                        let expected_msk =
                            b64_no_pad(&hs.calculate_mac(peer_msk.as_bytes(), b"master")?);

                        let their_ed_norm = normalize_b64(&their_ed);
                        let their_msk_norm = normalize_b64(&their_msk);

                        // Constant-time comparison: MACs must not leak timing info.
                        let ed_eq: bool = their_ed_norm
                            .as_bytes()
                            .ct_eq(expected_ed.as_bytes())
                            .into();
                        let msk_eq: bool = their_msk_norm
                            .as_bytes()
                            .ct_eq(expected_msk.as_bytes())
                            .into();
                        let ok = ed_eq & msk_eq;
                        return Ok(Some(ok));
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Ok(Some(false)),
            }
        }
    }
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

fn normalize_b64(s: &str) -> String {
    s.trim_end_matches('=').to_string()
}

fn generate_txid() -> Result<String> {
    crate::core::crypto::random::random_txid()
}
