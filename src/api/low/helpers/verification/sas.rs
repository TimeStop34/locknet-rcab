use std::sync::Arc;
use std::time::Duration;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use vodozemac::sas::{EstablishedSas, Sas};
use vodozemac::Curve25519PublicKey;
use crate::api::low::event::Event;
use crate::api::low::helpers::olm::LockNetOlmHelper;
use crate::core::crypto::CryptoStore;
use crate::core::errors::{LockNetError, Result};

const SAS_INFO_PREFIX: &str = "LOCKNET_ENCRYPTION_KEY_VERIFICATION_SAS_V1";
const SAS_START: &str = "ln.encryption.key.verification.start";
const SAS_ACCEPT: &str = "ln.encryption.key.verification.accept";
const SAS_KEY: &str = "ln.encryption.key.verification.key";
const SAS_MAC: &str = "ln.encryption.key.verification.mac";
const SAS_METHOD: &str = "ln.encryption.key.verification.sas.v1";

const SAS_EMOJI: [(&str, &str); 64] = [
    ("🐶","Dog"),("🐱","Cat"),("🦁","Lion"),("🐎","Horse"),("🦄","Unicorn"),("🐷","Pig"),("🐘","Elephant"),("🐰","Rabbit"),
    ("🐼","Panda"),("🐓","Rooster"),("🐧","Penguin"),("🐢","Turtle"),("🐟","Fish"),("🐙","Octopus"),("🦋","Butterfly"),("🌷","Flower"),
    ("🌳","Tree"),("🌵","Cactus"),("🍄","Mushroom"),("🌏","Globe"),("🌙","Moon"),("☁️","Cloud"),("🔥","Fire"),("🍌","Banana"),
    ("🍎","Apple"),("🍓","Strawberry"),("🌽","Corn"),("🍕","Pizza"),("🎂","Cake"),("❤️","Heart"),("🙂","Smiley"),("🤖","Robot"),
    ("🎩","Hat"),("👓","Glasses"),("🔧","Spanner"),("🎅","Santa"),("👍","Thumbs Up"),("☂️","Umbrella"),("⌛","Hourglass"),("⏰","Clock"),
    ("🎁","Gift"),("💡","Light Bulb"),("📕","Book"),("✏️","Pencil"),("📎","Paperclip"),("🔒","Lock"),("🔑","Key"),("🔨","Hammer"),
    ("☎️","Telephone"),("🏁","Flag"),("🚂","Train"),("🚲","Bicycle"),("✈️","Aeroplane"),("🚀","Rocket"),("🎸","Guitar"),("🎺","Trumpet"),
    ("🔔","Bell"),("⚓","Anchor"),("🎧","Headphones"),("📁","Folder"),("📌","Pin"),("✂️","Scissors"),("🔐","Lock with Key"),("🔓","Unlocked"),
];

#[derive(Debug, Clone)]
pub struct SasEmoji { pub symbol: &'static str, pub name: &'static str }

#[derive(Debug, Clone)]
pub enum SasStatus { WaitingAccept, WaitingKey, NeedUserConfirmation { emoji: Vec<SasEmoji> }, WaitingMac, Verified, Cancelled(String) }

#[derive(Debug)]
pub enum SasStep { Emoji(Vec<SasEmoji>), Verified, Cancelled(String) }

pub struct SasFlow {
    txid: String,
    to_user: i64,
    to_session: i64,
    sas: Option<Sas>,
    established: Option<EstablishedSas>,
    status: SasStatus,
    computed_emoji: Option<Vec<SasEmoji>>,
    olm: Arc<LockNetOlmHelper>,
    event_rx: broadcast::Receiver<Event>,
    our_msk_b64: String,
    our_ed25519_b64: String,
    mac_verified: Option<bool>,
}

impl SasFlow {
    pub async fn start(olm: Arc<LockNetOlmHelper>, event_rx: broadcast::Receiver<Event>, _store: Arc<dyn CryptoStore>, to_user: i64, to_session: i64, our_msk_b64: String, our_ed25519_b64: String) -> Result<Self> {
        let txid = generate_txid();
        let flow = Self {
            txid: txid.clone(), to_user, to_session, sas: Some(Sas::new()), established: None,
            status: SasStatus::WaitingAccept, computed_emoji: None, olm, event_rx, our_msk_b64, our_ed25519_b64, mac_verified: None,
        };
        flow.send_sas_message(SAS_START, json!({
            "from_session": to_session.to_string(), "method": SAS_METHOD, "transaction_id": txid,
            "key_agreement_protocols": ["curve25519"], "hashes": ["sha256"],
            "message_authentication_codes": ["hkdf-hmac-sha256"], "short_authentication_string": ["emoji"],
        })).await?;
        Ok(flow)
    }

    pub async fn start_as_responder(olm: Arc<LockNetOlmHelper>, event_rx: broadcast::Receiver<Event>, txid: String, to_user: i64, to_session: i64, our_msk_b64: String, our_ed25519_b64: String) -> Result<Self> {
        let flow = Self {
            txid, to_user, to_session, sas: Some(Sas::new()), established: None,
            status: SasStatus::WaitingKey, computed_emoji: None, olm, event_rx, our_msk_b64, our_ed25519_b64, mac_verified: None,
        };
        flow.send_accept().await?;
        flow.send_key().await?;
        Ok(flow)
    }

    pub fn transaction_id(&self) -> &str { &self.txid }
    pub fn check_status(&self) -> SasStatus { self.status.clone() }
    pub fn emoji(&self) -> Option<&[SasEmoji]> { self.computed_emoji.as_deref() }

    pub async fn next(&mut self) -> Result<SasStep> {
        loop {
            match &self.status {
                SasStatus::WaitingAccept => { self.wait_for_sas(SAS_ACCEPT).await?; self.send_key().await?; self.status = SasStatus::WaitingKey; }
                SasStatus::WaitingKey => { self.wait_for_key().await?; let emoji = self.compute_emoji()?; self.computed_emoji = Some(emoji.clone()); self.status = SasStatus::NeedUserConfirmation { emoji: emoji.clone() }; return Ok(SasStep::Emoji(emoji)); }
                SasStatus::NeedUserConfirmation { .. } => { tokio::time::sleep(Duration::from_millis(50)).await; }
                SasStatus::WaitingMac => match self.try_recv_mac().await? {
                    Some(true) => { self.status = SasStatus::Verified; return Ok(SasStep::Verified); }
                    Some(false) => { let r = "MAC mismatch".to_string(); self.status = SasStatus::Cancelled(r.clone()); return Ok(SasStep::Cancelled(r)); }
                    None => continue,
                },
                SasStatus::Verified => return Ok(SasStep::Verified),
                SasStatus::Cancelled(r) => return Ok(SasStep::Cancelled(r.clone())),
            }
        }
    }

    pub async fn confirm_emoji(&mut self, accept: bool) -> Result<()> {
        if !matches!(self.status, SasStatus::NeedUserConfirmation { .. }) {
            return Err(LockNetError::InvalidArgument("confirm_emoji called in wrong state".into()));
        }
        if !accept { self.status = SasStatus::Cancelled("user rejected".into()); return Ok(()); }
        self.send_mac().await?;
        self.status = SasStatus::WaitingMac;
        Ok(())
    }

    pub async fn abort(&mut self) -> Result<()> { self.status = SasStatus::Cancelled("aborted".into()); Ok(()) }

    async fn send_accept(&self) -> Result<()> {
        self.send_sas_message(SAS_ACCEPT, json!({
            "transaction_id": self.txid, "method": SAS_METHOD, "key_agreement_protocol": "curve25519",
            "hash": "sha256", "message_authentication_code": "hkdf-hmac-sha256", "short_authentication_string": ["emoji"],
        })).await
    }

    async fn send_sas_message(&self, kind: &str, content: Value) -> Result<()> {
        let pt = json!({ "type": kind, "content": content }).to_string();
        self.olm.send(self.to_user, self.to_session, pt).wait().await
    }

    async fn wait_for_sas(&mut self, expected_type: &str) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { return Err(LockNetError::Timeout(Duration::from_secs(30))); }
            match tokio::time::timeout(remaining, self.event_rx.recv()).await {
                Ok(Ok(Event::ToDevice(payload))) => {
                    if let Some(pt) = self.olm.decrypt(payload).wait().await? {
                        if let Ok(val) = serde_json::from_str::<Value>(&pt) {
                            if val.get("type").and_then(|v| v.as_str()) == Some(expected_type) {
                                return Ok(val.get("content").cloned().unwrap_or(Value::Null));
                            }
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Err(LockNetError::Timeout(Duration::from_secs(30))),
            }
        }
    }

    async fn send_key(&self) -> Result<()> {
        let sas = self.sas.as_ref().ok_or_else(|| LockNetError::InvalidResponse("SAS already consumed".into()))?;
        self.send_sas_message(SAS_KEY, json!({ "transaction_id": self.txid, "key": sas.public_key().to_base64() })).await
    }

    async fn wait_for_key(&mut self) -> Result<()> {
        let content = self.wait_for_sas(SAS_KEY).await?;
        let key_b64 = content.get("key").and_then(|v| v.as_str()).ok_or_else(|| LockNetError::InvalidResponse("no key".into()))?;
        let their_pub = Curve25519PublicKey::from_base64(key_b64).map_err(|e| LockNetError::InvalidResponse(format!("sas pubkey: {e}")))?;
        let sas = self.sas.take().ok_or_else(|| LockNetError::InvalidResponse("SAS already consumed".into()))?;
        let established = sas.diffie_hellman(their_pub).map_err(|e| LockNetError::InvalidResponse(format!("sas dh: {e}")))?;
        self.established = Some(established);
        Ok(())
    }

    fn compute_emoji(&self) -> Result<Vec<SasEmoji>> {
        let established = self.established.as_ref().ok_or_else(|| LockNetError::InvalidResponse("SAS not established".into()))?;
        let info = format!("{}{}", SAS_INFO_PREFIX, self.txid);
        let sas_bytes = established.bytes(&info);
        let indices = sas_bytes.emoji_indices();
        let mut result = Vec::with_capacity(7);
        for &idx in indices.iter() {
            let (sym, name) = SAS_EMOJI[idx as usize];
            result.push(SasEmoji { symbol: sym, name });
        }
        Ok(result)
    }

    async fn send_mac(&self) -> Result<()> {
        let established = self.established.as_ref().ok_or_else(|| LockNetError::InvalidResponse("SAS not established".into()))?;
        let info = self.txid.as_str();
        let mac_ed = established.calculate_mac(self.our_ed25519_b64.as_str(), info);
        let mac_master = established.calculate_mac(self.our_msk_b64.as_str(), info);
        self.send_sas_message(SAS_MAC, json!({
            "transaction_id": self.txid,
            "mac": { "ed25519": hex_encode(mac_ed.as_bytes()), "master": hex_encode(mac_master.as_bytes()) }
        })).await
    }

    async fn try_recv_mac(&mut self) -> Result<Option<bool>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { return Ok(Some(false)); }
            match tokio::time::timeout(remaining, self.event_rx.recv()).await {
                Ok(Ok(Event::ToDevice(payload))) => {
                    if let Some(pt) = self.olm.decrypt(payload).wait().await? {
                        if let Ok(val) = serde_json::from_str::<Value>(&pt) {
                            if val.get("type").and_then(|v| v.as_str()) == Some(SAS_MAC) {
                                let their_ed = val.pointer("/content/mac/ed25519").and_then(|v| v.as_str()).unwrap_or("");
                                let their_master = val.pointer("/content/mac/master").and_then(|v| v.as_str()).unwrap_or("");
                                let ok = !their_ed.is_empty() && !their_master.is_empty();
                                self.mac_verified = Some(ok);
                                return Ok(Some(ok));
                            }
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => return Err(LockNetError::RunnerDown),
                Err(_) => return Ok(Some(false)),
            }
        }
    }
}

fn generate_txid() -> String {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).expect("getrandom");
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}