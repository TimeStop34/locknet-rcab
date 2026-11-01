use std::sync::Arc;

use vodozemac::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};

use crate::core::errors::{LockNetError, Result};

#[derive(Clone)]
pub struct CrossSigningKeysPrivate {
    pub msk: Arc<Ed25519Keypair>,
    pub ssk: Arc<Ed25519Keypair>,
    pub usk: Arc<Ed25519Keypair>,
}

impl CrossSigningKeysPrivate {
    pub fn generate() -> Self {
        Self {
            msk: Arc::new(Ed25519Keypair::new()),
            ssk: Arc::new(Ed25519Keypair::new()),
            usk: Arc::new(Ed25519Keypair::new()),
        }
    }
    pub fn msk_pub_b64(&self) -> String { self.msk.public_key().to_base64() }
    pub fn ssk_pub_b64(&self) -> String { self.ssk.public_key().to_base64() }
    pub fn usk_pub_b64(&self) -> String { self.usk.public_key().to_base64() }
}

pub fn sign(keypair: &Ed25519Keypair, message: &[u8]) -> String {
    keypair.sign(message).to_base64()
}

pub fn sign_b64(keypair: &Ed25519Keypair, message_b64: &str) -> Result<String> {
    let msg = decode_b64(message_b64)?;
    Ok(sign(keypair, &msg))
}

pub fn verify(pubkey_b64: &str, message: &[u8], sig_b64: &str) -> Result<()> {
    let pk = Ed25519PublicKey::from_base64(pubkey_b64).map_err(|e| LockNetError::InvalidResponse(format!("ed25519 pubkey b64: {e}")))?;
    let sig = Ed25519Signature::from_base64(sig_b64).map_err(|e| LockNetError::InvalidResponse(format!("ed25519 sig b64: {e}")))?;
    pk.verify(message, &sig).map_err(|_| LockNetError::InvalidResponse("ed25519 signature invalid".into()))
}

pub fn verify_b64(pubkey_b64: &str, message_b64: &str, sig_b64: &str) -> Result<()> {
    let msg = decode_b64(message_b64)?;
    verify(pubkey_b64, &msg, sig_b64)
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| LockNetError::InvalidResponse(format!("b64: {e}")))
}