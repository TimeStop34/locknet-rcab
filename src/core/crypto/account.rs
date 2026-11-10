//! Olm account wrapper.

use std::collections::HashMap;
use vodozemac::olm::Account as OlmAccount;

/// Olm account: long-term identity keys and unpublished one-time keys.
///
/// Wraps [`vodozemac::olm::Account`] and exposes the operations needed by
/// `locknet-rcab` in terms of base64-encoded strings (the wire format used by
/// the LockNet server).
///
/// Owned by the [`crate::core::crypto::CryptoStore`] and accessed via
/// [`crate::core::crypto::CryptoStore::account`].
pub struct Account {
    inner: OlmAccount,
}

impl Account {
    /// Create a fresh account with newly generated identity keys.
    pub fn new() -> Self {
        Self { inner: OlmAccount::new() }
    }

    /// Ed25519 identity key, base64 (unpadded).
    pub fn ed25519_public_b64(&self) -> String {
        self.inner.identity_keys().ed25519.to_base64()
    }

    /// Curve25519 identity key, base64 (unpadded).
    pub fn curve25519_public_b64(&self) -> String {
        self.inner.identity_keys().curve25519.to_base64()
    }

    /// Generate `count` new one-time keys.
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }

    /// Return all unpublished one-time keys as `{"curve25519:<id>": "<key>"}`.
    pub fn one_time_keys_b64(&self) -> HashMap<String, String> {
        let mut otks = HashMap::new();
        for (key_id, public_key) in self.inner.one_time_keys().iter() {
            otks.insert(format!("curve25519:{}", key_id.to_base64()), public_key.to_base64());
        }
        otks
    }

    /// Mark all current one-time keys as published.
    ///
    /// Call this **after** successfully uploading them via
    /// [`crate::api::low::helpers::keys::LockNetKeysHelper::upload`];
    /// subsequent calls to [`Self::one_time_keys_b64`] will not return them.
    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published();
    }

    /// Borrow the inner `vodozemac` account.
    pub fn inner(&self) -> &OlmAccount {
        &self.inner
    }

    /// Mutably borrow the inner `vodozemac` account.
    pub fn inner_mut(&mut self) -> &mut OlmAccount {
        &mut self.inner
    }

    /// Wrap an existing `vodozemac` account (used by persistent stores on load).
    pub fn from_inner(inner: OlmAccount) -> Self {
        Self { inner }
    }
}

impl Default for Account {
    fn default() -> Self { Self::new() }
}