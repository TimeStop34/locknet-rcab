use std::collections::HashMap;
use vodozemac::olm::Account as OlmAccount;

pub struct Account {
    inner: OlmAccount,
}

impl Account {
    pub fn new() -> Self {
        Self { inner: OlmAccount::new() }
    }
    pub fn ed25519_public_b64(&self) -> String {
        self.inner.identity_keys().ed25519.to_base64()
    }
    pub fn curve25519_public_b64(&self) -> String {
        self.inner.identity_keys().curve25519.to_base64()
    }
    pub fn generate_one_time_keys(&mut self, count: usize) {
        self.inner.generate_one_time_keys(count);
    }
    pub fn one_time_keys_b64(&self) -> HashMap<String, String> {
        let mut otks = HashMap::new();
        for (key_id, public_key) in self.inner.one_time_keys().iter() {
            otks.insert(format!("curve25519:{}", key_id.to_base64()), public_key.to_base64());
        }
        otks
    }
    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published();
    }
    pub fn inner(&self) -> &OlmAccount {
        &self.inner
    }
    pub fn inner_mut(&mut self) -> &mut OlmAccount {
        &mut self.inner
    }
    pub fn from_inner(inner: OlmAccount) -> Self {
        Self { inner }
    }
}

impl Default for Account {
    fn default() -> Self { Self::new() }
}