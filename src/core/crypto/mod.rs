//! Cryptographic primitives used by `locknet-rcab`.
//!
//! This module re-exports the low-level crypto building blocks. Higher layers
//! ([`crate::api::low`], [`crate::api::high`]) consume them, but you normally
//! do not call these directly from application code — use
//! [`crate::LockNetAgent`] or [`crate::LockNetLowAgent`] instead.
//!
//! - [`Account`] — Olm identity keys and one-time keys.
//! - [`CryptoStore`] / [`InMemoryStore`] / [`SqliteStore`] — persistent state.
//! - [`CrossSigningKeysPrivate`] — MSK/SSK/USK for the Web of Trust.
//! - [`group_data`] — encryption of the group policy blob.

pub mod account;
pub mod group_data;
pub mod megolm;
pub mod olm;
pub mod signature;
pub mod sqlite_store;
pub mod store;

pub use account::Account;
pub use group_data::{decrypt_group_data, encrypt_group_data, derive_group_data_encryption_key};
pub use megolm::MEGOLM_ALGORITHM;
pub use olm::{EncryptedOlm, OlmSessionEntry, OLM_ALGORITHM};
pub use signature::{sign, sign_b64, verify, verify_b64, CrossSigningKeysPrivate};
pub use sqlite_store::SqliteStore;
pub use store::{CryptoStore, InMemoryStore};