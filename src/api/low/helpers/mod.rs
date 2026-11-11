//! Per-area WebSocket method wrappers.
//!
//! Each helper wraps one category of server methods as typed `async fn`s. All
//! helpers are owned by [`crate::LockNetLowAgent`] and accessed via its
//! accessor methods (`.messages()`, `.groups()`, …).
//!
//! - `messages` — send, get, edit, delete, reactions.
//! - `groups` — create, join, leave, invites, policy sync.
//! - `keys` — device keys and one-time keys.
//! - `crypto` — cross-signing keys and `send_to_device`.
//! - `events` — offline event sync.
//! - `backup` — encrypted key backup (export / import).
//! - `olm` — Olm 1-to-1 encrypted payloads.
//! - `megolm` — Megolm group sessions and rotation.
//! - `key_sharing` — `ln.encryption.key_request` flows.
//! - `verification` — SAS and QR verification flows.

pub mod backup;
pub mod crypto;
pub mod events;
pub mod groups;
pub mod key_sharing;
pub mod keys;
pub mod megolm;
pub mod messages;
pub mod olm;
pub mod verification;

pub use backup::{BackupExportResult, BackupImportResult, LockNetBackupHelper, RecoveryKey};
pub use crypto::LockNetCryptoHelper;
pub use events::LockNetEventsHelper;
pub use groups::LockNetGroupsHelper;
pub use key_sharing::{
    IncomingKeyRequest, KeyRequestFlow, KeyRequestStep, LockNetKeySharingHelper,
};
pub use keys::LockNetKeysHelper;
pub use megolm::{LockNetMegolmHelper, MegolmSessionInfo};
pub use messages::LockNetMessagesHelper;
pub use olm::LockNetOlmHelper;
pub use verification::LockNetVerificationHelper;
