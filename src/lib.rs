//! Rust client for LockNet — a social network with end-to-end encrypted
//! messaging.
//!
//! # Overview
//!
//! The crate has two API layers:
//!
//! - [`api::high`] — object-oriented, stateful. [`LockNetAgent`] maintains a
//!   cache of chats, users, invites, and messages; converts raw server events
//!   into [`HighEvent`]s; and orchestrates the multi-step E2EE flows
//!   (group key fan-out, key requests, SAS/QR verification, policy sync).
//!   Most applications use this layer.
//! - [`api::low`] — thin wrappers over individual WebSocket methods. Use this
//!   when raw control over each request is needed, or when building a custom
//!   UI that wants raw server events rather than processed [`HighEvent`]s.
//!
//! Both layers share a single WebSocket runner ([`LockNetClient`]) and a
//! cryptographic state store ([`CryptoStore`]).
//!
//! # End-to-end encryption
//!
//! Messages are encrypted with Megolm (group sessions) wrapped by Olm (1-to-1
//! sessions). Key material lives in [`CryptoStore`]:
//!
//! - [`InMemoryStore`] (default) — non-persistent; all keys are lost when the
//!   process exits.
//! - [`SqliteStore`] — encrypted SQLite database. The caller supplies the
//!   passphrase; obtaining and protecting it (macOS Keychain, Windows
//!   Credential Manager, GNOME Keyring, KWallet, TPM, user prompt) is the
//!   caller's responsibility.
//!
//! Group policies ([`HistoryVisibility`], [`MegolmRotationVisibility`]) are
//! themselves E2EE: they live in an `encrypted_group_data` blob that only
//! group members with the `group_data_key` can read. The server stores and
//! forwards the blob but cannot read or tamper with it.
//!
//! **Recovery keys** (used by [`SecurityHelper`] to back up Megolm sessions)
//! are shown to the user once, as base64. Losing a recovery key means losing
//! access to all backed-up history — there is no server-side recovery.
//!
//! # Examples
//!
//! ```rust,no_run
//! use locknet_rcab::{Credentials, LockNetClient, LockNetConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Configure and connect.
//!     let config = LockNetConfig::new("https://locknet.example.com", "example.com")?;
//!     let mut client = LockNetClient::new(config);
//!     let session = client
//!         .connection_request(Credentials::Login {
//!             username: "alice".into(),
//!             password: "secret".into(),
//!         })
//!         .await?;
//!     println!("logged in as {} (session {})", session.user_id, session.session_id);
//!
//!     // 2. Get the high-level agent.
//!     let agent = client.get_agent().expect("agent");
//!
//!     // 3. Set up cross-signing so other users can verify this device.
//!     agent.security().setup_cross_signing().await?;
//!
//!     // 4. Subscribe to events, then send a message.
//!     let mut events = agent.subscribe();
//!     let chat = agent.chat(42).await?;
//!     chat.send("hello, world").await?;
//!
//!     // 5. Process events.
//!     while let Ok(event) = events.recv().await {
//!         println!("event: {event:?}");
//!     }
//!
//!     client.disconnect().await?;
//!     Ok(())
//! }
//! ```
//!
//! See the `examples/` directory for self-contained programs
//! (`echo_bot`, `send_message`, `persistent_login`).

pub mod api;
pub mod core;

pub use api::client::LockNetClient;
pub use api::high::{
    Chat, Group, GroupMember, HighEvent, Invite, LockNetAgent, Message, QrCode, QrFlow, QrMode,
    QrStep, Reaction, SasEmoji, SasFlow, SasStatus, SasStep, SecurityHelper, SessionInfo, User,
};
pub use api::low::{Event, LockNetLowAgent};
pub use api::low::helpers::backup::{BackupExportResult, BackupImportResult, RecoveryKey};
pub use api::low::models;
pub use api::session::{Credentials, LockNetSessionContext};
pub use core::config::LockNetConfig;
pub use core::policies::{HistoryVisibility, MegolmRotationVisibility};
pub use core::crypto::{Account, CryptoStore, InMemoryStore, SqliteStore};
pub use core::errors::{LockNetError, Result};
pub use core::flow::{FlowStatus, SimpleFlow};