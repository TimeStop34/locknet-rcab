//! SAS and QR verification flows.
//!
//! - [`sas`] — emoji-based SAS verification (short authentication string).
//! - [`qr`] — QR-code verification for user-to-user and self-device cases.
//!
//! Both flows transmit their messages through the Olm channel
//! ([`crate::api::low::helpers::olm`]) using `ln.encryption.key.verification.*`
//! wire types. See the individual modules for protocol details.
//!
//! Most applications should use [`crate::SecurityHelper`] instead, which
//! orchestrates these flows with the local [`crate::CryptoStore`] and updates
//! the Web of Trust cache on success.

pub mod helper;
pub mod qr;
pub mod sas;

pub use helper::LockNetVerificationHelper;
pub use qr::{QrCode, QrFlow, QrMode, QrStep};
pub use sas::{SasEmoji, SasFlow, SasStatus, SasStep};
