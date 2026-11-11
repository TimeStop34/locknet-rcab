//! High-level SAS and QR verification flows.
//!
//! Unlike the low-level flows in
//! [`crate::api::low::helpers::verification`], these consume
//! [`crate::HighEvent::SasMessage`] / [`crate::HighEvent::QrMessage`] rather
//! than raw `to_device` events. This means the agent is the sole Olm
//! decryptor, eliminating races on the stateful Olm session.
//!
//! Applications should drive these flows via [`crate::SecurityHelper`],
//! which registers them in the agent's state and updates the trust cache on
//! success.

pub mod qr;
pub mod sas;

pub use qr::{QrCode, QrFlow, QrMode, QrStep};
pub use sas::{SasEmoji, SasFlow, SasStatus, SasStep};
