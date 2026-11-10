//! Helper facade for SAS and QR flows.

use std::sync::Arc;
use tokio::sync::broadcast;
use crate::api::low::command::CmdSender;
use crate::api::low::event::Event;
use crate::api::low::helpers::olm::LockNetOlmHelper;
use crate::api::low::helpers::verification::sas::SasFlow;
use crate::core::crypto::CryptoStore;
use crate::core::errors::Result;

/// Entry point for verification flows.
///
/// Obtained via [`crate::LockNetLowAgent::verification`]. Each method returns
/// a low-level flow that transmits messages through Olm. The caller is
/// responsible for driving the flow to completion and, on success, for
/// marking the peer as verified in their own state.
///
/// Most applications should use [`crate::SecurityHelper`], which does that.
pub struct LockNetVerificationHelper {
    #[allow(dead_code)]
    pub(crate) cmd_tx: CmdSender,
    pub(crate) store: Arc<dyn CryptoStore>,
    pub(crate) event_tx: broadcast::Sender<Event>,
    pub(crate) olm: Arc<LockNetOlmHelper>,
}

impl LockNetVerificationHelper {
    /// Start a SAS verification as the initiator.
    ///
    /// Sends the initial `ln.encryption.key.verification.start` message via
    /// Olm. The returned [`SasFlow`] must be driven with
    /// [`SasFlow::next`] / [`SasFlow::confirm_emoji`].
    ///
    /// `our_msk_b64` and `our_ed25519_b64` are the caller's public MSK and
    /// ed25519 identity keys — they are MAC'ed in the final step.
    ///
    /// # Errors
    ///
    /// - [`crate::LockNetError::RunnerDown`] if the Olm channel is closed.
    /// - [`crate::LockNetError::Timeout`] on send timeout.
    pub async fn sas_start(&self, to_user: i64, to_session: i64, our_msk_b64: String, our_ed25519_b64: String) -> Result<SasFlow> {
        SasFlow::start(self.olm.clone(), self.event_tx.subscribe(), self.store.clone(), to_user, to_session, our_msk_b64, our_ed25519_b64).await
    }

    /// Respond to an incoming `ln.encryption.key.verification.start`.
    ///
    /// Immediately sends `accept` and `key`. The returned [`SasFlow`] must be
    /// driven with [`SasFlow::next`] / [`SasFlow::confirm_emoji`].
    pub async fn sas_start_responder(&self, to_user: i64, to_session: i64, txid: String, our_msk_b64: String, our_ed25519_b64: String) -> Result<SasFlow> {
        SasFlow::start_as_responder(self.olm.clone(), self.event_tx.subscribe(), txid, to_user, to_session, our_msk_b64, our_ed25519_b64).await
    }

    /// Show a QR code (displayer side).
    ///
    /// Returns the QR string to render and a [`crate::api::low::helpers::verification::QrFlow`]
    /// that waits for the peer to scan it and send `qr.scanned`.
    pub async fn qr_display(
        &self,
        mode: crate::api::low::helpers::verification::qr::QrMode,
        to_user: i64,
        to_session: i64,
        our_msk_b64: String,
        our_ed25519_b64: String,
    ) -> Result<(crate::api::low::helpers::verification::qr::QrCode, crate::api::low::helpers::verification::qr::QrFlow)> {
        crate::api::low::helpers::verification::qr::QrFlow::display(
            mode,
            self.olm.clone(),
            self.event_tx.subscribe(),
            to_user,
            to_session,
            our_msk_b64,
            our_ed25519_b64,
        ).await
    }

    /// Scan a QR code (scanner side).
    ///
    /// Immediately sends `qr.scanned` to the displayer. The returned flow
    /// must be driven with `.next()` and `.exchange_mac()`.
    pub async fn qr_scan(
        &self,
        qr_raw: &str,
        to_user: i64,
        to_session: i64,
        our_msk_b64: String,
        our_ed25519_b64: String,
    ) -> Result<crate::api::low::helpers::verification::qr::QrFlow> {
        crate::api::low::helpers::verification::qr::QrFlow::scan(
            qr_raw,
            self.olm.clone(),
            self.event_tx.subscribe(),
            to_user,
            to_session,
            our_msk_b64,
            our_ed25519_b64,
        ).await
    }
}