use std::sync::Arc;
use tokio::sync::broadcast;
use crate::api::low::command::CmdSender;
use crate::api::low::event::Event;
use crate::api::low::helpers::olm::LockNetOlmHelper;
use crate::api::low::helpers::verification::sas::SasFlow;
use crate::core::crypto::CryptoStore;
use crate::core::errors::Result;

pub struct LockNetVerificationHelper {
    #[allow(dead_code)]
    pub(crate) cmd_tx: CmdSender,
    pub(crate) store: Arc<dyn CryptoStore>,
    pub(crate) event_tx: broadcast::Sender<Event>,
    pub(crate) olm: Arc<LockNetOlmHelper>,
}

impl LockNetVerificationHelper {
    pub async fn sas_start(&self, to_user: i64, to_session: i64, our_msk_b64: String, our_ed25519_b64: String) -> Result<SasFlow> {
        SasFlow::start(self.olm.clone(), self.event_tx.subscribe(), self.store.clone(), to_user, to_session, our_msk_b64, our_ed25519_b64).await
    }
    pub async fn sas_start_responder(&self, to_user: i64, to_session: i64, txid: String, our_msk_b64: String, our_ed25519_b64: String) -> Result<SasFlow> {
        SasFlow::start_as_responder(self.olm.clone(), self.event_tx.subscribe(), txid, to_user, to_session, our_msk_b64, our_ed25519_b64).await
    }

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