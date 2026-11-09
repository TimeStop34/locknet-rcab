use std::sync::Arc;
use tokio::sync::broadcast;
use crate::api::low::command::CmdSender;
use crate::api::low::event::Event;
use crate::api::low::helpers::*;
use crate::core::crypto::CryptoStore;

pub struct LockNetLowAgent {
    user_id: i64,
    session_id: i64,
    #[allow(dead_code)]
    cmd_tx: CmdSender,
    event_tx: broadcast::Sender<Event>,
    store: Arc<dyn CryptoStore>,

    messages_helper: Arc<LockNetMessagesHelper>,
    groups_helper: Arc<LockNetGroupsHelper>,
    keys_helper: Arc<LockNetKeysHelper>,
    crypto_helper: Arc<LockNetCryptoHelper>,
    events_helper: Arc<LockNetEventsHelper>,
    backup_helper: Arc<LockNetBackupHelper>,
    olm_helper: Arc<LockNetOlmHelper>,
    megolm_helper: Arc<LockNetMegolmHelper>,
    verification_helper: Arc<LockNetVerificationHelper>,
    key_sharing_helper: Arc<LockNetKeySharingHelper>,
}

impl LockNetLowAgent {
    pub(crate) fn new(
        user_id: i64,
        session_id: i64,
        cmd_tx: CmdSender,
        event_tx: broadcast::Sender<Event>,
        store: Arc<dyn CryptoStore>,
        default_history_visibility: crate::core::policies::HistoryVisibility,
        default_megolm_rotation_visibility: crate::core::policies::MegolmRotationVisibility,
        megolm_rotation_message_count: u64,
        megolm_rotation_ttl_secs: u64,
    ) -> Self {
        let messages_helper = Arc::new(LockNetMessagesHelper { cmd_tx: cmd_tx.clone() });
        let groups_helper = Arc::new(LockNetGroupsHelper { cmd_tx: cmd_tx.clone() });
        let keys_helper = Arc::new(LockNetKeysHelper { cmd_tx: cmd_tx.clone() });
        let crypto_helper = Arc::new(LockNetCryptoHelper { cmd_tx: cmd_tx.clone() });
        let events_helper = Arc::new(LockNetEventsHelper { cmd_tx: cmd_tx.clone() });
        let olm_helper = Arc::new(LockNetOlmHelper { cmd_tx: cmd_tx.clone(), store: store.clone() });
        let megolm_helper = Arc::new(LockNetMegolmHelper {
            cmd_tx: cmd_tx.clone(), store: store.clone(), olm: olm_helper.clone(), session_id,
            default_history_visibility,
            default_megolm_rotation_visibility,
            rotation_message_count: megolm_rotation_message_count,
            rotation_ttl_secs: megolm_rotation_ttl_secs,
        });
        let backup_helper = Arc::new(LockNetBackupHelper {
            cmd_tx: cmd_tx.clone(),
            store: store.clone(),
            megolm: megolm_helper.clone(),
        });
        let verification_helper = Arc::new(LockNetVerificationHelper {
            cmd_tx: cmd_tx.clone(), store: store.clone(), event_tx: event_tx.clone(), olm: olm_helper.clone(),
        });
        let key_sharing_helper = Arc::new(LockNetKeySharingHelper {
            event_tx: event_tx.clone(),
            olm: olm_helper.clone(),
            megolm: megolm_helper.clone(),
            our_session_id: session_id,
        });

        Self {
            user_id, session_id, cmd_tx, event_tx, store,
            messages_helper, groups_helper, keys_helper, crypto_helper, events_helper, backup_helper,
            olm_helper, megolm_helper, verification_helper, key_sharing_helper,
        }
    }

    pub fn user_id(&self) -> i64 { self.user_id }
    pub fn session_id(&self) -> i64 { self.session_id }
    pub fn subscribe(&self) -> broadcast::Receiver<Event> { self.event_tx.subscribe() }
    pub fn store(&self) -> Arc<dyn CryptoStore> { self.store.clone() }

    pub fn messages(&self) -> Arc<LockNetMessagesHelper> { Arc::clone(&self.messages_helper) }
    pub fn groups(&self) -> Arc<LockNetGroupsHelper> { Arc::clone(&self.groups_helper) }
    pub fn keys(&self) -> Arc<LockNetKeysHelper> { Arc::clone(&self.keys_helper) }
    pub fn crypto(&self) -> Arc<LockNetCryptoHelper> { Arc::clone(&self.crypto_helper) }
    pub fn events(&self) -> Arc<LockNetEventsHelper> { Arc::clone(&self.events_helper) }
    pub fn backup(&self) -> Arc<LockNetBackupHelper> { Arc::clone(&self.backup_helper) }
    pub fn olm(&self) -> Arc<LockNetOlmHelper> { Arc::clone(&self.olm_helper) }
    pub fn megolm(&self) -> Arc<LockNetMegolmHelper> { Arc::clone(&self.megolm_helper) }
    pub fn verification(&self) -> Arc<LockNetVerificationHelper> { Arc::clone(&self.verification_helper) }
    pub fn key_sharing(&self) -> Arc<LockNetKeySharingHelper> { Arc::clone(&self.key_sharing_helper) }
}