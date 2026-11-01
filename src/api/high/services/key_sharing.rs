pub struct KeySharingFlow {
    transaction_id: String,
    chat_ids: Vec<i64>,
    received: u32,
    total: u32,
}

pub enum KeySharingStep {
    Progress { chat_id: i64, received: u32, total: u32 },
    Imported { chat_id: i64, megolm_session_id: String },
    Done { total_imported: u32 },
    Denied { reason: String },
    Failed { reason: String },
}

impl KeySharingFlow {
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn received(&self) -> u32 {
        self.received
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    pub fn chat_ids(&self) -> &[i64] {
        &self.chat_ids
    }

    pub async fn next(&mut self) -> crate::core::errors::Result<KeySharingStep> {
        Err(crate::core::errors::LockNetError::InvalidResponse(
            "key_sharing: deferred to next pass".into(),
        ))
    }

    pub async fn cancel(&mut self) -> crate::core::errors::Result<()> {
        Ok(())
    }
}