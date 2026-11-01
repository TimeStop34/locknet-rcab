pub struct QrCode {
    pub mode: QrMode,
    pub transaction_id: String,
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrMode {
    UserToUser,
    SelfDeviceTrusted,
    SelfDeviceUntrusted,
}

pub struct QrFlow {
    transaction_id: String,
}

pub enum QrStep {
    Scanned { from_user: i64, from_session: i64 },
    Confirmed,
    MacExchanged,
    Verified,
    Cancelled(String),
}

impl QrFlow {
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub async fn next(&mut self) -> crate::core::errors::Result<QrStep> {
        Err(crate::core::errors::LockNetError::InvalidResponse(
            "qr: deferred to next pass".into(),
        ))
    }

    pub async fn confirm(&mut self, _accept: bool) -> crate::core::errors::Result<()> {
        Ok(())
    }

    pub async fn cancel(&mut self) -> crate::core::errors::Result<()> {
        Ok(())
    }
}