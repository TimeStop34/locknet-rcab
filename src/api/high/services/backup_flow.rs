pub struct RecoveryKey(pub(crate) [u8; 32]);

impl RecoveryKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom");
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base58(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_base58(s: &str) -> crate::core::errors::Result<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| {
                crate::core::errors::LockNetError::InvalidResponse(format!(
                    "recovery key b64: {e}"
                ))
            })?;
        if bytes.len() != 32 {
            return Err(crate::core::errors::LockNetError::InvalidResponse(
                "recovery key: wrong length".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

pub struct BackupExportResult {
    pub version: i32,
    pub items_uploaded: u32,
}

pub struct BackupImportResult {
    pub version: i32,
    pub sessions_imported: u32,
}

pub struct BackupFlow;

impl BackupFlow {
    pub async fn export(&self) -> crate::core::errors::Result<BackupExportResult> {
        Err(crate::core::errors::LockNetError::InvalidResponse(
            "backup: deferred to next pass".into(),
        ))
    }

    pub async fn import(
        &self,
        _version: i32,
    ) -> crate::core::errors::Result<BackupImportResult> {
        Err(crate::core::errors::LockNetError::InvalidResponse(
            "backup: deferred to next pass".into(),
        ))
    }
}