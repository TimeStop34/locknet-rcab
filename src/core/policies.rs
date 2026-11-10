use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    AfterJoin,
    AllVerifiedSessions,
    #[default]
    AllVerifiedUsers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MegolmRotationVisibility {
    AllMembers,
    OnlyVerifiedSessions,
    #[default]
    OnlyVerifiedUsers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupData {
            pub version: u32,
    pub history_visibility: HistoryVisibility,
    pub megolm_rotation_visibility: MegolmRotationVisibility,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct GroupDataState {
            pub key: [u8; 32],
        pub data: GroupData,
                pub blob: String,
}

#[derive(Debug, Clone)]
pub struct MegolmOutboundMeta {
    pub session_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub messages_sent: u64,
}