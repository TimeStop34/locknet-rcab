use serde::{Deserialize, Serialize};

/// Кто может читать историю чата.
///
/// - `AfterJoin` — история до вступления недоступна. `key_request` на старые ключи
///   отклоняется с `history_visibility_policy`.
/// - `AllVerifiedSessions` — отдаём ключи любой сессии, чей ed25519 подписан SSK
///   владельца (session-verified).
/// - `AllVerifiedUsers` (default) — отдаём только сессиям, чей владелец доверен
///   через Web of Trust (USK-цепочка от нашего user_id) И сессия session-verified.
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

/// Политики группы. Хранятся локально (в `CryptoStore`) и зашифрованы
/// `group_data_key`. На сервер отдаются как `Group.encrypted_group_data`
/// (opaque blob, сервер не может прочитать или валидно подменить).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupData {
    /// Монотонный счётчик версий (anti-replay: клиент игнорирует blob
    /// с версией меньше локальной).
    pub version: u32,
    pub history_visibility: HistoryVisibility,
    pub megolm_rotation_visibility: MegolmRotationVisibility,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
}

/// Локальное состояние группы в `CryptoStore`:
/// ключ шифрования blob'а + plaintext `GroupData` + актуальный blob.
#[derive(Debug, Clone)]
pub struct GroupDataState {
    /// 32-байтный симметричный ключ, производный от `group_data_key` из `group_key` payload.
    /// Ротируется вместе с megolm-сессией.
    pub key: [u8; 32],
    /// Расшифрованное содержимое.
    pub data: GroupData,
    /// Актуальный зашифрованный blob (`encrypt_group_data`).
    /// На сервер отдаётся как `Group.encrypted_group_data`,
    /// в `group_key` payload уходит в `content.group_data`.
    pub blob: String,
}