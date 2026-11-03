use std::sync::Arc;

use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::helpers::megolm::MegolmSessionInfo;
use crate::core::errors::Result;

/// Раздаёт `ln.encryption.group_key` для `chat_id` всем сессиям всех
/// участников (кроме нашей текущей сессии — у нас уже есть inbound).
/// Возвращает число получателей.
pub(crate) async fn fan_out_group_key(
    low: &Arc<LockNetLowAgent>,
    chat_id: i64,
    participant_ids: &[i64],
    info: &MegolmSessionInfo,
) -> Result<usize> {
    if participant_ids.is_empty() {
        return Ok(0);
    }

    let our_uid = low.user_id();
    let our_sid = low.session_id();

    let all_sessions = low.keys().query(participant_ids.to_vec()).await?;

    let mut shared = 0usize;
    for uid in participant_ids {
        let Some(sessions) = all_sessions.get(uid) else {
            continue;
        };
        for sid in sessions.keys() {
            if *uid == our_uid && *sid == our_sid {
                continue;
            }
            low.megolm()
                .share_group_key_with_session_key(
                    chat_id,
                    *uid,
                    *sid,
                    info.megolm_session_id.clone(),
                    info.session_key.clone(),
                )
                .await?;
            shared += 1;
        }
    }
    Ok(shared)
}