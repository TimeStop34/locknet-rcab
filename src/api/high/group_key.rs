//! Megolm `group_key` fan-out.
//!
//! Called by [`crate::Chat`] when the outbound Megolm session changes or the
//! group membership changes. Recipients are filtered by the group's
//! [`crate::core::policies::MegolmRotationVisibility`] policy.

use std::sync::Arc;

use super::security::SecurityHelper;
use crate::api::low::agent::LockNetLowAgent;
use crate::api::low::helpers::megolm::MegolmSessionInfo;
use crate::core::errors::Result;
use crate::core::policies::MegolmRotationVisibility;

/// Share the current Megolm key with eligible member sessions.
///
/// Iterates every session of every member (skipping the caller's current
/// session — it already has the inbound key), filters by `policy`, and sends
/// `ln.encryption.group_key` over Olm.
///
/// Returns the number of sessions that received the key.
///
/// # Errors
///
/// Propagates transport errors from `query_keys` or `send_to_device`.
pub(crate) async fn fan_out_group_key(
    low: &Arc<LockNetLowAgent>,
    chat_id: i64,
    participant_ids: &[i64],
    info: &MegolmSessionInfo,
    policy: MegolmRotationVisibility,
    security: &SecurityHelper,
) -> Result<usize> {
    if participant_ids.is_empty() {
        return Ok(0);
    }

    let our_uid = low.user_id();
    let our_sid = low.session_id();

    let all_sessions = low.keys().query(participant_ids.to_vec()).await?;

    let mut shared = 0usize;
    for uid in participant_ids {
        // User-level gate: only for OnlyVerifiedUsers.
        if policy == MegolmRotationVisibility::OnlyVerifiedUsers
            && !security.is_user_verified(*uid).await
        {
            continue;
        }

        let Some(sessions) = all_sessions.get(uid) else {
            continue;
        };

        for sid in sessions.keys() {
            if *uid == our_uid && *sid == our_sid {
                continue;
            }

            // Session-level gate: for both OnlyVerifiedSessions and
            // OnlyVerifiedUsers.
            if policy != MegolmRotationVisibility::AllMembers
                && !security.is_session_verified(*uid, *sid).await
            {
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
