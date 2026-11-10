use serde_json::Value;
use super::models::*;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Event {
    MessageCreate(MessageCreate),
    MessageUpdate(MessageUpdate),
    MessageDelete(MessageDelete),
    ReactionAdd(ReactionAdd),
    ReactionRemove(ReactionRemove),
    GroupCreated(GroupCreated),
    GroupInviteCreated(GroupInviteCreated),
    GroupMembershipChanged(GroupMembershipChanged),
    GroupDataUpdated { group_id: i64 },
    ToDevice(ToDevicePayload),
    CrossSigningSignatureAdded(CrossSigningSignatureAdded),
    CrossSigningReset(CrossSigningReset),
    Reconnected,
    SessionExpired,
    Unknown { event_type: String, data: Value },
}

impl Event {
    pub(crate) fn parse(envelope: Value) -> Self {
        let event_type = envelope.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let data = envelope.get("data").cloned().unwrap_or(Value::Null);

        match event_type.as_str() {
            "message_create" => serde_json::from_value(data).map(Event::MessageCreate).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "message_update" => serde_json::from_value(data).map(Event::MessageUpdate).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "message_delete" => serde_json::from_value(data).map(Event::MessageDelete).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "reaction_add" => serde_json::from_value(data).map(Event::ReactionAdd).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "reaction_remove" => serde_json::from_value(data).map(Event::ReactionRemove).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_created" => serde_json::from_value(data).map(Event::GroupCreated).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_invite_created" => serde_json::from_value(data).map(Event::GroupInviteCreated).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_membership_changed" => serde_json::from_value(data).map(Event::GroupMembershipChanged).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_data_updated" => {
                match data.get("group_id").and_then(|v| v.as_i64()) {
                    Some(id) if id != 0 => Event::GroupDataUpdated { group_id: id },
                    _ => Event::Unknown { event_type, data },
                }
            }
            "to_device" => serde_json::from_value(data).map(Event::ToDevice).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "cross_signing_signature_added" => serde_json::from_value(data).map(Event::CrossSigningSignatureAdded).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "cross_signing_reset" => serde_json::from_value(data).map(Event::CrossSigningReset).unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            _ => Event::Unknown { event_type, data },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(v: serde_json::Value) -> Event {
        Event::parse(v)
    }


    #[test]
    fn parse_message_create_ok() {
        let v = json!({
            "type": "message_create",
            "data": {
                "message_id": 1i64,
                "chat_id": 2i64,
                "author_id": 3i64,
                "author_session_id": 4i64,
                "encrypted": {
                    "algorithm": "ln.encryption.megolm.v1",
                    "sender_key": "k",
                    "sender_session_id": 4i64,
                    "megolm_session_id": "m",
                    "ciphertext": "ct",
                },
                "thread_id": null,
                "created_at": "2026-01-01T00:00:00Z",
                "edited_at": null,
                "reactions": [],
            }
        });
        match parse(v) {
            Event::MessageCreate(mc) => {
                assert_eq!(mc.message_id, 1);
                assert_eq!(mc.chat_id, 2);
            }
            other => panic!("expected MessageCreate, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_create_missing_encrypted_becomes_unknown() {
        let v = json!({
            "type": "message_create",
            "data": {
                "message_id": 1i64,
                "chat_id": 2i64,
                "author_id": 3i64,
                "author_session_id": 4i64,
                "thread_id": null,
                "created_at": "2026-01-01T00:00:00Z",
                "edited_at": null,
                "reactions": [],
            }
        });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "message_create"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_message_create_null_data_becomes_unknown() {
        let v = json!({ "type": "message_create", "data": null });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "message_create"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }


    #[test]
    fn parse_group_data_updated_ok() {
        let v = json!({
            "type": "group_data_updated",
            "data": { "group_id": 42i64 }
        });
        match parse(v) {
            Event::GroupDataUpdated { group_id } => assert_eq!(group_id, 42),
            other => panic!("expected GroupDataUpdated, got {other:?}"),
        }
    }

    #[test]
    fn parse_group_data_updated_missing_id_becomes_unknown() {
        let v = json!({ "type": "group_data_updated", "data": {} });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "group_data_updated"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_group_data_updated_zero_id_becomes_unknown() {
        let v = json!({ "type": "group_data_updated", "data": { "group_id": 0i64 } });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "group_data_updated"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_group_data_updated_string_id_becomes_unknown() {
        let v = json!({ "type": "group_data_updated", "data": { "group_id": "42" } });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "group_data_updated"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }


    #[test]
    fn parse_error_becomes_unknown() {
        let v = json!({
            "type": "error",
            "id": "r1",
            "data": { "id": "rate_limited", "error": "too many" }
        });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "error"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_without_id_becomes_unknown() {
        let v = json!({
            "type": "error",
            "data": { "id": "internal", "error": "boom" }
        });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "error"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }


    #[test]
    fn parse_unknown_type_preserves_event_type_and_data() {
        let v = json!({
            "type": "ln.something.weird",
            "data": { "foo": "bar" }
        });
        match parse(v) {
            Event::Unknown { event_type, data } => {
                assert_eq!(event_type, "ln.something.weird");
                assert_eq!(data["foo"], "bar");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_missing_type_becomes_unknown_with_empty_type() {
        let v = json!({ "data": { "x": 1 } });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, ""),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn parse_no_data_field_does_not_panic() {
        let v = json!({ "type": "message_create" });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "message_create"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }


    #[test]
    fn parse_membership_changed_ok() {
        let v = json!({
            "type": "group_membership_changed",
            "data": { "group_id": 1i64, "change": "added", "user_id": 2i64 }
        });
        match parse(v) {
            Event::GroupMembershipChanged(mc) => {
                assert_eq!(mc.group_id, 1);
                assert_eq!(mc.user_id, 2);
                assert_eq!(mc.change, super::super::models::MembershipChange::Added);
            }
            other => panic!("expected GroupMembershipChanged, got {other:?}"),
        }
    }

    #[test]
    fn parse_reaction_add_ok() {
        let v = json!({
            "type": "reaction_add",
            "data": {
                "message_id": 1i64, "chat_id": 2i64, "user_id": 3i64,
                "emoji": "👍", "created_at": "2026-01-01T00:00:00Z"
            }
        });
        match parse(v) {
            Event::ReactionAdd(r) => {
                assert_eq!(r.message_id, 1);
                assert_eq!(r.emoji, "👍");
            }
            other => panic!("expected ReactionAdd, got {other:?}"),
        }
    }

    #[test]
    fn parse_reaction_add_missing_emoji_becomes_unknown() {
        let v = json!({
            "type": "reaction_add",
            "data": { "message_id": 1i64, "chat_id": 2i64, "user_id": 3i64,
                      "created_at": "2026-01-01T00:00:00Z" }
        });
        match parse(v) {
            Event::Unknown { event_type, .. } => assert_eq!(event_type, "reaction_add"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }
}