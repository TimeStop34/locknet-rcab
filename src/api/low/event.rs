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

    ToDevice(ToDevicePayload),

    CrossSigningSignatureAdded(CrossSigningSignatureAdded),
    CrossSigningReset(CrossSigningReset),

    Reconnected,
    SessionExpired,

    Unknown { event_type: String, data: Value },
}

impl Event {
    pub(crate) fn parse(envelope: Value) -> Self {
        let event_type = envelope
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let data = envelope.get("data").cloned().unwrap_or(Value::Null);

        match event_type.as_str() {
            "message_create" => serde_json::from_value(data)
                .map(Event::MessageCreate)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "message_update" => serde_json::from_value(data)
                .map(Event::MessageUpdate)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "message_delete" => serde_json::from_value(data)
                .map(Event::MessageDelete)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "reaction_add" => serde_json::from_value(data)
                .map(Event::ReactionAdd)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "reaction_remove" => serde_json::from_value(data)
                .map(Event::ReactionRemove)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_created" => serde_json::from_value(data)
                .map(Event::GroupCreated)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_invite_created" => serde_json::from_value(data)
                .map(Event::GroupInviteCreated)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "group_membership_changed" => serde_json::from_value(data)
                .map(Event::GroupMembershipChanged)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "to_device" => serde_json::from_value(data)
                .map(Event::ToDevice)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "cross_signing_signature_added" => serde_json::from_value(data)
                .map(Event::CrossSigningSignatureAdded)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            "cross_signing_reset" => serde_json::from_value(data)
                .map(Event::CrossSigningReset)
                .unwrap_or_else(|_| Event::Unknown { event_type, data: Value::Null }),
            _ => Event::Unknown { event_type, data },
        }
    }
}