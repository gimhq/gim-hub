//! The push payload contract (`docs/push.md`).

use serde_json::{json, Value};

/// Event that triggered a push; serialized as the payload's `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    Message,
    Welcome,
    MemberAdded,
    MemberRemoved,
}

impl PushKind {
    /// The kind for an event type, if that type triggers pushes.
    pub fn from_event_type(event_type: &str) -> Option<Self> {
        match event_type {
            "message" => Some(Self::Message),
            "welcome" => Some(Self::Welcome),
            "group.member_added" => Some(Self::MemberAdded),
            "group.member_removed" => Some(Self::MemberRemoved),
            _ => None,
        }
    }

    /// The payload `type` (equal to the event type).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Welcome => "welcome",
            Self::MemberAdded => "group.member_added",
            Self::MemberRemoved => "group.member_removed",
        }
    }

    /// Whether the user should see an alert (messages and Welcomes);
    /// membership changes are silent background pushes.
    pub fn is_alert(self) -> bool {
        matches!(self, Self::Message | Self::Welcome)
    }
}

/// A notification for one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushNotification {
    pub kind: PushKind,
    /// Alert (user-visible, webhook priority `high`) rather than silent.
    /// Starts as [`PushKind::is_alert`]; a push that coalesced an alert
    /// stays one (`docs/push.md` §4).
    pub alert: bool,
    pub gid: String,
    pub seq: u64,
    /// ID of the stored message at `(gid, seq)`; also the collapse id.
    pub message_id: String,
    /// MLS message (or Welcome), base64, inlined only if it fits the
    /// provider's limit.
    pub mls_message: Option<String>,
    /// Minimal mode (`GIM_HUB_PUSH_MINIMAL`): the payload is only a wake-up
    /// with the collapse id; `mls_message` is never inlined.
    pub minimal: bool,
    /// Unique id of this push, identical across its retries (the webhook's
    /// idempotency key).
    pub delivery_id: String,
    /// Unix ms of the first send attempt; set by the dispatcher.
    pub sent_at: i64,
}

impl PushNotification {
    /// Collapse id: always the message ID, so duplicate pushes (e.g. from
    /// several hubs of a multi-homed user) collapse on the device.
    pub fn collapse_id(&self) -> &str {
        &self.message_id
    }

    /// Webhook `priority`: `high` for alerts, `normal` for silent pushes.
    pub fn priority(&self) -> &'static str {
        if self.alert {
            "high"
        } else {
            "normal"
        }
    }

    /// The contract payload; `mls_message` is included only if `inline`.
    /// The sender is never included: it is inside the MLS ciphertext.
    pub fn payload(&self, inline: bool) -> Value {
        if self.minimal {
            return json!({ "v": 1, "type": "wake", "collapse_id": self.collapse_id() });
        }
        let mut payload = json!({
            "v": 1,
            "type": self.kind.as_str(),
            "gid": self.gid,
            "seq": self.seq,
            "message_id": self.message_id,
            "collapse_id": self.collapse_id(),
        });
        if let (true, Some(mls_message)) = (inline, &self.mls_message) {
            payload["mls_message"] = json!(mls_message);
        }
        payload
    }
}

/// Encodes `wrap(payload)` with the MLS message inlined if the encoding is
/// at most `limit` bytes, otherwise without it. Returns the encoding and
/// whether the message was inlined.
pub fn encode_within(
    notification: &PushNotification,
    limit: usize,
    wrap: impl Fn(Value) -> Vec<u8>,
) -> (Vec<u8>, bool) {
    if notification.mls_message.is_some() && !notification.minimal {
        let inlined = wrap(notification.payload(true));
        if inlined.len() <= limit {
            return (inlined, true);
        }
    }
    (wrap(notification.payload(false)), false)
}

#[cfg(test)]
pub(crate) fn sample(mls_len: usize) -> PushNotification {
    PushNotification {
        kind: PushKind::Message,
        alert: true,
        gid: "g1".into(),
        seq: 7,
        message_id: "m7".into(),
        mls_message: (mls_len > 0).then(|| "A".repeat(mls_len)),
        minimal: false,
        delivery_id: "d7".into(),
        sent_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_contract() {
        let n = sample(4);
        assert_eq!(
            n.payload(true),
            json!({
                "v": 1, "type": "message", "gid": "g1", "seq": 7, "message_id": "m7",
                "collapse_id": "m7", "mls_message": "AAAA",
            })
        );
        assert!(n.payload(false).get("mls_message").is_none());
    }

    #[test]
    fn minimal_payload_is_a_wake_up() {
        let n = PushNotification {
            minimal: true,
            ..sample(4)
        };
        let wake = json!({ "v": 1, "type": "wake", "collapse_id": "m7" });
        assert_eq!(n.payload(true), wake);
        let plain = |v: Value| serde_json::to_vec(&v).unwrap();
        let (bytes, inlined) = encode_within(&n, 4096, plain);
        assert!(!inlined);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), wake);
    }

    #[test]
    fn inlines_only_within_limit() {
        let plain = |v: Value| serde_json::to_vec(&v).unwrap();
        let (small, inlined) = encode_within(&sample(100), 4096, plain);
        assert!(inlined);
        assert!(small.len() <= 4096);
        let (big, inlined) = encode_within(&sample(5000), 4096, plain);
        assert!(!inlined);
        assert_eq!(
            serde_json::from_slice::<Value>(&big).unwrap(),
            sample(0).payload(false)
        );
        let (_, inlined) = encode_within(&sample(0), 4096, plain);
        assert!(!inlined);
    }

    #[test]
    fn event_types_map_to_kinds() {
        for kind in [
            PushKind::Message,
            PushKind::Welcome,
            PushKind::MemberAdded,
            PushKind::MemberRemoved,
        ] {
            assert_eq!(PushKind::from_event_type(kind.as_str()), Some(kind));
        }
        assert_eq!(PushKind::from_event_type("keypackages.low"), None);
    }
}
