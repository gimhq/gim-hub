//! The registry of stored settings: every non-bootstrap `GIM_HUB_*`
//! setting with its group, type, default, description and apply class.
//! Values are validated by the configuration parsers themselves
//! ([`super::validate`]), so a stored value and an environment value
//! validate identically.

use serde_json::Value;

/// Environment-only settings, needed before the database opens or to reach
/// the admin API. Never stored, never listed by the settings API.
pub const BOOTSTRAP: &[&str] = &[
    "GIM_HUB_DATA_DIR",
    "GIM_HUB_DATABASE_PATH",
    "GIM_HUB_LISTEN",
    "GIM_HUB_ADMIN_LISTEN",
    "GIM_HUB_ADMIN_TOKEN",
    "GIM_HUB_ADMIN_TOKEN_FILE",
    "GIM_HUB_ADMIN_TRUSTED_HEADER",
    "GIM_HUB_ADMIN_TRUSTED_PROXIES",
    "GIM_HUB_ADMIN_COOKIE_SECURE",
];

/// Value type of a setting, as shown by the settings API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    String,
    Integer,
    Bool,
    Url,
    DurationSeconds,
    /// Comma-separated in the environment, a JSON array of strings stored.
    List,
    /// Write-only: never returned.
    Secret,
    Enum,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Bool => "bool",
            Self::Url => "url",
            Self::DurationSeconds => "duration_seconds",
            Self::List => "list",
            Self::Secret => "secret",
            Self::Enum => "enum",
        }
    }
}

/// When a changed value takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    /// At once, in the running hub.
    Live,
    /// At the next start.
    Restart,
}

impl Apply {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Restart => "restart",
        }
    }
}

/// Built-in default of a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultValue {
    /// No default (unset).
    None,
    Int(u64),
    Bool(bool),
    Str(&'static str),
    /// Comma-separated list.
    List(&'static str),
}

/// One stored setting.
#[derive(Debug, PartialEq, Eq)]
pub struct Setting {
    /// The environment variable name.
    pub key: &'static str,
    /// UI grouping: general, users, federation, push, limits, storage.
    pub group: &'static str,
    pub kind: Kind,
    /// Choices of [`Kind::Enum`].
    pub choices: Option<&'static [&'static str]>,
    pub description: &'static str,
    pub default: DefaultValue,
    pub apply: Apply,
}

impl Setting {
    pub fn is_secret(&self) -> bool {
        self.kind == Kind::Secret
    }

    /// The default as a JSON value; `null` for secrets and without default.
    pub fn default_json(&self) -> Value {
        if self.is_secret() {
            return Value::Null;
        }
        match self.default {
            DefaultValue::None => Value::Null,
            DefaultValue::Int(n) => n.into(),
            DefaultValue::Bool(b) => b.into(),
            DefaultValue::Str(s) => s.into(),
            DefaultValue::List(s) => self.json(s),
        }
    }

    /// The default in the environment format, if any.
    pub fn default_raw(&self) -> Option<String> {
        match self.default {
            DefaultValue::None => None,
            DefaultValue::Int(n) => Some(n.to_string()),
            DefaultValue::Bool(b) => Some(b.to_string()),
            DefaultValue::Str(s) | DefaultValue::List(s) => Some(s.to_owned()),
        }
    }

    /// A value in the environment format (`raw`) as JSON: a number for
    /// integers and durations, a boolean, an array of strings for lists,
    /// else the string. A raw value that does not have the type stays a
    /// string.
    pub fn json(&self, raw: &str) -> Value {
        let trimmed = raw.trim();
        match self.kind {
            Kind::Integer | Kind::DurationSeconds => trimmed
                .parse::<u64>()
                .map_or_else(|_| raw.into(), Value::from),
            Kind::Bool => match trimmed {
                "true" => true.into(),
                "false" => false.into(),
                _ => raw.into(),
            },
            Kind::List => raw
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(|part| Value::from(part.to_owned()))
                .collect::<Vec<_>>()
                .into(),
            Kind::String | Kind::Url | Kind::Secret | Kind::Enum => raw.into(),
        }
    }

    /// A JSON value written through the API or the CLI in the environment
    /// format. A string is taken as the environment value for every type;
    /// a number, a boolean or (for lists) an array of strings must match
    /// the type. Whether the value is valid is up to the parsers.
    pub fn raw(&self, value: &Value) -> Result<String, String> {
        let raw = match (self.kind, value) {
            (_, Value::Null) => return Err("a value is required; unset the setting instead".into()),
            (_, Value::String(s)) => s.clone(),
            (Kind::Integer | Kind::DurationSeconds, Value::Number(n)) => n.to_string(),
            (Kind::Bool, Value::Bool(b)) => b.to_string(),
            (Kind::List, Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "list items must be strings".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(","),
            _ => return Err(format!("expected a value of type {}", self.kind.as_str())),
        };
        if raw.trim().is_empty() {
            return Err("empty value; unset the setting instead".into());
        }
        if let Some(choices) = self.choices {
            if !choices.contains(&raw.trim()) {
                return Err(format!("expected one of {}", choices.join(", ")));
            }
        }
        Ok(raw)
    }
}

/// Federation listen default, as in `gim_hub_s2s::config`.
const P2P_LISTEN_DEFAULT: &str = "/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4001";

const fn setting(
    key: &'static str,
    group: &'static str,
    kind: Kind,
    default: DefaultValue,
    apply: Apply,
    description: &'static str,
) -> Setting {
    Setting {
        key,
        group,
        kind,
        choices: None,
        description,
        default,
        apply,
    }
}

use Apply::{Live, Restart};
use DefaultValue::{Bool as B, Int as I, List as L, None as Unset};
use Kind::{Bool, DurationSeconds, Integer, List, Secret, Url};

/// Every stored setting, in display order.
pub static SETTINGS: &[Setting] = &[
    // general
    setting(
        "GIM_HUB_PUBLIC_URL",
        "general",
        Url,
        Unset,
        Restart,
        "Canonical client-API base URL (scheme://host[:port]); required with federation",
    ),
    setting(
        "GIM_HUB_STATUS_PAGE",
        "general",
        Bool,
        B(true),
        Live,
        "Serve the status page (version and system information) at / and /status; 404 there when off",
    ),
    setting(
        "GIM_HUB_SESSION_TTL_DAYS",
        "general",
        Integer,
        I(30),
        Live,
        "Lifetime of device bearer tokens (days, minimum 1)",
    ),
    setting(
        "GIM_HUB_KEYPACKAGE_LOW_THRESHOLD",
        "general",
        Integer,
        I(10),
        Live,
        "A device is sent keypackages.low when its one-time KeyPackages drop below this",
    ),
    setting(
        "GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS",
        "general",
        DurationSeconds,
        I(30),
        Live,
        "Upper bound for long-poll wait (seconds)",
    ),
    // users
    Setting {
        key: crate::user_policy::MODE_KEY,
        group: "users",
        kind: Kind::Enum,
        choices: Some(crate::user_policy::Mode::CHOICES),
        description: "Who may use this hub: open (everyone), allow (only the users on the user \
policy list) or deny (everyone except the listed users)",
        default: DefaultValue::Str("open"),
        apply: Live,
    },
    // limits
    setting(
        "GIM_HUB_MAX_MESSAGE_BYTES",
        "limits",
        Integer,
        I(262_144),
        Live,
        "Largest accepted MLS message (bytes, minimum 1)",
    ),
    setting(
        "GIM_HUB_MAX_BLOB_BYTES",
        "limits",
        Integer,
        I(104_857_600),
        Live,
        "Largest accepted blob (bytes, minimum 1)",
    ),
    setting(
        "GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN",
        "limits",
        Integer,
        I(120),
        Live,
        "Unauthenticated user, DeviceList and hosting record reads per client IP per minute",
    ),
    setting(
        "GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN",
        "limits",
        Integer,
        I(60),
        Live,
        "Unauthenticated reads of one user per minute, across all clients",
    ),
    setting(
        "GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN",
        "limits",
        Integer,
        I(20),
        Live,
        "Recovery backup reads per client IP per minute",
    ),
    setting(
        "GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN",
        "limits",
        Integer,
        I(10),
        Live,
        "Recovery backup reads of one user per minute, across all clients",
    ),
    setting(
        "GIM_HUB_TRUST_FORWARDED_FOR",
        "limits",
        Bool,
        B(false),
        Live,
        "Key the per-IP limits by the left-most X-Forwarded-For address (behind a proxy only)",
    ),
    setting(
        "GIM_HUB_FETCH_BLOB_PER_MINUTE",
        "limits",
        Integer,
        I(600),
        Live,
        "Blob chunk requests (FetchBlob) served per peer hub and minute",
    ),
    // storage
    setting(
        "GIM_HUB_EVENT_RETENTION_DAYS",
        "storage",
        Integer,
        I(7),
        Live,
        "Events older than this are pruned (days, minimum 1)",
    ),
    setting(
        "GIM_HUB_UNHOSTED_GRACE_HOURS",
        "storage",
        Integer,
        I(168),
        Live,
        "How long data of a user who removed this hub is kept before the purge (hours)",
    ),
    // push
    setting(
        "GIM_HUB_PUSH_MEMBER_EVENTS",
        "push",
        Bool,
        B(false),
        Live,
        "Also push group.member_added / group.member_removed (silent)",
    ),
    setting(
        "GIM_HUB_PUSH_MINIMAL",
        "push",
        Bool,
        B(false),
        Live,
        "Send minimal wake-up payloads only",
    ),
    setting(
        "GIM_HUB_PUSH_QUEUE_CAPACITY",
        "push",
        Integer,
        I(10_000),
        Live,
        "Most devices with a queued push; further pushes are dropped",
    ),
    setting(
        "GIM_HUB_PUSH_LOG_ENDPOINT",
        "push",
        Bool,
        B(false),
        Live,
        "Serve the test-only GET /v2/debug/push-log; never enable in production",
    ),
    setting(
        "GIM_HUB_PUSH_WEBHOOK_URL",
        "push",
        Url,
        Unset,
        Live,
        "Push server URL; needs the webhook secret. Unset: non-log pushes are skipped",
    ),
    setting(
        "GIM_HUB_PUSH_WEBHOOK_SECRET",
        "push",
        Secret,
        Unset,
        Live,
        "HMAC-SHA256 key of X-Gim-Signature, at least 32 bytes",
    ),
    setting(
        "GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS",
        "push",
        DurationSeconds,
        I(10),
        Live,
        "Timeout of one webhook request (seconds)",
    ),
    // federation
    setting(
        "GIM_HUB_FEDERATION",
        "federation",
        Bool,
        B(false),
        Restart,
        "Run the libp2p host and federation",
    ),
    setting(
        "GIM_HUB_P2P_LISTEN",
        "federation",
        List,
        L(P2P_LISTEN_DEFAULT),
        Restart,
        "Listen multiaddrs (TCP only with a PSK)",
    ),
    setting(
        "GIM_HUB_P2P_EXTERNAL_ADDRS",
        "federation",
        List,
        Unset,
        Restart,
        "Multiaddrs advertised to peers (default: the actual listen addresses)",
    ),
    setting(
        "GIM_HUB_P2P_BOOTSTRAP",
        "federation",
        List,
        Unset,
        Restart,
        "Bootstrap multiaddrs, /p2p/<PeerId> optional",
    ),
    setting(
        "GIM_HUB_FEDERATION_ALLOWLIST",
        "federation",
        Kind::String,
        Unset,
        Restart,
        "Allowlist file; when set it is authoritative and the stored allowlist is not used",
    ),
    setting(
        "GIM_HUB_P2P_PSK_FILE",
        "federation",
        Kind::String,
        Unset,
        Restart,
        "libp2p swarm.key file (private network, TCP only); wins over the PSK",
    ),
    setting(
        "GIM_HUB_P2P_PSK",
        "federation",
        Secret,
        Unset,
        Restart,
        "The swarm.key contents (private network, TCP only), when no PSK file is set",
    ),
    setting(
        "GIM_HUB_RUNTIME_CERT_DAYS",
        "federation",
        Integer,
        I(30),
        Restart,
        "Runtime certificate lifetime (days, minimum 2)",
    ),
    setting(
        "GIM_HUB_S2S_TIMEOUT_SECONDS",
        "federation",
        DurationSeconds,
        I(10),
        Restart,
        "Timeout of one hub-to-hub request (seconds)",
    ),
    setting(
        "GIM_HUB_DHT_REPUBLISH_HOURS",
        "federation",
        Integer,
        I(12),
        Restart,
        "Republish cadence of hosted users' hosting records (hours)",
    ),
    setting(
        "GIM_HUB_PUSH_FAILOVER_SECONDS",
        "federation",
        DurationSeconds,
        I(30),
        Restart,
        "A co-host without a successful exchange for this long is down for the push rule",
    ),
    setting(
        "GIM_HUB_HOSTING_CACHE_SECONDS",
        "federation",
        DurationSeconds,
        I(600),
        Live,
        "Freshness of cached remote hosting records (seconds)",
    ),
    setting(
        "GIM_HUB_DEVICE_LIST_CACHE_HOURS",
        "federation",
        Integer,
        I(24),
        Live,
        "Freshness of cached remote DeviceLists (hours)",
    ),
    setting(
        "GIM_HUB_OUTBOX_TTL_HOURS",
        "federation",
        Integer,
        I(168),
        Live,
        "Lifetime of queued outbound hub-to-hub entries (hours)",
    ),
    setting(
        "GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER",
        "federation",
        Integer,
        I(100_000),
        Live,
        "Outbound backlog cap per peer hub (entries)",
    ),
    setting(
        "GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER",
        "federation",
        Integer,
        I(1_073_741_824),
        Live,
        "Outbound backlog cap per peer hub (bytes)",
    ),
    setting(
        "GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS",
        "federation",
        DurationSeconds,
        I(300),
        Live,
        "Maximum retry backoff per peer hub (seconds)",
    ),
];

/// The registered setting `key`.
pub fn find(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|setting| setting.key == key)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn keys_are_unique_and_never_bootstrap() {
        let mut keys: Vec<_> = SETTINGS.iter().map(|s| s.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), SETTINGS.len());
        for key in BOOTSTRAP {
            assert!(find(key).is_none(), "{key}");
        }
        assert!(find("GIM_HUB_BUILD_REV").is_none());
    }

    #[test]
    fn json_and_raw_round_trip() {
        let list = find("GIM_HUB_P2P_LISTEN").unwrap();
        assert_eq!(
            list.default_json(),
            json!(["/ip4/0.0.0.0/udp/4001/quic-v1", "/ip4/0.0.0.0/tcp/4001"])
        );
        assert_eq!(list.raw(&json!(["/a", "/b"])).unwrap(), "/a,/b");
        assert_eq!(list.raw(&json!("/a, /b")).unwrap(), "/a, /b");
        assert!(list.raw(&json!([1])).is_err());
        let int = find("GIM_HUB_EVENT_RETENTION_DAYS").unwrap();
        assert_eq!(int.json(" 30 "), json!(30));
        assert_eq!(int.json("x"), json!("x"));
        assert_eq!(int.raw(&json!(30)).unwrap(), "30");
        assert_eq!(int.raw(&json!("30")).unwrap(), "30");
        assert!(int.raw(&json!(true)).is_err());
        assert!(int.raw(&Value::Null).is_err());
        assert!(int.raw(&json!(" ")).is_err());
        let flag = find("GIM_HUB_PUSH_MINIMAL").unwrap();
        assert_eq!(flag.json("true"), json!(true));
        assert_eq!(flag.raw(&json!(false)).unwrap(), "false");
        let secret = find("GIM_HUB_PUSH_WEBHOOK_SECRET").unwrap();
        assert!(secret.is_secret());
        assert_eq!(secret.default_json(), Value::Null);
        assert!(secret.raw(&json!(1)).is_err());
        let policy = find("GIM_HUB_USER_POLICY").unwrap();
        assert_eq!((policy.kind, policy.group), (Kind::Enum, "users"));
        assert_eq!(policy.default_json(), json!("open"));
        assert_eq!(policy.raw(&json!("deny")).unwrap(), "deny");
        assert_eq!(
            policy.raw(&json!("closed")).unwrap_err(),
            "expected one of open, allow, deny"
        );
        assert!(policy.raw(&json!(1)).is_err());
    }
}
