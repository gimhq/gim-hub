//! Hub configuration from `GIM_HUB_*` environment variables.
//!
//! See `docs/operations.md`. Empty variables count as unset.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};

use gim_hub_push::{ApnsConfig, FcmConfig, PushConfig};

/// Hub configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `GIM_HUB_LISTEN`: socket address to serve on.
    pub listen: SocketAddr,
    /// `GIM_HUB_DATA_DIR`: holds `hub.db`, `hub_key` and `blobs/`.
    pub data_dir: PathBuf,
    /// `GIM_HUB_DATABASE_PATH`: SQLite database file.
    pub database_path: PathBuf,
    /// `GIM_HUB_EVENT_RETENTION_DAYS`: events older than this are pruned.
    pub event_retention_days: u32,
    /// `GIM_HUB_KEYPACKAGE_LOW_THRESHOLD`: emit `keypackages.low` below this.
    pub keypackage_low_threshold: u32,
    /// `GIM_HUB_MAX_MESSAGE_BYTES`: largest accepted MLS message.
    pub max_message_bytes: usize,
    /// `GIM_HUB_MAX_BLOB_BYTES`: largest accepted blob.
    pub max_blob_bytes: u64,
    /// `GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS`: cap on long-poll `wait`.
    pub longpoll_max_wait_seconds: u32,
    /// `GIM_HUB_SESSION_TTL_DAYS`: lifetime of device bearer tokens.
    pub session_ttl_days: u32,
    /// `GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN`: unauthenticated user reads per
    /// client IP per minute.
    pub public_read_per_ip_per_min: u32,
    /// `GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN`: unauthenticated reads of one
    /// user per minute.
    pub public_read_per_user_per_min: u32,
    /// `GIM_HUB_TRUST_FORWARDED_FOR`: key client limits by the left-most
    /// `X-Forwarded-For` address instead of the peer address.
    pub trust_forwarded_for: bool,
    /// `GIM_HUB_PUSH_*`: push gateway.
    pub push: PushConfig,
    /// `GIM_HUB_UNHOSTED_GRACE_HOURS`: how long the data of a user who
    /// removed this hub from their hosting record is kept before the purge
    /// (docs/multihoming.md §7.3). Only used with federation.
    pub unhosted_grace_hours: u32,
}

/// Invalid configuration value.
#[derive(Debug, thiserror::Error)]
#[error("invalid {name}={value:?}: {reason}")]
pub struct ConfigError {
    pub name: &'static str,
    pub value: String,
    pub reason: String,
}

impl Config {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(std::env::vars())
    }

    /// Reads the configuration from `(name, value)` pairs.
    pub fn from_vars(
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let vars: HashMap<String, String> = vars
            .into_iter()
            .filter(|(name, value)| name.starts_with("GIM_HUB_") && !value.is_empty())
            .collect();
        let get = |name: &str| vars.get(name).map(String::as_str);

        let data_dir = PathBuf::from(get("GIM_HUB_DATA_DIR").unwrap_or("./data"));
        let database_path = get("GIM_HUB_DATABASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("hub.db"));
        Ok(Self {
            listen: parse(
                get,
                "GIM_HUB_LISTEN",
                SocketAddr::from(([0, 0, 0, 0], 8080)),
                None,
            )?,
            event_retention_days: parse(get, "GIM_HUB_EVENT_RETENTION_DAYS", 7, Some(1))?,
            keypackage_low_threshold: parse(get, "GIM_HUB_KEYPACKAGE_LOW_THRESHOLD", 10, None)?,
            max_message_bytes: parse(get, "GIM_HUB_MAX_MESSAGE_BYTES", 262_144, Some(1))?,
            max_blob_bytes: parse(get, "GIM_HUB_MAX_BLOB_BYTES", 104_857_600, Some(1))?,
            longpoll_max_wait_seconds: parse(get, "GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS", 30, None)?,
            session_ttl_days: parse(get, "GIM_HUB_SESSION_TTL_DAYS", 30, Some(1))?,
            public_read_per_ip_per_min: parse(
                get,
                "GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN",
                120,
                Some(1),
            )?,
            public_read_per_user_per_min: parse(
                get,
                "GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN",
                60,
                Some(1),
            )?,
            trust_forwarded_for: parse(get, "GIM_HUB_TRUST_FORWARDED_FOR", false, None)?,
            push: push_config(get)?,
            unhosted_grace_hours: parse(get, "GIM_HUB_UNHOSTED_GRACE_HOURS", 168, Some(1))?,
            data_dir,
            database_path,
        })
    }

    /// Path of the hub's Ed25519 key seed.
    pub fn hub_key_path(&self) -> PathBuf {
        self.data_dir.join("hub_key")
    }

    /// Directory of blob contents.
    pub fn blobs_dir(&self) -> PathBuf {
        self.data_dir.join("blobs")
    }
}

/// Push settings; APNs needs all four `GIM_HUB_PUSH_APNS_*` credentials
/// variables, FCM a service account path.
fn push_config<'a>(
    get: impl Fn(&str) -> Option<&'a str> + Copy,
) -> Result<PushConfig, ConfigError> {
    let apns = match (
        get("GIM_HUB_PUSH_APNS_TEAM_ID"),
        get("GIM_HUB_PUSH_APNS_KEY_ID"),
        get("GIM_HUB_PUSH_APNS_KEY_PATH"),
        get("GIM_HUB_PUSH_APNS_TOPIC"),
    ) {
        (None, None, None, None) => None,
        (Some(team_id), Some(key_id), Some(key_path), Some(topic)) => Some(ApnsConfig {
            team_id: team_id.to_owned(),
            key_id: key_id.to_owned(),
            key_path: PathBuf::from(key_path),
            topic: topic.to_owned(),
            sandbox: parse(get, "GIM_HUB_PUSH_APNS_SANDBOX", false, None)?,
        }),
        (team_id, ..) => {
            return Err(ConfigError {
                name: "GIM_HUB_PUSH_APNS_TEAM_ID",
                value: team_id.unwrap_or_default().to_owned(),
                reason: "set GIM_HUB_PUSH_APNS_TEAM_ID, _KEY_ID, _KEY_PATH and _TOPIC together"
                    .into(),
            })
        }
    };
    let fcm = get("GIM_HUB_PUSH_FCM_SERVICE_ACCOUNT_PATH").map(|path| FcmConfig {
        service_account_path: PathBuf::from(path),
        project_id: get("GIM_HUB_PUSH_FCM_PROJECT_ID").map(str::to_owned),
    });
    Ok(PushConfig {
        member_events: parse(get, "GIM_HUB_PUSH_MEMBER_EVENTS", false, None)?,
        minimal: parse(get, "GIM_HUB_PUSH_MINIMAL", false, None)?,
        queue_capacity: parse(get, "GIM_HUB_PUSH_QUEUE_CAPACITY", 10_000, Some(1))?,
        log_endpoint: parse(get, "GIM_HUB_PUSH_LOG_ENDPOINT", false, None)?,
        apns,
        fcm,
        unifiedpush: parse(get, "GIM_HUB_PUSH_UNIFIEDPUSH", false, None)?,
    })
}

/// Parses `name` or returns `default`; `min` is the smallest accepted value.
fn parse<'a, T>(
    get: impl Fn(&str) -> Option<&'a str>,
    name: &'static str,
    default: T,
    min: Option<T>,
) -> Result<T, ConfigError>
where
    T: FromStr + PartialOrd + std::fmt::Display,
    T::Err: std::fmt::Display,
{
    let Some(raw) = get(name) else {
        return Ok(default);
    };
    let invalid = |reason: String| ConfigError {
        name,
        value: raw.to_owned(),
        reason,
    };
    let value: T = raw
        .trim()
        .parse()
        .map_err(|err: T::Err| invalid(err.to_string()))?;
    if let Some(min) = min.filter(|min| value < *min) {
        return Err(invalid(format!("must be at least {min}")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn defaults() {
        let config = Config::from_vars(vars(&[("GIM_HUB_LISTEN", "")])).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.data_dir, PathBuf::from("./data"));
        assert_eq!(config.database_path, PathBuf::from("./data/hub.db"));
        assert_eq!(config.event_retention_days, 7);
        assert_eq!(config.keypackage_low_threshold, 10);
        assert_eq!(config.max_message_bytes, 262_144);
        assert_eq!(config.max_blob_bytes, 104_857_600);
        assert_eq!(config.longpoll_max_wait_seconds, 30);
        assert_eq!(config.session_ttl_days, 30);
        assert_eq!(config.unhosted_grace_hours, 168);
        assert_eq!(config.public_read_per_ip_per_min, 120);
        assert_eq!(config.public_read_per_user_per_min, 60);
        assert!(!config.trust_forwarded_for);
        assert_eq!(config.hub_key_path(), PathBuf::from("./data/hub_key"));
        assert_eq!(config.blobs_dir(), PathBuf::from("./data/blobs"));
        assert_eq!(config.push, PushConfig::default());
    }

    #[test]
    fn push_settings() {
        let config = Config::from_vars(vars(&[
            ("GIM_HUB_PUSH_MEMBER_EVENTS", "true"),
            ("GIM_HUB_PUSH_MINIMAL", "true"),
            ("GIM_HUB_PUSH_QUEUE_CAPACITY", "5"),
            ("GIM_HUB_PUSH_LOG_ENDPOINT", "true"),
            ("GIM_HUB_PUSH_APNS_TEAM_ID", "TEAM123456"),
            ("GIM_HUB_PUSH_APNS_KEY_ID", "KEY1234567"),
            ("GIM_HUB_PUSH_APNS_KEY_PATH", "/run/secrets/apns.p8"),
            ("GIM_HUB_PUSH_APNS_TOPIC", "im.g.apps"),
            (
                "GIM_HUB_PUSH_FCM_SERVICE_ACCOUNT_PATH",
                "/run/secrets/fcm.json",
            ),
            ("GIM_HUB_PUSH_UNIFIEDPUSH", "true"),
        ]))
        .unwrap()
        .push;
        assert!(config.member_events && config.minimal);
        assert!(config.log_endpoint && config.unifiedpush);
        assert_eq!(config.queue_capacity, 5);
        let apns = config.apns.unwrap();
        assert_eq!(apns.key_path, PathBuf::from("/run/secrets/apns.p8"));
        assert!(!apns.sandbox);
        let fcm = config.fcm.unwrap();
        assert_eq!(fcm.project_id, None);

        let err = Config::from_vars(vars(&[("GIM_HUB_PUSH_APNS_KEY_ID", "K")])).unwrap_err();
        assert_eq!(err.name, "GIM_HUB_PUSH_APNS_TEAM_ID");
        assert!(Config::from_vars(vars(&[("GIM_HUB_PUSH_LOG_ENDPOINT", "yes")])).is_err());
        assert!(Config::from_vars(vars(&[("GIM_HUB_PUSH_QUEUE_CAPACITY", "0")])).is_err());
    }

    #[test]
    fn overrides() {
        let config = Config::from_vars(vars(&[
            ("GIM_HUB_LISTEN", "127.0.0.1:9000"),
            ("GIM_HUB_DATA_DIR", "/var/lib/gim"),
            ("GIM_HUB_EVENT_RETENTION_DAYS", "30"),
            ("GIM_HUB_MAX_BLOB_BYTES", "1024"),
            ("GIM_HUB_UNHOSTED_GRACE_HOURS", "1"),
            ("GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN", "5"),
            ("GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN", "3"),
            ("GIM_HUB_TRUST_FORWARDED_FOR", "true"),
        ]))
        .unwrap();
        assert_eq!(config.public_read_per_ip_per_min, 5);
        assert_eq!(config.public_read_per_user_per_min, 3);
        assert!(config.trust_forwarded_for);
        assert_eq!(config.unhosted_grace_hours, 1);
        assert_eq!(config.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.database_path, PathBuf::from("/var/lib/gim/hub.db"));
        assert_eq!(config.event_retention_days, 30);
        assert_eq!(config.max_blob_bytes, 1024);

        let config = Config::from_vars(vars(&[("GIM_HUB_DATABASE_PATH", "/tmp/x.db")])).unwrap();
        assert_eq!(config.database_path, PathBuf::from("/tmp/x.db"));
    }

    #[test]
    fn invalid_values_are_rejected() {
        let err = Config::from_vars(vars(&[("GIM_HUB_EVENT_RETENTION_DAYS", "0")])).unwrap_err();
        assert_eq!(err.name, "GIM_HUB_EVENT_RETENTION_DAYS");
        assert!(Config::from_vars(vars(&[("GIM_HUB_MAX_MESSAGE_BYTES", "big")])).is_err());
        assert!(Config::from_vars(vars(&[("GIM_HUB_LISTEN", "nowhere")])).is_err());
        assert!(Config::from_vars(vars(&[("GIM_HUB_SESSION_TTL_DAYS", "0")])).is_err());
        assert!(Config::from_vars(vars(&[("GIM_HUB_UNHOSTED_GRACE_HOURS", "0")])).is_err());
        assert!(Config::from_vars(vars(&[("GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN", "0")])).is_err());
        assert!(Config::from_vars(vars(&[("GIM_HUB_TRUST_FORWARDED_FOR", "1")])).is_err());
    }
}
