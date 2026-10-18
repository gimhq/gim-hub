//! Hub configuration from `GIM_HUB_*` environment variables.
//!
//! See `docs/operations.md`. Empty variables count as unset. The binary
//! passes the variables merged with the stored settings (see
//! [`crate::settings`]); the bootstrap settings ([`Bootstrap`]) only come
//! from the environment.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};

use gim_hub_identity::HUB_PROOF_MAX_URL_LEN;
use gim_hub_push::{PushConfig, WebhookConfig};

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
    /// `GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN`: recovery backup reads per
    /// client IP per minute.
    pub recovery_read_per_ip_per_min: u32,
    /// `GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN`: recovery backup reads of one
    /// user per minute.
    pub recovery_read_per_user_per_min: u32,
    /// `GIM_HUB_TRUST_FORWARDED_FOR`: key client limits by the left-most
    /// `X-Forwarded-For` address instead of the peer address.
    pub trust_forwarded_for: bool,
    /// `GIM_HUB_PUSH_*`: push gateway.
    pub push: PushConfig,
    /// `GIM_HUB_PUBLIC_URL`: the canonical client-API base URL, normalized
    /// (see [`normalize_public_url`]). Required with federation; without it
    /// the hub issues v1 sign-in challenges and has no proof of possession.
    pub public_url: Option<String>,
    /// `GIM_HUB_UNHOSTED_GRACE_HOURS`: how long the data of a user who
    /// removed this hub from their hosting record is kept before the purge
    /// (docs/multihoming.md §7.3). Only used with federation.
    pub unhosted_grace_hours: u32,
    /// The release version reported by `GET /healthz` and `GET /v2/hub`:
    /// `LODE_ACTIVE_VERSION` when supervised by lode, else the package
    /// version (see [`release_version`]).
    pub release_version: String,
}

/// The bootstrap settings, read from the environment only: needed before
/// the database (and the stored settings) can be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    /// `GIM_HUB_LISTEN`.
    pub listen: SocketAddr,
    /// `GIM_HUB_DATA_DIR`.
    pub data_dir: PathBuf,
    /// `GIM_HUB_DATABASE_PATH`.
    pub database_path: PathBuf,
    /// See [`Config::release_version`].
    pub release_version: String,
}

impl Bootstrap {
    /// Reads the bootstrap settings from `(name, value)` pairs.
    pub fn from_vars(
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let vars = relevant(vars);
        let get = |name: &str| vars.get(name).map(String::as_str);
        let data_dir = PathBuf::from(get("GIM_HUB_DATA_DIR").unwrap_or("./data"));
        Ok(Self {
            listen: parse(
                get,
                "GIM_HUB_LISTEN",
                SocketAddr::from(([0, 0, 0, 0], 8080)),
                None,
            )?,
            database_path: get("GIM_HUB_DATABASE_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| data_dir.join("hub.db")),
            release_version: release_version(get("LODE_ACTIVE_VERSION")),
            data_dir,
        })
    }

    /// Path of the hub's Ed25519 key seed.
    pub fn hub_key_path(&self) -> PathBuf {
        self.data_dir.join("hub_key")
    }
}

/// The non-empty `GIM_HUB_*` and `LODE_ACTIVE_VERSION` pairs of `vars`.
fn relevant(vars: impl IntoIterator<Item = (String, String)>) -> HashMap<String, String> {
    vars.into_iter()
        .filter(|(name, value)| {
            (name.starts_with("GIM_HUB_") || name == "LODE_ACTIVE_VERSION") && !value.is_empty()
        })
        .collect()
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
        let vars = relevant(vars);
        let get = |name: &str| vars.get(name).map(String::as_str);

        let Bootstrap {
            listen,
            data_dir,
            database_path,
            release_version,
        } = Bootstrap::from_vars(vars.clone())?;
        let public_url = get("GIM_HUB_PUBLIC_URL")
            .map(|raw| {
                normalize_public_url(raw).map_err(|reason| ConfigError {
                    name: "GIM_HUB_PUBLIC_URL",
                    value: raw.to_owned(),
                    reason,
                })
            })
            .transpose()?;
        // GIM_HUB_FEDERATION itself is validated by the federation config.
        if public_url.is_none() && get("GIM_HUB_FEDERATION").map(str::trim) == Some("true") {
            return Err(ConfigError {
                name: "GIM_HUB_PUBLIC_URL",
                value: String::new(),
                reason: "required when GIM_HUB_FEDERATION=true".into(),
            });
        }
        Ok(Self {
            listen,
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
            recovery_read_per_ip_per_min: parse(
                get,
                "GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN",
                20,
                Some(1),
            )?,
            recovery_read_per_user_per_min: parse(
                get,
                "GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN",
                10,
                Some(1),
            )?,
            trust_forwarded_for: parse(get, "GIM_HUB_TRUST_FORWARDED_FOR", false, None)?,
            push: push_config(get)?,
            unhosted_grace_hours: parse(get, "GIM_HUB_UNHOSTED_GRACE_HOURS", 168, Some(1))?,
            release_version,
            public_url,
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

/// The release version: `lode_active_version` (`LODE_ACTIVE_VERSION`, the
/// version lode launched) when set and non-empty, else the package version.
pub fn release_version(lode_active_version: Option<&str>) -> String {
    lode_active_version
        .filter(|v| !v.is_empty())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .to_owned()
}

/// Push settings; `GIM_HUB_PUSH_WEBHOOK_URL` needs a valid
/// `GIM_HUB_PUSH_WEBHOOK_SECRET`.
fn push_config<'a>(
    get: impl Fn(&str) -> Option<&'a str> + Copy,
) -> Result<PushConfig, ConfigError> {
    let timeout: u64 = parse(get, "GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS", 10, Some(1))?;
    let webhook = match get("GIM_HUB_PUSH_WEBHOOK_URL") {
        None => None,
        Some(url) => Some(
            WebhookConfig::new(
                url,
                get("GIM_HUB_PUSH_WEBHOOK_SECRET"),
                std::time::Duration::from_secs(timeout),
            )
            .map_err(|reason| ConfigError {
                name: "GIM_HUB_PUSH_WEBHOOK_URL",
                value: url.to_owned(),
                reason,
            })?,
        ),
    };
    Ok(PushConfig {
        member_events: parse(get, "GIM_HUB_PUSH_MEMBER_EVENTS", false, None)?,
        minimal: parse(get, "GIM_HUB_PUSH_MINIMAL", false, None)?,
        queue_capacity: parse(get, "GIM_HUB_PUSH_QUEUE_CAPACITY", 10_000, Some(1))?,
        log_endpoint: parse(get, "GIM_HUB_PUSH_LOG_ENDPOINT", false, None)?,
        webhook,
    })
}

/// Normalizes a public URL to `scheme://host[:port]`: scheme `http` or
/// `https`, lowercase host (DNS name, IPv4 or bracketed IPv6), the port
/// omitted when it is the scheme default, no trailing slash. Userinfo, a
/// path other than `/`, a query or a fragment are rejected, as is a result
/// longer than 65535 bytes (the proof's `u16` length). Shared vectors:
/// `testdata/identity/public-url.json`.
pub fn normalize_public_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| "expected scheme://host[:port]".to_owned())?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err("scheme must be http or https".into()),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if !tail.is_empty() && tail != "/" {
        return Err("must not have a path, query or fragment".into());
    }
    if authority.contains('@') {
        return Err("must not have userinfo".into());
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (addr, after) = v6
                .split_once(']')
                .ok_or_else(|| "unterminated IPv6 literal".to_owned())?;
            addr.parse::<std::net::Ipv6Addr>()
                .map_err(|_| "invalid IPv6 literal".to_owned())?;
            let port = match after {
                "" => None,
                _ => Some(
                    after
                        .strip_prefix(':')
                        .ok_or_else(|| "invalid authority".to_owned())?,
                ),
            };
            (format!("[{}]", addr.to_ascii_lowercase()), port)
        }
        None => {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            let host = host.to_ascii_lowercase();
            let label_ok = |label: &str| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            };
            if !host.split('.').all(label_ok) {
                return Err("invalid host".into());
            }
            (host, port)
        }
    };
    let port = match port {
        None => None,
        Some(port) => {
            let port: u16 = Some(port)
                .filter(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|port| port.parse().ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| "invalid port".to_owned())?;
            Some(port).filter(|port| *port != default_port)
        }
    };
    let url = match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    if url.len() > HUB_PROOF_MAX_URL_LEN {
        return Err(format!("longer than {HUB_PROOF_MAX_URL_LEN} bytes"));
    }
    Ok(url)
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
    fn release_version_follows_lode() {
        let version =
            |pairs: &[(&str, &str)]| Config::from_vars(vars(pairs)).unwrap().release_version;
        assert_eq!(version(&[]), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            version(&[("LODE_ACTIVE_VERSION", "")]),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(version(&[("LODE_ACTIVE_VERSION", "0.2.1")]), "0.2.1");
        assert_eq!(release_version(None), env!("CARGO_PKG_VERSION"));
        assert_eq!(release_version(Some("1.0.0-rc.1")), "1.0.0-rc.1");
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
        assert_eq!(config.recovery_read_per_ip_per_min, 20);
        assert_eq!(config.recovery_read_per_user_per_min, 10);
        assert!(!config.trust_forwarded_for);
        assert_eq!(config.hub_key_path(), PathBuf::from("./data/hub_key"));
        assert_eq!(config.blobs_dir(), PathBuf::from("./data/blobs"));
        assert_eq!(config.push, PushConfig::default());
        assert_eq!(config.release_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(config.public_url, None);
    }

    /// testdata/identity/public-url.json, shared with gim-core.
    #[test]
    fn public_url_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/identity/public-url.json"
        );
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cases = file["cases"].as_array().unwrap();
        assert!(cases.len() >= 30);
        for case in cases {
            let input = case["input"].as_str().unwrap();
            let result = Config::from_vars(vars(&[("GIM_HUB_PUBLIC_URL", input)]));
            match case["normalized"].as_str() {
                Some(normalized) => {
                    assert_eq!(normalize_public_url(input).as_deref(), Ok(normalized));
                    assert_eq!(
                        result.unwrap().public_url.as_deref(),
                        Some(normalized),
                        "{input:?}"
                    );
                }
                None => {
                    assert!(case["error"].is_string(), "{input:?}");
                    assert_eq!(result.unwrap_err().name, "GIM_HUB_PUBLIC_URL", "{input:?}");
                }
            }
        }
        let host = "a".repeat(HUB_PROOF_MAX_URL_LEN);
        assert!(normalize_public_url(&format!("https://{host}")).is_err());
    }

    #[test]
    fn federation_requires_public_url() {
        let err = Config::from_vars(vars(&[("GIM_HUB_FEDERATION", "true")])).unwrap_err();
        assert_eq!(err.name, "GIM_HUB_PUBLIC_URL");
        assert!(err
            .to_string()
            .contains("required when GIM_HUB_FEDERATION=true"));
        let config = Config::from_vars(vars(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_PUBLIC_URL", "http://hub-a:8080/"),
        ]))
        .unwrap();
        assert_eq!(config.public_url.as_deref(), Some("http://hub-a:8080"));
        assert!(Config::from_vars(vars(&[("GIM_HUB_FEDERATION", "false")])).is_ok());
    }

    #[test]
    fn push_settings() {
        let secret = "s".repeat(32);
        let config = Config::from_vars(vars(&[
            ("GIM_HUB_PUSH_MEMBER_EVENTS", "true"),
            ("GIM_HUB_PUSH_MINIMAL", "true"),
            ("GIM_HUB_PUSH_QUEUE_CAPACITY", "5"),
            ("GIM_HUB_PUSH_LOG_ENDPOINT", "true"),
            ("GIM_HUB_PUSH_WEBHOOK_URL", "http://push:8080/v1/push"),
            ("GIM_HUB_PUSH_WEBHOOK_SECRET", &secret),
            ("GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS", "3"),
        ]))
        .unwrap()
        .push;
        assert!(config.member_events && config.minimal && config.log_endpoint);
        assert_eq!(config.queue_capacity, 5);
        let webhook = config.webhook.unwrap();
        assert_eq!(webhook.url, "http://push:8080/v1/push");
        assert_eq!(webhook.secret, secret);
        assert_eq!(webhook.timeout, std::time::Duration::from_secs(3));

        let default = Config::from_vars(vars(&[
            ("GIM_HUB_PUSH_WEBHOOK_URL", "https://push.example.eu/hook"),
            ("GIM_HUB_PUSH_WEBHOOK_SECRET", &secret),
        ]))
        .unwrap();
        assert_eq!(
            default.push.webhook.unwrap().timeout,
            std::time::Duration::from_secs(10)
        );
        for bad in [
            vec![("GIM_HUB_PUSH_WEBHOOK_URL", "http://push:8080")],
            vec![
                ("GIM_HUB_PUSH_WEBHOOK_URL", "http://push:8080"),
                ("GIM_HUB_PUSH_WEBHOOK_SECRET", "short"),
            ],
            vec![
                ("GIM_HUB_PUSH_WEBHOOK_URL", "ftp://push"),
                ("GIM_HUB_PUSH_WEBHOOK_SECRET", &secret),
            ],
        ] {
            let err = Config::from_vars(vars(&bad)).unwrap_err();
            assert_eq!(err.name, "GIM_HUB_PUSH_WEBHOOK_URL");
        }
        assert!(Config::from_vars(vars(&[("GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS", "0")])).is_err());
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
            ("GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN", "4"),
            ("GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN", "2"),
            ("GIM_HUB_TRUST_FORWARDED_FOR", "true"),
        ]))
        .unwrap();
        assert_eq!(config.public_read_per_ip_per_min, 5);
        assert_eq!(config.public_read_per_user_per_min, 3);
        assert_eq!(config.recovery_read_per_ip_per_min, 4);
        assert_eq!(config.recovery_read_per_user_per_min, 2);
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
        assert!(
            Config::from_vars(vars(&[("GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN", "0")])).is_err()
        );
        assert!(Config::from_vars(vars(&[("GIM_HUB_TRUST_FORWARDED_FOR", "1")])).is_err());
    }
}
