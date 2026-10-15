//! Hub configuration from `GIM_HUB_*` environment variables.
//!
//! See `docs/operations.md`. Empty variables count as unset.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};

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
        assert_eq!(config.hub_key_path(), PathBuf::from("./data/hub_key"));
        assert_eq!(config.blobs_dir(), PathBuf::from("./data/blobs"));
    }

    #[test]
    fn overrides() {
        let config = Config::from_vars(vars(&[
            ("GIM_HUB_LISTEN", "127.0.0.1:9000"),
            ("GIM_HUB_DATA_DIR", "/var/lib/gim"),
            ("GIM_HUB_EVENT_RETENTION_DAYS", "30"),
            ("GIM_HUB_MAX_BLOB_BYTES", "1024"),
        ]))
        .unwrap();
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
    }
}
