//! Federation configuration from `GIM_HUB_*` environment variables
//! (docs/federation.md §10).
//!
//! Same conventions as the hub configuration: empty variables count as
//! unset and an invalid value stops the hub naming the variable. Every
//! variable except `GIM_HUB_FEDERATION` is ignored while federation is
//! disabled.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use crate::transport::{self, Multiaddr};

/// Pre-shared key for libp2p pnet.
pub type Psk = [u8; 32];

/// Federation configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationConfig {
    /// `GIM_HUB_FEDERATION`: run the libp2p host and federation.
    pub enabled: bool,
    /// The hub data directory (`runtime_key`, `runtime_cert`, `allowlist`).
    pub data_dir: PathBuf,
    /// `GIM_HUB_P2P_LISTEN`: listen multiaddrs.
    pub listen: Vec<Multiaddr>,
    /// `GIM_HUB_P2P_EXTERNAL_ADDRS`: advertised multiaddrs; empty means the
    /// actual listen addresses that are not unspecified.
    pub external_addrs: Vec<Multiaddr>,
    /// `GIM_HUB_P2P_BOOTSTRAP`: bootstrap multiaddrs, `/p2p/<PeerId>` optional.
    pub bootstrap: Vec<Multiaddr>,
    /// `GIM_HUB_FEDERATION_ALLOWLIST`: allowlist file.
    pub allowlist_path: PathBuf,
    /// The stored allowlist (file format) to use instead of the file at
    /// `allowlist_path`. Never set from variables: the settings loader sets
    /// it when the stored allowlist is in force.
    pub allowlist_text: Option<String>,
    /// `GIM_HUB_P2P_PSK_FILE` (read and parsed), else `GIM_HUB_P2P_PSK` (the
    /// `swarm.key` contents, parsed). `Some` means TCP only.
    pub psk: Option<Psk>,
    /// `GIM_HUB_RUNTIME_CERT_DAYS`: runtime certificate lifetime.
    pub runtime_cert_days: u32,
    /// `GIM_HUB_S2S_TIMEOUT_SECONDS`: timeout of one S2S request.
    pub s2s_timeout: Duration,
    /// `GIM_HUB_DHT_REPUBLISH_HOURS`: republish cadence of hosted users' records.
    pub dht_republish_hours: u32,
    /// `GIM_HUB_HOSTING_CACHE_SECONDS`: freshness of cached hosting records.
    pub hosting_cache_seconds: u32,
    /// `GIM_HUB_DEVICE_LIST_CACHE_HOURS`: freshness of cached DeviceLists.
    pub device_list_cache_hours: u32,
    /// `GIM_HUB_OUTBOX_TTL_HOURS`: outbox entry lifetime.
    pub outbox_ttl_hours: u32,
    /// `GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER`: backlog cap, entries.
    pub outbox_max_entries_per_peer: u64,
    /// `GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER`: backlog cap, bytes.
    pub outbox_max_bytes_per_peer: u64,
    /// `GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS`: maximum retry backoff per peer.
    pub outbox_backoff_max_seconds: u32,
    /// `GIM_HUB_PUSH_FAILOVER_SECONDS`: a co-host without a successful ping
    /// or S2S exchange for this long is down for the push rule
    /// (docs/multihoming.md §8, §10).
    pub push_failover_seconds: u32,
    /// `GIM_HUB_FETCH_BLOB_PER_MINUTE`: `FetchBlob` requests served per
    /// caller hub and minute.
    pub fetch_blob_per_minute: u32,
}

/// Invalid configuration value.
#[derive(Debug, thiserror::Error)]
#[error("invalid {name}={value:?}: {reason}")]
pub struct ConfigError {
    pub name: &'static str,
    pub value: String,
    pub reason: String,
}

const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4001";

impl FederationConfig {
    /// Reads the configuration from the process environment.
    pub fn from_env(data_dir: &Path) -> Result<Self, ConfigError> {
        Self::from_vars(std::env::vars(), data_dir)
    }

    /// Reads the configuration from `(name, value)` pairs; `data_dir` is the
    /// hub's `GIM_HUB_DATA_DIR`.
    pub fn from_vars(
        vars: impl IntoIterator<Item = (String, String)>,
        data_dir: &Path,
    ) -> Result<Self, ConfigError> {
        let vars: HashMap<String, String> = vars
            .into_iter()
            .filter(|(name, value)| name.starts_with("GIM_HUB_") && !value.is_empty())
            .collect();
        let get = |name: &str| vars.get(name).map(String::as_str);

        let enabled = match get("GIM_HUB_FEDERATION").map(str::trim) {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                return Err(ConfigError {
                    name: "GIM_HUB_FEDERATION",
                    value: other.to_owned(),
                    reason: "expected true or false".into(),
                })
            }
        };
        let mut config = Self::disabled(data_dir);
        if !enabled {
            return Ok(config);
        }
        config.enabled = true;
        config.listen = addrs(get, "GIM_HUB_P2P_LISTEN")?
            .unwrap_or_else(|| parse_addrs(DEFAULT_LISTEN).expect("default listen addrs"));
        config.external_addrs = addrs(get, "GIM_HUB_P2P_EXTERNAL_ADDRS")?.unwrap_or_default();
        config.bootstrap = addrs(get, "GIM_HUB_P2P_BOOTSTRAP")?.unwrap_or_default();
        if let Some(path) = get("GIM_HUB_FEDERATION_ALLOWLIST") {
            config.allowlist_path = PathBuf::from(path);
        }
        if let Some(path) = get("GIM_HUB_P2P_PSK_FILE") {
            let invalid = |reason: String| ConfigError {
                name: "GIM_HUB_P2P_PSK_FILE",
                value: path.to_owned(),
                reason,
            };
            let text = std::fs::read_to_string(path).map_err(|err| invalid(err.to_string()))?;
            config.psk = Some(parse_swarm_key(&text).map_err(invalid)?);
        } else if let Some(text) = get("GIM_HUB_P2P_PSK") {
            // The value is secret: the error never shows it.
            config.psk = Some(parse_swarm_key(text).map_err(|reason| ConfigError {
                name: "GIM_HUB_P2P_PSK",
                value: "***".into(),
                reason,
            })?);
        }
        if config.psk.is_some() {
            for (name, list) in [
                ("GIM_HUB_P2P_LISTEN", &config.listen),
                ("GIM_HUB_P2P_EXTERNAL_ADDRS", &config.external_addrs),
                ("GIM_HUB_P2P_BOOTSTRAP", &config.bootstrap),
            ] {
                if let Some(addr) = list.iter().find(|addr| transport::is_quic(addr)) {
                    return Err(ConfigError {
                        name,
                        value: addr.to_string(),
                        reason: "QUIC is not available with GIM_HUB_P2P_PSK_FILE (TCP only)".into(),
                    });
                }
            }
        }
        config.runtime_cert_days = parse(get, "GIM_HUB_RUNTIME_CERT_DAYS", 30, 2)?;
        config.s2s_timeout = Duration::from_secs(parse(get, "GIM_HUB_S2S_TIMEOUT_SECONDS", 10, 1)?);
        config.dht_republish_hours = parse(get, "GIM_HUB_DHT_REPUBLISH_HOURS", 12, 1)?;
        config.hosting_cache_seconds = parse(get, "GIM_HUB_HOSTING_CACHE_SECONDS", 600, 0)?;
        config.device_list_cache_hours = parse(get, "GIM_HUB_DEVICE_LIST_CACHE_HOURS", 24, 0)?;
        config.outbox_ttl_hours = parse(get, "GIM_HUB_OUTBOX_TTL_HOURS", 168, 1)?;
        config.outbox_max_entries_per_peer =
            parse(get, "GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER", 100_000, 1)?;
        config.outbox_max_bytes_per_peer =
            parse(get, "GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER", 1_073_741_824, 1)?;
        config.outbox_backoff_max_seconds =
            parse(get, "GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS", 300, 1)?;
        config.push_failover_seconds = parse(get, "GIM_HUB_PUSH_FAILOVER_SECONDS", 30, 1)?;
        config.fetch_blob_per_minute = parse(
            get,
            "GIM_HUB_FETCH_BLOB_PER_MINUTE",
            crate::policy::FETCH_BLOB_LIMIT,
            1,
        )?;
        Ok(config)
    }

    /// The default configuration with federation disabled.
    pub fn disabled(data_dir: &Path) -> Self {
        Self {
            enabled: false,
            data_dir: data_dir.to_owned(),
            listen: parse_addrs(DEFAULT_LISTEN).expect("default listen addrs"),
            external_addrs: Vec::new(),
            bootstrap: Vec::new(),
            allowlist_path: data_dir.join("allowlist"),
            allowlist_text: None,
            psk: None,
            runtime_cert_days: 30,
            s2s_timeout: Duration::from_secs(10),
            dht_republish_hours: 12,
            hosting_cache_seconds: 600,
            device_list_cache_hours: 24,
            outbox_ttl_hours: 168,
            outbox_max_entries_per_peer: 100_000,
            outbox_max_bytes_per_peer: 1_073_741_824,
            outbox_backoff_max_seconds: 300,
            push_failover_seconds: 30,
            fetch_blob_per_minute: crate::policy::FETCH_BLOB_LIMIT,
        }
    }

    /// Path of the runtime (libp2p host) key seed.
    pub fn runtime_key_path(&self) -> PathBuf {
        self.data_dir.join("runtime_key")
    }

    /// Path of the runtime certificate (`SignedHubRuntimeCert` CBOR).
    pub fn runtime_cert_path(&self) -> PathBuf {
        self.data_dir.join("runtime_cert")
    }
}

/// Parses a comma-separated multiaddr list; `None` when unset.
fn addrs<'a>(
    get: impl Fn(&str) -> Option<&'a str>,
    name: &'static str,
) -> Result<Option<Vec<Multiaddr>>, ConfigError> {
    get(name)
        .map(|raw| {
            parse_addrs(raw).map_err(|reason| ConfigError {
                name,
                value: raw.to_owned(),
                reason,
            })
        })
        .transpose()
}

fn parse_addrs(raw: &str) -> Result<Vec<Multiaddr>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<Multiaddr>()
                .map_err(|err| format!("{part:?}: {err}"))
        })
        .collect()
}

/// Parses a libp2p `swarm.key` file:
/// `/key/swarm/psk/1.0.0/\n/base16/\n<64 hex chars>`.
pub fn parse_swarm_key(text: &str) -> Result<Psk, String> {
    let mut lines = text.lines().map(str::trim);
    if lines.next() != Some("/key/swarm/psk/1.0.0/") {
        return Err("expected /key/swarm/psk/1.0.0/ header".into());
    }
    if lines.next() != Some("/base16/") {
        return Err("expected /base16/ encoding".into());
    }
    let key = lines.next().ok_or("missing key")?;
    if lines.any(|line| !line.is_empty()) {
        return Err("trailing data after the key".into());
    }
    let bytes = hex::decode(key).map_err(|err| format!("key: {err}"))?;
    Psk::try_from(bytes.as_slice()).map_err(|_| "key must be 32 bytes (64 hex chars)".into())
}

/// Parses `name` or returns `default`; `min` is the smallest accepted value.
fn parse<'a, T>(
    get: impl Fn(&str) -> Option<&'a str>,
    name: &'static str,
    default: T,
    min: T,
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
    if value < min {
        return Err(invalid(format!("must be at least {min}")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "/key/swarm/psk/1.0.0/\n/base16/\n\
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn load(pairs: &[(&str, &str)]) -> Result<FederationConfig, ConfigError> {
        FederationConfig::from_vars(vars(pairs), Path::new("/data"))
    }

    #[test]
    fn disabled_by_default_and_ignores_other_variables() {
        let config = load(&[("GIM_HUB_P2P_LISTEN", "garbage")]).unwrap();
        assert!(!config.enabled);
        assert_eq!(config, FederationConfig::disabled(Path::new("/data")));
        assert!(!load(&[("GIM_HUB_FEDERATION", "false")]).unwrap().enabled);
        assert!(!load(&[("GIM_HUB_FEDERATION", "")]).unwrap().enabled);
    }

    #[test]
    fn defaults_when_enabled() {
        let config = load(&[("GIM_HUB_FEDERATION", "true")]).unwrap();
        assert!(config.enabled);
        assert_eq!(
            config.listen,
            vec![
                "/ip4/0.0.0.0/udp/4001/quic-v1"
                    .parse::<Multiaddr>()
                    .unwrap(),
                "/ip4/0.0.0.0/tcp/4001".parse().unwrap(),
            ]
        );
        assert!(config.external_addrs.is_empty());
        assert!(config.bootstrap.is_empty());
        assert_eq!(config.allowlist_path, PathBuf::from("/data/allowlist"));
        assert_eq!(config.psk, None);
        assert_eq!(config.runtime_cert_days, 30);
        assert_eq!(config.s2s_timeout, Duration::from_secs(10));
        assert_eq!(config.dht_republish_hours, 12);
        assert_eq!(config.hosting_cache_seconds, 600);
        assert_eq!(config.device_list_cache_hours, 24);
        assert_eq!(config.outbox_ttl_hours, 168);
        assert_eq!(config.outbox_max_entries_per_peer, 100_000);
        assert_eq!(config.outbox_max_bytes_per_peer, 1_073_741_824);
        assert_eq!(config.outbox_backoff_max_seconds, 300);
        assert_eq!(config.push_failover_seconds, 30);
        assert_eq!(config.fetch_blob_per_minute, 600);
        assert_eq!(
            config.runtime_key_path(),
            PathBuf::from("/data/runtime_key")
        );
        assert_eq!(
            config.runtime_cert_path(),
            PathBuf::from("/data/runtime_cert")
        );
    }

    #[test]
    fn overrides() {
        let config = load(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_LISTEN", "/ip4/127.0.0.1/tcp/0, /ip6/::1/tcp/0"),
            ("GIM_HUB_P2P_EXTERNAL_ADDRS", "/dns4/hub-a/tcp/4001"),
            ("GIM_HUB_P2P_BOOTSTRAP", "/dns4/hub-b/tcp/4001"),
            ("GIM_HUB_FEDERATION_ALLOWLIST", "/config/allowlist"),
            ("GIM_HUB_RUNTIME_CERT_DAYS", "2"),
            ("GIM_HUB_S2S_TIMEOUT_SECONDS", "3"),
            ("GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS", "5"),
            ("GIM_HUB_PUSH_FAILOVER_SECONDS", "2"),
            ("GIM_HUB_FETCH_BLOB_PER_MINUTE", "7"),
        ])
        .unwrap();
        assert_eq!(config.listen.len(), 2);
        assert_eq!(config.external_addrs.len(), 1);
        assert_eq!(config.bootstrap.len(), 1);
        assert_eq!(config.allowlist_path, PathBuf::from("/config/allowlist"));
        assert_eq!(config.runtime_cert_days, 2);
        assert_eq!(config.s2s_timeout, Duration::from_secs(3));
        assert_eq!(config.outbox_backoff_max_seconds, 5);
        assert_eq!(config.push_failover_seconds, 2);
        assert_eq!(config.fetch_blob_per_minute, 7);
    }

    #[test]
    fn invalid_values_name_the_variable() {
        let cases: &[(&str, &str)] = &[
            ("GIM_HUB_FEDERATION", "yes"),
            ("GIM_HUB_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001,not-an-addr"),
            ("GIM_HUB_P2P_EXTERNAL_ADDRS", "tcp/4001"),
            ("GIM_HUB_P2P_BOOTSTRAP", "/ip4/1.2.3.4/tcp/x"),
            ("GIM_HUB_RUNTIME_CERT_DAYS", "1"),
            ("GIM_HUB_S2S_TIMEOUT_SECONDS", "0"),
            ("GIM_HUB_DHT_REPUBLISH_HOURS", "-1"),
            ("GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER", "big"),
            ("GIM_HUB_PUSH_FAILOVER_SECONDS", "0"),
            ("GIM_HUB_FETCH_BLOB_PER_MINUTE", "0"),
            ("GIM_HUB_P2P_PSK_FILE", "/nonexistent/swarm.key"),
        ];
        for (name, value) in cases {
            let mut pairs = vec![("GIM_HUB_FEDERATION", "true")];
            if *name != "GIM_HUB_FEDERATION" {
                pairs.push((name, value));
            } else {
                pairs[0].1 = value;
            }
            let err = load(&pairs).unwrap_err();
            assert_eq!(err.name, *name, "{err}");
        }
    }

    #[test]
    fn psk_forces_tcp_only() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("swarm.key");
        std::fs::write(&key, KEY).unwrap();
        let key = key.display().to_string();

        let err = load(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_PSK_FILE", &key),
        ])
        .unwrap_err();
        assert_eq!(err.name, "GIM_HUB_P2P_LISTEN");
        assert!(err.reason.contains("QUIC"));

        let err = load(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_PSK_FILE", &key),
            ("GIM_HUB_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
            ("GIM_HUB_P2P_BOOTSTRAP", "/ip4/10.0.0.2/udp/4001/quic-v1"),
        ])
        .unwrap_err();
        assert_eq!(err.name, "GIM_HUB_P2P_BOOTSTRAP");

        let config = load(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_PSK_FILE", &key),
            ("GIM_HUB_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
        ])
        .unwrap();
        let expected: Psk = std::array::from_fn(|i| i as u8);
        assert_eq!(config.psk, Some(expected));
    }

    #[test]
    fn psk_from_the_variable() {
        let config = load(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_PSK", KEY),
            ("GIM_HUB_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
        ])
        .unwrap();
        let expected: Psk = std::array::from_fn(|i| i as u8);
        assert_eq!(config.psk, Some(expected));
        let err = load(&[("GIM_HUB_FEDERATION", "true"), ("GIM_HUB_P2P_PSK", KEY)]).unwrap_err();
        assert_eq!(err.name, "GIM_HUB_P2P_LISTEN");
        let bad = KEY.replace("0001", "zz01");
        let err = load(&[("GIM_HUB_FEDERATION", "true"), ("GIM_HUB_P2P_PSK", &bad)]).unwrap_err();
        assert_eq!(err.name, "GIM_HUB_P2P_PSK");
        assert!(!err.to_string().contains("zz01"), "{err}");

        // The file wins over the variable.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("swarm.key");
        std::fs::write(&file, KEY.replace("1e1f", "1e20")).unwrap();
        let config = load(&[
            ("GIM_HUB_FEDERATION", "true"),
            ("GIM_HUB_P2P_PSK", KEY),
            ("GIM_HUB_P2P_PSK_FILE", file.to_str().unwrap()),
            ("GIM_HUB_P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001"),
        ])
        .unwrap();
        assert_eq!(config.psk.unwrap()[31], 0x20);
    }

    #[test]
    fn swarm_key_format() {
        assert!(parse_swarm_key(KEY).is_ok());
        assert!(parse_swarm_key(&KEY.replace("\n", "\r\n")).is_ok());
        for bad in [
            "",
            "/key/swarm/psk/1.0.0/\n/base64/\nAAAA\n",
            "/key/swarm/psk/1.0.0/\n/base16/\n0001\n",
            "/key/swarm/psk/1.0.0/\n/base16/\nzz02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
            "/key/swarm/psk/1.0.0/\n/base16/\n",
            &format!("{KEY}extra\n"),
        ] {
            assert!(parse_swarm_key(bad).is_err(), "{bad:?}");
        }
    }
}
