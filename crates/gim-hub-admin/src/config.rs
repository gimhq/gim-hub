//! Admin configuration from `GIM_HUB_ADMIN_*` environment variables
//! (docs/admin.md). Empty variables count as unset. While
//! `GIM_HUB_ADMIN_LISTEN` is unset the admin API is disabled and the other
//! variables are ignored.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use axum::http::HeaderName;
use gim_hub_api::config::ConfigError;
use sha2::{Digest, Sha256};

/// Shortest accepted admin token, in characters.
pub const MIN_TOKEN_LEN: usize = 32;

/// Admin configuration.
#[derive(Clone, Default)]
pub struct AdminConfig {
    /// `GIM_HUB_ADMIN_LISTEN`: socket address of the admin listener; `None`
    /// disables the admin API.
    pub listen: Option<SocketAddr>,
    /// `GIM_HUB_ADMIN_TOKEN_FILE`: file holding the admin token.
    pub token_file: Option<PathBuf>,
    /// SHA-256 of the trimmed token; the token itself is not kept.
    token_hash: Option<[u8; 32]>,
    /// `GIM_HUB_ADMIN_TRUSTED_HEADER`: identity header set by a trusted
    /// reverse proxy.
    pub trusted_header: Option<HeaderName>,
    /// `GIM_HUB_ADMIN_TRUSTED_PROXIES`: peers whose `X-Forwarded-For` and
    /// identity header are trusted.
    pub trusted_proxies: Vec<Cidr>,
    /// `GIM_HUB_ADMIN_COOKIE_SECURE`: set `Secure` on the session cookie.
    pub cookie_secure: bool,
}

impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("listen", &self.listen)
            .field("token_file", &self.token_file)
            .field("trusted_header", &self.trusted_header)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("cookie_secure", &self.cookie_secure)
            .finish_non_exhaustive()
    }
}

impl AdminConfig {
    /// Reads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(std::env::vars())
    }

    /// Reads the configuration from `(name, value)` pairs. With a listen
    /// address, the token file is read and at least one of the token file
    /// and the trusted header is required; the trusted header requires
    /// trusted proxies.
    pub fn from_vars(
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let vars: HashMap<String, String> = vars
            .into_iter()
            .filter(|(name, value)| name.starts_with("GIM_HUB_ADMIN_") && !value.is_empty())
            .collect();
        let get = |name: &str| vars.get(name).map(String::as_str);
        let invalid = |name: &'static str, value: &str, reason: &str| ConfigError {
            name,
            value: value.to_owned(),
            reason: reason.to_owned(),
        };

        let Some(listen_raw) = get("GIM_HUB_ADMIN_LISTEN") else {
            return Ok(Self::default());
        };
        let listen: SocketAddr =
            listen_raw
                .trim()
                .parse()
                .map_err(|err: std::net::AddrParseError| {
                    invalid("GIM_HUB_ADMIN_LISTEN", listen_raw, &err.to_string())
                })?;

        let token_file = get("GIM_HUB_ADMIN_TOKEN_FILE").map(PathBuf::from);
        let token_hash = match &token_file {
            None => None,
            Some(path) => {
                let raw = path.display().to_string();
                let text = std::fs::read_to_string(path)
                    .map_err(|err| invalid("GIM_HUB_ADMIN_TOKEN_FILE", &raw, &err.to_string()))?;
                let token = text.trim();
                if token.chars().count() < MIN_TOKEN_LEN {
                    return Err(invalid(
                        "GIM_HUB_ADMIN_TOKEN_FILE",
                        &raw,
                        &format!("the token must be at least {MIN_TOKEN_LEN} characters"),
                    ));
                }
                Some(token_hash(token))
            }
        };

        let trusted_header = get("GIM_HUB_ADMIN_TRUSTED_HEADER")
            .map(|raw| {
                HeaderName::from_bytes(raw.trim().as_bytes()).map_err(|_| {
                    invalid(
                        "GIM_HUB_ADMIN_TRUSTED_HEADER",
                        raw,
                        "not a valid header name",
                    )
                })
            })
            .transpose()?;
        let trusted_proxies = match get("GIM_HUB_ADMIN_TRUSTED_PROXIES") {
            None => Vec::new(),
            Some(raw) => raw
                .split(',')
                .map(str::trim)
                .filter(|cidr| !cidr.is_empty())
                .map(|cidr| {
                    cidr.parse().map_err(|reason: String| {
                        invalid("GIM_HUB_ADMIN_TRUSTED_PROXIES", raw, &reason)
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        if trusted_header.is_some() && trusted_proxies.is_empty() {
            return Err(invalid(
                "GIM_HUB_ADMIN_TRUSTED_PROXIES",
                "",
                "required when GIM_HUB_ADMIN_TRUSTED_HEADER is set",
            ));
        }
        if token_hash.is_none() && trusted_header.is_none() {
            return Err(invalid(
                "GIM_HUB_ADMIN_LISTEN",
                listen_raw,
                "needs GIM_HUB_ADMIN_TOKEN_FILE or GIM_HUB_ADMIN_TRUSTED_HEADER",
            ));
        }
        let cookie_secure = match get("GIM_HUB_ADMIN_COOKIE_SECURE").map(str::trim) {
            None | Some("false") => false,
            Some("true") => true,
            Some(other) => {
                return Err(invalid(
                    "GIM_HUB_ADMIN_COOKIE_SECURE",
                    other,
                    "expected true or false",
                ))
            }
        };
        Ok(Self {
            listen: Some(listen),
            token_file,
            token_hash,
            trusted_header,
            trusted_proxies,
            cookie_secure,
        })
    }

    /// Whether the admin listener is configured.
    pub fn enabled(&self) -> bool {
        self.listen.is_some()
    }

    /// Whether token login is enabled.
    pub fn token_login(&self) -> bool {
        self.token_hash.is_some()
    }

    /// Whether `token` (trimmed) is the admin token, compared in constant
    /// time over the SHA-256 digests.
    pub fn token_matches(&self, token: &str) -> bool {
        let Some(expected) = &self.token_hash else {
            return false;
        };
        constant_time_eq(expected, &token_hash(token.trim()))
    }

    /// Whether `ip` is in a trusted proxy range.
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted_proxies.iter().any(|cidr| cidr.contains(ip))
    }
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Byte-wise equality whose time does not depend on where the inputs differ.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// An IP network: an address and a prefix length (a bare address is a
/// single host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Whether `ip` is in the network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                net.to_bits() & mask == ip.to_bits() & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, String> {
        let (addr, prefix) = match raw.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (raw, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("{raw:?} is not an IP address or CIDR"))?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= max)
                .ok_or_else(|| format!("{raw:?} has an invalid prefix length"))?,
        };
        Ok(Self { addr, prefix })
    }
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

    fn config(pairs: &[(&str, &str)]) -> AdminConfig {
        AdminConfig::from_vars(vars(pairs)).unwrap()
    }

    fn token_file(dir: &tempfile::TempDir, token: &str) -> String {
        let path = dir.path().join("admin.token");
        std::fs::write(&path, token).unwrap();
        path.display().to_string()
    }

    #[test]
    fn disabled_by_default_and_ignores_the_rest() {
        let config = config(&[("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-User")]);
        assert!(!config.enabled());
        assert!(!config.token_login());
        assert!(
            !AdminConfig::from_vars(vars(&[("GIM_HUB_ADMIN_LISTEN", "")]))
                .unwrap()
                .enabled()
        );
    }

    #[test]
    fn token_file_is_hashed_and_compared() {
        let dir = tempfile::tempdir().unwrap();
        let token = "a".repeat(64);
        let path = token_file(&dir, &format!("{token}\n"));
        let config = config(&[
            ("GIM_HUB_ADMIN_LISTEN", "127.0.0.1:8081"),
            ("GIM_HUB_ADMIN_TOKEN_FILE", &path),
        ]);
        assert_eq!(config.listen, Some("127.0.0.1:8081".parse().unwrap()));
        assert!(config.token_login());
        assert!(config.token_matches(&token));
        assert!(config.token_matches(&format!(" {token} ")));
        assert!(!config.token_matches(&"b".repeat(64)));
        assert!(!config.cookie_secure);
        assert!(!format!("{config:?}").contains(&token));
    }

    #[test]
    fn startup_validation() {
        let dir = tempfile::tempdir().unwrap();
        let short = token_file(&dir, "short-token");
        let err = |pairs: &[(&str, &str)]| AdminConfig::from_vars(vars(pairs)).unwrap_err();
        let listen = ("GIM_HUB_ADMIN_LISTEN", "127.0.0.1:8081");

        let e = err(&[listen]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_LISTEN");
        let e = err(&[listen, ("GIM_HUB_ADMIN_TOKEN_FILE", &short)]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_TOKEN_FILE");
        assert!(!e.to_string().contains("short-token"));
        let e = err(&[listen, ("GIM_HUB_ADMIN_TOKEN_FILE", "/nonexistent/token")]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_TOKEN_FILE");
        let e = err(&[listen, ("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-Forwarded-User")]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_TRUSTED_PROXIES");
        let e = err(&[
            listen,
            ("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-Forwarded-User"),
            ("GIM_HUB_ADMIN_TRUSTED_PROXIES", "10.0.0.0/33"),
        ]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_TRUSTED_PROXIES");
        let e = err(&[
            listen,
            ("GIM_HUB_ADMIN_TRUSTED_HEADER", "bad header"),
            ("GIM_HUB_ADMIN_TRUSTED_PROXIES", "10.0.0.0/8"),
        ]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_TRUSTED_HEADER");
        assert_eq!(
            err(&[("GIM_HUB_ADMIN_LISTEN", "nowhere")]).name,
            "GIM_HUB_ADMIN_LISTEN"
        );

        let config = config(&[
            listen,
            ("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-Forwarded-User"),
            (
                "GIM_HUB_ADMIN_TRUSTED_PROXIES",
                "10.0.0.0/8, 2001:db8::/32,192.0.2.7",
            ),
            ("GIM_HUB_ADMIN_COOKIE_SECURE", "true"),
        ]);
        assert!(!config.token_login());
        assert!(config.cookie_secure);
        assert_eq!(config.trusted_header.unwrap().as_str(), "x-forwarded-user");
        assert_eq!(config.trusted_proxies.len(), 3);
        let e = err(&[
            listen,
            ("GIM_HUB_ADMIN_TRUSTED_HEADER", "X-Forwarded-User"),
            ("GIM_HUB_ADMIN_TRUSTED_PROXIES", "10.0.0.0/8"),
            ("GIM_HUB_ADMIN_COOKIE_SECURE", "yes"),
        ]);
        assert_eq!(e.name, "GIM_HUB_ADMIN_COOKIE_SECURE");
    }

    #[test]
    fn cidr_matching() {
        let cidr = |s: &str| s.parse::<Cidr>().unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(cidr("10.0.0.0/8").contains(ip("10.255.0.1")));
        assert!(!cidr("10.0.0.0/8").contains(ip("11.0.0.1")));
        assert!(cidr("10.0.0.0/8").contains(ip("::ffff:10.0.0.1")));
        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(cidr("192.0.2.7").contains(ip("192.0.2.7")));
        assert!(!cidr("192.0.2.7").contains(ip("192.0.2.8")));
        assert!(cidr("2001:db8::/32").contains(ip("2001:db8:1::1")));
        assert!(!cidr("2001:db8::/32").contains(ip("2001:db9::1")));
        assert!(!cidr("10.0.0.0/8").contains(ip("2001:db8::1")));
        assert!("10.0.0.0/x".parse::<Cidr>().is_err());
        assert!("nope".parse::<Cidr>().is_err());
        assert!("::/129".parse::<Cidr>().is_err());
    }
}
