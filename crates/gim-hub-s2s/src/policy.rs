//! Federation policy (docs/federation.md §3.3, §3.6, §6.8).
//!
//! [`FederationPolicy`] holds every admission decision of the federation
//! layer. [`AllowlistPolicy`] is the closed-federation implementation: an
//! operator-maintained file of allowed `hub_id`s (with optional static
//! multiaddrs) plus an optional pnet PSK.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

use gim_hub_identity::HubId;
use gim_hub_proto::s2s::s2s_request::Op;

use crate::config::Psk;
use crate::transport::{self, Multiaddr};

/// Outcome of an admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(&'static str),
    RateLimited { retry_after_ms: u64 },
}

/// S2S operation kinds, one per `S2sRequest.op` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpKind {
    Hello,
    SubmitCommit,
    SubmitMessage,
    Deliver,
    DeliverWelcome,
    ClaimKeyPackage,
    FetchLog,
    GetDeviceList,
    GetHostingRecord,
    NotifyDeviceList,
}

impl OpKind {
    pub fn of(op: &Op) -> Self {
        match op {
            Op::Hello(_) => Self::Hello,
            Op::SubmitCommit(_) => Self::SubmitCommit,
            Op::SubmitMessage(_) => Self::SubmitMessage,
            Op::Deliver(_) => Self::Deliver,
            Op::DeliverWelcome(_) => Self::DeliverWelcome,
            Op::ClaimKeyPackage(_) => Self::ClaimKeyPackage,
            Op::FetchLog(_) => Self::FetchLog,
            Op::GetDeviceList(_) => Self::GetDeviceList,
            Op::GetHostingRecord(_) => Self::GetHostingRecord,
            Op::NotifyDeviceList(_) => Self::NotifyDeviceList,
        }
    }
}

/// Admission decisions of the federation layer. These are the only places
/// the policy is consulted, so an open-federation policy needs no protocol
/// change (§3.6).
pub trait FederationPolicy: Send + Sync + 'static {
    /// PSK for libp2p pnet; `Some` forces TCP-only transport.
    fn psk(&self) -> Option<Psk>;
    /// Hub-level admission after the runtime certificate verified (Hello,
    /// step 4).
    fn allow_hub(&self, hub_id: &HubId) -> Decision;
    /// Per-request admission for a bound hub, before the op handler runs.
    fn admit(&self, hub_id: &HubId, op: OpKind) -> Decision;
    /// Whether this hub may dial / send to `hub_id` at all.
    fn may_contact(&self, hub_id: &HubId) -> bool;
    /// Static addresses known for a hub (allowlist).
    fn static_addrs(&self, hub_id: &HubId) -> Vec<Multiaddr>;
    /// Hubs to dial at bootstrap when they have static addresses.
    fn known_hubs(&self) -> Vec<HubId> {
        Vec::new()
    }
}

/// Allowlist file errors.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read allowlist {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("allowlist line {line}: {reason}")]
    Invalid { line: usize, reason: String },
    #[error("allowlist {0} lists no other hub")]
    Empty(PathBuf),
}

/// Parsed allowlist: allowed hubs and their static addresses.
pub type Allowlist = HashMap<HubId, Vec<Multiaddr>>;

/// Rate limits per caller hub (§6.8): (requests, per window).
const CLAIM_LIMIT: u32 = 600;
const LOOKUP_LIMIT: u32 = 600;
const LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Closed-federation policy backed by an allowlist file, reloaded on SIGHUP.
pub struct AllowlistPolicy {
    path: PathBuf,
    own_hub_id: HubId,
    psk: Option<Psk>,
    hubs: RwLock<Allowlist>,
    buckets: Mutex<HashMap<(HubId, Bucket), TokenBucket>>,
}

impl std::fmt::Debug for AllowlistPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowlistPolicy")
            .field("path", &self.path)
            .field("hubs", &self.hubs.read().expect("allowlist lock").len())
            .field("psk", &self.psk.is_some())
            .finish_non_exhaustive()
    }
}

impl AllowlistPolicy {
    /// Loads the allowlist at `path`. A missing, invalid or empty allowlist
    /// is an error (federation does not start).
    pub fn load(path: &Path, own_hub_id: &HubId, psk: Option<Psk>) -> Result<Self, PolicyError> {
        let hubs = read_allowlist(path, own_hub_id, psk.is_some())?;
        Ok(Self {
            path: path.to_owned(),
            own_hub_id: own_hub_id.clone(),
            psk,
            hubs: RwLock::new(hubs),
            buckets: Mutex::default(),
        })
    }

    /// Re-reads the allowlist file. On error the previous allowlist stays in
    /// force.
    pub fn reload(&self) -> Result<(), PolicyError> {
        let hubs = read_allowlist(&self.path, &self.own_hub_id, self.psk.is_some())?;
        *self.hubs.write().expect("allowlist lock") = hubs;
        Ok(())
    }

    /// The allowed hubs.
    pub fn hub_ids(&self) -> Vec<HubId> {
        let mut ids: Vec<_> = self
            .hubs
            .read()
            .expect("allowlist lock")
            .keys()
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    fn listed(&self, hub_id: &HubId) -> bool {
        self.hubs
            .read()
            .expect("allowlist lock")
            .contains_key(hub_id)
    }

    /// [`FederationPolicy::admit`] evaluated at an explicit `now`.
    fn admit_at(&self, hub_id: &HubId, op: OpKind, now: Instant) -> Decision {
        if !self.listed(hub_id) {
            return Decision::Deny("hub not allowlisted");
        }
        let (bucket, limit) = match op {
            OpKind::ClaimKeyPackage => (Bucket::Claim, CLAIM_LIMIT),
            OpKind::GetDeviceList | OpKind::GetHostingRecord => (Bucket::Lookup, LOOKUP_LIMIT),
            _ => return Decision::Allow,
        };
        self.buckets
            .lock()
            .expect("rate limit lock")
            .entry((hub_id.clone(), bucket))
            .or_insert_with(|| TokenBucket::new(limit, now))
            .take(now)
    }
}

impl FederationPolicy for AllowlistPolicy {
    fn psk(&self) -> Option<Psk> {
        self.psk
    }

    fn allow_hub(&self, hub_id: &HubId) -> Decision {
        if self.listed(hub_id) {
            Decision::Allow
        } else {
            Decision::Deny("hub not allowlisted")
        }
    }

    fn admit(&self, hub_id: &HubId, op: OpKind) -> Decision {
        self.admit_at(hub_id, op, Instant::now())
    }

    fn may_contact(&self, hub_id: &HubId) -> bool {
        self.listed(hub_id)
    }

    fn static_addrs(&self, hub_id: &HubId) -> Vec<Multiaddr> {
        self.hubs
            .read()
            .expect("allowlist lock")
            .get(hub_id)
            .cloned()
            .unwrap_or_default()
    }

    fn known_hubs(&self) -> Vec<HubId> {
        self.hub_ids()
    }
}

fn read_allowlist(path: &Path, own_hub_id: &HubId, psk: bool) -> Result<Allowlist, PolicyError> {
    let text = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
        path: path.to_owned(),
        source,
    })?;
    let hubs = parse_allowlist(&text, own_hub_id, psk)?;
    if hubs.is_empty() {
        return Err(PolicyError::Empty(path.to_owned()));
    }
    Ok(hubs)
}

/// Parses allowlist text: one `hub_id [multiaddr ...]` per line, `#` starts
/// a comment. Multiaddrs must not carry `/p2p/`; with a PSK they must not be
/// QUIC. The own `hub_id` is ignored.
pub fn parse_allowlist(
    text: &str,
    own_hub_id: &HubId,
    psk: bool,
) -> Result<Allowlist, PolicyError> {
    let mut hubs = Allowlist::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let invalid = |reason: String| PolicyError::Invalid { line, reason };
        let content = raw.split('#').next().unwrap_or_default();
        let mut fields = content.split_whitespace();
        let Some(hub) = fields.next() else {
            continue;
        };
        let hub_id = HubId::parse(hub).map_err(|err| invalid(err.to_string()))?;
        let mut addrs = Vec::new();
        for field in fields {
            let addr: Multiaddr = field
                .parse()
                .map_err(|err| invalid(format!("{field:?}: {err}")))?;
            if transport::has_peer_id(&addr) {
                return Err(invalid(format!("{field:?}: must not contain /p2p/")));
            }
            if psk && transport::is_quic(&addr) {
                return Err(invalid(format!(
                    "{field:?}: QUIC is not available with a PSK (TCP only)"
                )));
            }
            addrs.push(addr);
        }
        if hub_id == *own_hub_id {
            continue;
        }
        hubs.entry(hub_id).or_default().extend(addrs);
    }
    Ok(hubs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Bucket {
    Claim,
    Lookup,
}

/// Token bucket refilling `capacity` tokens per [`LIMIT_WINDOW`].
#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, now: Instant) -> Self {
        Self {
            capacity: f64::from(capacity),
            tokens: f64::from(capacity),
            updated: now,
        }
    }

    fn take(&mut self, now: Instant) -> Decision {
        let rate = self.capacity / LIMIT_WINDOW.as_secs_f64();
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(self.capacity);
        self.updated = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Decision::Allow
        } else {
            let wait = (1.0 - self.tokens) / rate;
            Decision::RateLimited {
                retry_after_ms: (wait * 1000.0).ceil() as u64,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use gim_hub_identity::SigningKey;

    use super::*;

    fn hub(seed: u8) -> HubId {
        HubId::from_root_pubkey(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    #[test]
    fn parses_hubs_addresses_and_comments() {
        let (own, a, b) = (hub(1), hub(2), hub(3));
        let text = format!(
            "# allowlist\n\n{a}  /dns4/hub-a/tcp/4001 /dns4/hub-a/udp/4001/quic-v1\n\
             {b} # address learned from the DHT\n{own} /ip4/127.0.0.1/tcp/1\n"
        );
        let hubs = parse_allowlist(&text, &own, false).unwrap();
        assert_eq!(hubs.len(), 2);
        assert_eq!(hubs[&a].len(), 2);
        assert!(hubs[&b].is_empty());
        assert!(!hubs.contains_key(&own));
    }

    #[test]
    fn rejects_invalid_lines() {
        let own = hub(1);
        let a = hub(2);
        for (text, line) in [
            ("hnotahubid\n".to_owned(), 1),
            (format!("\n{a} /ip4/1.2.3.4/tcp/x\n"), 2),
            (format!("{a} /ip4/1.2.3.4/tcp/1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA\n"), 1),
        ] {
            match parse_allowlist(&text, &own, false) {
                Err(PolicyError::Invalid { line: got, .. }) => assert_eq!(got, line, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
        let quic = format!("{a} /ip4/1.2.3.4/udp/4001/quic-v1\n");
        assert!(parse_allowlist(&quic, &own, false).is_ok());
        assert!(matches!(
            parse_allowlist(&quic, &own, true),
            Err(PolicyError::Invalid { line: 1, .. })
        ));
    }

    #[test]
    fn load_requires_a_non_empty_allowlist_and_reload_keeps_previous_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist");
        let own = hub(1);
        assert!(matches!(
            AllowlistPolicy::load(&path, &own, None),
            Err(PolicyError::Read { .. })
        ));
        std::fs::write(&path, format!("# nothing\n{own}\n")).unwrap();
        assert!(matches!(
            AllowlistPolicy::load(&path, &own, None),
            Err(PolicyError::Empty(_))
        ));

        std::fs::write(&path, format!("{} /ip4/127.0.0.1/tcp/4001\n", hub(2))).unwrap();
        let policy = AllowlistPolicy::load(&path, &own, None).unwrap();
        assert_eq!(policy.allow_hub(&hub(2)), Decision::Allow);
        assert_eq!(
            policy.allow_hub(&hub(3)),
            Decision::Deny("hub not allowlisted")
        );
        assert!(policy.may_contact(&hub(2)));
        assert!(!policy.may_contact(&hub(3)));
        assert_eq!(policy.static_addrs(&hub(2)).len(), 1);

        std::fs::write(&path, "garbage\n").unwrap();
        assert!(policy.reload().is_err());
        assert!(policy.may_contact(&hub(2)));

        std::fs::write(&path, format!("{}\n", hub(3))).unwrap();
        policy.reload().unwrap();
        assert!(!policy.may_contact(&hub(2)));
        assert!(policy.may_contact(&hub(3)));
        assert!(policy.static_addrs(&hub(3)).is_empty());
        assert_eq!(policy.hub_ids(), vec![hub(3)]);
    }

    #[test]
    fn admit_rate_limits_claims_and_lookups_per_caller() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist");
        std::fs::write(&path, format!("{}\n{}\n", hub(2), hub(3))).unwrap();
        let policy = AllowlistPolicy::load(&path, &hub(1), None).unwrap();
        let now = Instant::now();
        for _ in 0..CLAIM_LIMIT {
            assert_eq!(
                policy.admit_at(&hub(2), OpKind::ClaimKeyPackage, now),
                Decision::Allow
            );
        }
        assert_eq!(
            policy.admit_at(&hub(2), OpKind::ClaimKeyPackage, now),
            Decision::RateLimited {
                retry_after_ms: 100
            }
        );
        // Other buckets, ops and callers are unaffected.
        assert_eq!(
            policy.admit_at(&hub(2), OpKind::GetDeviceList, now),
            Decision::Allow
        );
        assert_eq!(
            policy.admit_at(&hub(2), OpKind::Deliver, now),
            Decision::Allow
        );
        assert_eq!(
            policy.admit_at(&hub(3), OpKind::ClaimKeyPackage, now),
            Decision::Allow
        );
        assert_eq!(
            policy.admit_at(&hub(4), OpKind::Deliver, now),
            Decision::Deny("hub not allowlisted")
        );
        // The exhausted bucket refills one token after `retry_after_ms`.
        assert_eq!(
            policy.admit_at(
                &hub(2),
                OpKind::ClaimKeyPackage,
                now + Duration::from_millis(100)
            ),
            Decision::Allow
        );
        // The trait entry point still applies the allowlist.
        assert_eq!(
            policy.admit(&hub(4), OpKind::Deliver),
            Decision::Deny("hub not allowlisted")
        );
    }

    #[test]
    fn token_bucket_refills() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(60, start);
        for _ in 0..60 {
            assert_eq!(bucket.take(start), Decision::Allow);
        }
        assert_eq!(
            bucket.take(start),
            Decision::RateLimited {
                retry_after_ms: 1000
            }
        );
        assert_eq!(bucket.take(start + Duration::from_secs(1)), Decision::Allow);
    }
}
