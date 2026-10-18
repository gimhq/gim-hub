//! In-memory token-bucket rate limits for the unauthenticated public reads
//! (`GET /v2/users/{user_id}` and `GET /v2/users/{user_id}/device-list`)
//! and recovery backup reads (`GET /v2/users/{user_id}/recovery-backup`).

use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, HeaderMap},
};

use crate::{error::ApiError, state::AppState};

const MINUTE_MS: i64 = 60_000;

/// Token buckets of `per_min` requests per minute (burst `per_min`), one per
/// key. Buckets idle for a minute are full again and are dropped lazily.
/// `per_min` can change at runtime ([`RateLimiter::set_per_min`]).
pub struct RateLimiter<K> {
    per_min: AtomicU32,
    inner: Mutex<Buckets<K>>,
}

struct Buckets<K> {
    map: HashMap<K, Bucket>,
    last_prune_ms: i64,
}

/// Tokens are counted in 1/60000ths: a request costs [`MINUTE_MS`] units
/// and a millisecond refills `per_min` units, so the arithmetic is exact.
struct Bucket {
    units: i64,
    updated_ms: i64,
}

impl<K: Hash + Eq> RateLimiter<K> {
    /// A limiter allowing `per_min` requests per minute per key (at least 1).
    pub fn new(per_min: u32) -> Self {
        Self {
            per_min: AtomicU32::new(per_min.max(1)),
            inner: Mutex::new(Buckets {
                map: HashMap::new(),
                last_prune_ms: i64::MIN,
            }),
        }
    }

    /// Changes the allowed requests per minute (at least 1); existing
    /// buckets refill at the new rate up to the new burst.
    pub fn set_per_min(&self, per_min: u32) {
        self.per_min.store(per_min.max(1), Ordering::Relaxed);
    }

    /// Takes one token for `key` at `now_ms` (ms since the Unix epoch), or
    /// returns the seconds (at least 1) until a token is available.
    pub fn check_at(&self, key: K, now_ms: i64) -> Result<(), u64> {
        let per_min_u32 = self.per_min.load(Ordering::Relaxed);
        let per_min = i64::from(per_min_u32);
        let capacity = per_min * MINUTE_MS;
        let mut inner = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        if now_ms.saturating_sub(inner.last_prune_ms) >= MINUTE_MS {
            inner
                .map
                .retain(|_, bucket| now_ms.saturating_sub(bucket.updated_ms) < MINUTE_MS);
            inner.last_prune_ms = now_ms;
        }
        let bucket = inner.map.entry(key).or_insert(Bucket {
            units: capacity,
            updated_ms: now_ms,
        });
        // A clock that goes backwards refills nothing.
        let elapsed = now_ms.saturating_sub(bucket.updated_ms).max(0);
        bucket.units = bucket
            .units
            .saturating_add(elapsed.saturating_mul(per_min))
            .min(capacity);
        bucket.updated_ms = bucket.updated_ms.max(now_ms);
        if bucket.units >= MINUTE_MS {
            bucket.units -= MINUTE_MS;
            return Ok(());
        }
        let missing = u64::try_from(MINUTE_MS - bucket.units).unwrap_or(0);
        let wait_ms = missing.div_ceil(u64::from(per_min_u32));
        Err(wait_ms.div_ceil(1000).max(1))
    }
}

/// Limits shared by the public user reads: per client IP, then per target
/// user ID.
#[derive(Clone)]
pub struct PublicReadLimits {
    per_ip: Arc<RateLimiter<IpAddr>>,
    per_user: Arc<RateLimiter<String>>,
    trust_forwarded_for: Arc<AtomicBool>,
}

impl PublicReadLimits {
    /// Limits of `per_ip` and `per_user` requests per minute; with
    /// `trust_forwarded_for` the client IP is the left-most
    /// `X-Forwarded-For` address.
    pub fn new(per_ip: u32, per_user: u32, trust_forwarded_for: bool) -> Self {
        Self {
            per_ip: Arc::new(RateLimiter::new(per_ip)),
            per_user: Arc::new(RateLimiter::new(per_user)),
            trust_forwarded_for: Arc::new(AtomicBool::new(trust_forwarded_for)),
        }
    }

    /// Applies changed limits at once, to every clone.
    pub fn reconfigure(&self, per_ip: u32, per_user: u32, trust_forwarded_for: bool) {
        self.per_ip.set_per_min(per_ip);
        self.per_user.set_per_min(per_user);
        self.trust_forwarded_for
            .store(trust_forwarded_for, Ordering::Relaxed);
    }

    /// Whether the client IP is the left-most `X-Forwarded-For` address.
    pub fn trust_forwarded_for(&self) -> bool {
        self.trust_forwarded_for.load(Ordering::Relaxed)
    }

    /// Checks the per-IP limit, then the per-user limit; 429
    /// `rate_limited` over either.
    pub fn check(&self, client: ClientIp, user_id: &str, now_ms: i64) -> Result<(), ApiError> {
        let limited = |retry_after| ApiError::RateLimited { retry_after };
        self.per_ip.check_at(client.0, now_ms).map_err(limited)?;
        self.per_user
            .check_at(user_id.to_owned(), now_ms)
            .map_err(limited)
    }
}

/// Rate-limit key of the calling client: its IP address, IPv6 truncated to
/// the /64. Without a known peer address (in-process router tests) all
/// requests share one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    fn resolve(peer: Option<SocketAddr>, headers: &HeaderMap, trust_forwarded_for: bool) -> Self {
        let forwarded = trust_forwarded_for
            .then(|| headers.get("x-forwarded-for")?.to_str().ok())
            .flatten()
            .and_then(|value| value.split(',').next()?.trim().parse::<IpAddr>().ok());
        let ip = forwarded
            .or(peer.map(|addr| addr.ip()))
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Self(match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from_bits(v6.to_bits() & !((1u128 << 64) - 1))),
            v4 => v4,
        })
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        Ok(Self::resolve(
            peer,
            &parts.headers,
            state.public_reads.trust_forwarded_for(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    const T0: i64 = 1_760_479_200_000;

    #[test]
    fn bucket_allows_a_burst_then_refills() {
        let limiter = RateLimiter::new(2);
        assert_eq!(limiter.check_at("a", T0), Ok(()));
        assert_eq!(limiter.check_at("a", T0), Ok(()));
        // One token refills every 30 s.
        assert_eq!(limiter.check_at("a", T0), Err(30));
        assert_eq!(limiter.check_at("a", T0 + 29_500), Err(1));
        assert_eq!(limiter.check_at("b", T0), Ok(()));
        assert_eq!(limiter.check_at("a", T0 + 30_000), Ok(()));
        assert_eq!(limiter.check_at("a", T0 + 30_000), Err(30));
        // Never more than the burst.
        assert_eq!(limiter.check_at("a", T0 + 10 * MINUTE_MS), Ok(()));
        assert_eq!(limiter.check_at("a", T0 + 10 * MINUTE_MS), Ok(()));
        assert!(limiter.check_at("a", T0 + 10 * MINUTE_MS).is_err());
    }

    #[test]
    fn a_new_rate_applies_to_existing_buckets() {
        let limiter = RateLimiter::new(1);
        assert_eq!(limiter.check_at("a", T0), Ok(()));
        assert_eq!(limiter.check_at("a", T0), Err(60));
        limiter.set_per_min(2);
        // One token refills every 30 s now.
        assert_eq!(limiter.check_at("a", T0), Err(30));
        assert_eq!(limiter.check_at("a", T0 + 30_000), Ok(()));
        let limits = PublicReadLimits::new(1, 1, false);
        let copy = limits.clone();
        limits.reconfigure(5, 6, true);
        assert!(copy.trust_forwarded_for());
        assert_eq!(copy.per_ip.per_min.load(Ordering::Relaxed), 5);
        assert_eq!(copy.per_user.per_min.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        let limiter = RateLimiter::new(6000);
        for _ in 0..6000 {
            limiter.check_at((), T0).unwrap();
        }
        assert_eq!(limiter.check_at((), T0), Err(1));
    }

    #[test]
    fn backwards_clock_refills_nothing() {
        let limiter = RateLimiter::new(1);
        limiter.check_at((), T0).unwrap();
        assert!(limiter.check_at((), T0 - MINUTE_MS).is_err());
        assert!(limiter.check_at((), T0 + 59_000).is_err());
        assert_eq!(limiter.check_at((), T0 + MINUTE_MS), Ok(()));
    }

    #[test]
    fn idle_buckets_are_pruned() {
        let limiter = RateLimiter::new(1);
        limiter.check_at(1, T0).unwrap();
        limiter.check_at(2, T0 + 30_000).unwrap();
        assert_eq!(limiter.inner.lock().unwrap().map.len(), 2);
        limiter.check_at(3, T0 + 70_000).unwrap();
        let keys: Vec<i32> = {
            let inner = limiter.inner.lock().unwrap();
            let mut keys: Vec<_> = inner.map.keys().copied().collect();
            keys.sort();
            keys
        };
        assert_eq!(keys, [2, 3]);
    }

    fn resolve(peer: Option<&str>, forwarded: Option<&str>, trust: bool) -> IpAddr {
        let mut headers = HeaderMap::new();
        if let Some(value) = forwarded {
            headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        }
        ClientIp::resolve(peer.map(|addr| addr.parse().unwrap()), &headers, trust).0
    }

    #[test]
    fn client_ip_from_peer_or_forwarded_for() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(resolve(None, None, false), ip("0.0.0.0"));
        assert_eq!(
            resolve(Some("203.0.113.7:4000"), None, false),
            ip("203.0.113.7")
        );
        assert_eq!(
            resolve(Some("[2001:db8:1:2:3:4:5:6]:443"), None, false),
            ip("2001:db8:1:2::")
        );
        assert_eq!(
            resolve(Some("[::ffff:203.0.113.7]:443"), None, false),
            ip("203.0.113.7")
        );
        // X-Forwarded-For only when trusted, left-most entry.
        let forwarded = Some("198.51.100.1, 10.0.0.1");
        assert_eq!(
            resolve(Some("10.0.0.1:1"), forwarded, false),
            ip("10.0.0.1")
        );
        assert_eq!(
            resolve(Some("10.0.0.1:1"), forwarded, true),
            ip("198.51.100.1")
        );
        assert_eq!(
            resolve(Some("10.0.0.1:1"), Some(" 2001:db8::9 "), true),
            ip("2001:db8::")
        );
        assert_eq!(
            resolve(Some("10.0.0.1:1"), Some("garbage"), true),
            ip("10.0.0.1")
        );
    }
}
