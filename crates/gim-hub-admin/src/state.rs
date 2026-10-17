//! Admin state: the hub state, the in-memory session table, the login
//! throttle and the audit log writer.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::http::HeaderMap;
use gim_hub_api::AppState;
use gim_hub_db::admin::{self, AuditEntry};
use gim_hub_s2s::{FederationConfig, FederationService};
use sha2::{Digest, Sha256};

use crate::{config::AdminConfig, error::AdminError, lode::Lode};

/// Absolute lifetime of an admin session (no sliding renewal).
pub const SESSION_TTL_MS: i64 = 8 * 60 * 60 * 1000;
/// Failed logins allowed per source IP within [`LOGIN_WINDOW_MS`].
pub const MAX_LOGIN_FAILURES: usize = 5;
const LOGIN_WINDOW_MS: i64 = 60 * 1000;
/// Longest accepted trusted-header identity, in bytes.
const MAX_HEADER_IDENTITY_LEN: usize = 256;

/// How a session was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Token,
    Header,
}

impl AuthKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Header => "header",
        }
    }
}

/// An admin session.
#[derive(Debug, Clone)]
pub struct Session {
    pub actor: String,
    pub auth: AuthKind,
    pub csrf_token: String,
    /// Absolute expiry, ms since the Unix epoch.
    pub expires_at: i64,
}

/// State of the admin API (cheap to clone).
#[derive(Clone)]
pub struct AdminState(Arc<Inner>);

pub struct Inner {
    /// The hub state shared with the client API.
    pub app: AppState,
    pub config: AdminConfig,
    pub federation_config: FederationConfig,
    /// The running federation service, if enabled.
    pub federation: Option<FederationService>,
    /// The lode `state.json` handle, when supervised (`LODE_DIR`).
    pub(crate) lode: Option<Arc<Lode>>,
    /// When the admin state was created (the hub start), ms.
    pub started_at: i64,
    /// Sessions keyed by the SHA-256 of the cookie value.
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// Failed login times per source IP, oldest first.
    login_failures: Mutex<HashMap<IpAddr, VecDeque<i64>>>,
    /// Serializes allowlist writes.
    pub(crate) allowlist_write: tokio::sync::Mutex<()>,
}

impl Deref for AdminState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AdminState {
    /// Admin state over the hub `app`; `lode_dir` is `LODE_DIR` when the
    /// hub runs under lode.
    pub fn new(
        app: AppState,
        config: AdminConfig,
        federation_config: FederationConfig,
        federation: Option<FederationService>,
        lode_dir: Option<PathBuf>,
    ) -> Self {
        let started_at = app.clock.now_ms();
        Self(Arc::new(Inner {
            app,
            config,
            federation_config,
            federation,
            lode: lode_dir.map(|dir| Arc::new(Lode::new(dir, ""))),
            started_at,
            sessions: Mutex::default(),
            login_failures: Mutex::default(),
            allowlist_write: tokio::sync::Mutex::new(()),
        }))
    }

    pub(crate) fn now_ms(&self) -> i64 {
        self.app.clock.now_ms()
    }

    /// Creates a session for `actor`; returns the cookie value and the
    /// session.
    pub(crate) fn create_session(
        &self,
        actor: String,
        auth: AuthKind,
    ) -> Result<(String, Session), AdminError> {
        let cookie = random_hex()?;
        let session = Session {
            actor,
            auth,
            csrf_token: random_hex()?,
            expires_at: self.now_ms() + SESSION_TTL_MS,
        };
        let now = self.now_ms();
        let mut sessions = self.sessions.lock().unwrap_or_else(|err| err.into_inner());
        sessions.retain(|_, session| session.expires_at > now);
        sessions.insert(cookie_key(&cookie), session.clone());
        Ok((cookie, session))
    }

    /// The unexpired session of `cookie`.
    pub(crate) fn session(&self, cookie: &str) -> Option<Session> {
        let now = self.now_ms();
        let mut sessions = self.sessions.lock().unwrap_or_else(|err| err.into_inner());
        let key = cookie_key(cookie);
        match sessions.get(&key) {
            Some(session) if session.expires_at > now => Some(session.clone()),
            Some(_) => {
                sessions.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Ends the session of `cookie`.
    pub(crate) fn remove_session(&self, cookie: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&cookie_key(cookie));
    }

    /// `Err(retry_after)` while `ip` has [`MAX_LOGIN_FAILURES`] failed logins
    /// within the last minute.
    pub(crate) fn login_allowed(&self, ip: IpAddr) -> Result<(), u64> {
        let now = self.now_ms();
        let mut failures = self
            .login_failures
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        failures.retain(|_, times| {
            while times.front().is_some_and(|at| now - at >= LOGIN_WINDOW_MS) {
                times.pop_front();
            }
            !times.is_empty()
        });
        match failures.get(&ip) {
            Some(times) if times.len() >= MAX_LOGIN_FAILURES => {
                let oldest = times.front().copied().unwrap_or(now);
                let wait_ms = u64::try_from(oldest + LOGIN_WINDOW_MS - now).unwrap_or(0);
                Err(wait_ms.div_ceil(1000).max(1))
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn record_login_failure(&self, ip: IpAddr) {
        let now = self.now_ms();
        self.login_failures
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .entry(ip)
            .or_default()
            .push_back(now);
    }

    /// The source IP of a request from `peer`: the left-most
    /// `X-Forwarded-For` address when `peer` is a trusted proxy, else the
    /// peer address.
    pub(crate) fn source_ip(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> IpAddr {
        let peer = peer
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .to_canonical();
        if !self.config.is_trusted_proxy(peer) {
            return peer;
        }
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next()?.trim().parse::<IpAddr>().ok())
            .map_or(peer, |ip| ip.to_canonical())
    }

    /// The `header:<value>` actor of a request carrying the trusted
    /// identity header from a trusted proxy `peer`.
    pub(crate) fn header_identity(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<String> {
        let name = self.config.trusted_header.as_ref()?;
        if !self.config.is_trusted_proxy(peer?) {
            return None;
        }
        let value = headers.get(name)?.to_str().ok()?.trim();
        (!value.is_empty() && value.len() <= MAX_HEADER_IDENTITY_LEN)
            .then(|| format!("header:{value}"))
    }

    /// Appends an audit entry; a failure to write it is logged.
    pub(crate) async fn audit(&self, entry: Audit<'_>) {
        let row = AuditEntry {
            id: 0,
            at: self.now_ms(),
            actor: entry.actor.to_owned(),
            action: entry.action.to_owned(),
            target: entry.target,
            source_ip: entry.source_ip.to_string(),
            ok: entry.ok,
            detail: entry.detail,
        };
        let action = entry.action;
        if let Err(err) = self
            .app
            .db
            .write(move |tx| admin::insert_audit(tx, &row))
            .await
        {
            tracing::error!(%err, action, "cannot write the admin audit log");
        }
    }
}

/// One audit log entry to write.
pub(crate) struct Audit<'a> {
    pub actor: &'a str,
    pub action: &'static str,
    pub target: Option<String>,
    pub source_ip: IpAddr,
    pub ok: bool,
    pub detail: Option<String>,
}

fn cookie_key(cookie: &str) -> [u8; 32] {
    Sha256::digest(cookie.as_bytes()).into()
}

/// 256 random bits, hex.
fn random_hex() -> Result<String, AdminError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| AdminError::Internal(err.to_string()))?;
    Ok(hex::encode(bytes))
}
