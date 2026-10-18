//! Stored settings (docs/operations.md, "Stored settings").
//!
//! Every non-bootstrap `GIM_HUB_*` setting ([`registry::SETTINGS`]) can be
//! stored in the `settings` table, managed from the admin API and
//! `gim-hub config`. Precedence: environment variable > stored value >
//! built-in default. The loader merges the environment and the stored
//! values into one variable set and builds the configuration with the
//! existing parsers ([`Config::from_vars`], [`FederationConfig::from_vars`]),
//! so an environment-only deployment is configured exactly as before, and a
//! value written through the API or the CLI is validated by the same parser
//! as the environment variable ([`validate`]).
//!
//! A running hub applies changed live settings at once ([`Runtime`]): the
//! admin API reloads after its write, and a watcher polls the settings
//! version (bumped by every write) to pick up changes made by the CLI from
//! another process. Restart settings are stored and reported as
//! `restart_pending` until the next start.

pub mod registry;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use gim_hub_db::{
    settings::{self as db, StoredSetting},
    Connection, Db, DbError,
};
use gim_hub_identity::HubId;
use gim_hub_s2s::{
    config::ConfigError as FederationConfigError, policy::parse_allowlist, FederationConfig,
    FederationService, Outbox, OutboxConfig,
};
use serde_json::Value;

pub use registry::{find, Apply, Kind, Setting, BOOTSTRAP, SETTINGS};

use crate::{
    config::{Config, ConfigError},
    user_policy, AppState,
};

/// `(name, value)` variables by name.
pub type Vars = BTreeMap<String, String>;

/// How often a running hub checks the settings version.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Actor of changes made with `gim-hub config`.
pub const CLI_ACTOR: &str = "cli";

/// The non-empty `GIM_HUB_*` and `LODE_ACTIVE_VERSION` variables of `vars`
/// (e.g. `std::env::vars()`).
pub fn env_vars(vars: impl IntoIterator<Item = (String, String)>) -> Vars {
    vars.into_iter()
        .filter(|(name, value)| {
            (name.starts_with("GIM_HUB_") || name == "LODE_ACTIVE_VERSION") && !value.is_empty()
        })
        .collect()
}

/// Where the effective value of a setting comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Env,
    Stored,
    Default,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Stored => "stored",
            Self::Default => "default",
        }
    }
}

/// The environment, the stored settings, the stored allowlist and the user
/// policy list.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    pub env: Vars,
    pub stored: BTreeMap<String, StoredSetting>,
    /// `(hub_id, static multiaddrs)` by hub ID.
    pub allowlist: Vec<(String, Vec<String>)>,
    /// The user IDs of the user policy list.
    pub user_list: BTreeSet<String>,
}

impl Sources {
    /// Reads the stored settings, allowlist and user policy list.
    pub fn read(conn: &Connection, env: Vars) -> Result<Self, DbError> {
        Ok(Self {
            env,
            stored: db::list(conn)?
                .into_iter()
                .map(|row| (row.key.clone(), row))
                .collect(),
            allowlist: db::allowlist(conn)?,
            user_list: gim_hub_db::user_policy::user_ids(conn)?
                .into_iter()
                .collect(),
        })
    }

    /// The stored value of `setting` in the environment format. A value
    /// that is not valid JSON is taken as it is (the parsers decide).
    fn stored_raw(&self, setting: &Setting) -> Option<String> {
        let row = self.stored.get(setting.key)?;
        Some(
            serde_json::from_str::<Value>(&row.value)
                .ok()
                .and_then(|value| setting.raw(&value).ok())
                .unwrap_or_else(|| row.value.clone()),
        )
    }

    /// The effective value of `setting` in the environment format (`None`:
    /// the default applies) and its source.
    pub fn effective(&self, setting: &Setting) -> (Option<String>, Source) {
        if let Some(raw) = self.env.get(setting.key) {
            return (Some(raw.clone()), Source::Env);
        }
        match self.stored_raw(setting) {
            Some(raw) => (Some(raw), Source::Stored),
            None => (None, Source::Default),
        }
    }

    /// The variables the configuration parsers see: the environment plus
    /// every registered stored setting it does not set.
    pub fn vars(&self) -> Vars {
        let mut vars = self.env.clone();
        for setting in SETTINGS {
            if let (Some(raw), Source::Stored) = self.effective(setting) {
                vars.insert(setting.key.to_owned(), raw);
            }
        }
        vars
    }

    /// Registered keys whose effective value is stored.
    fn stored_keys(&self) -> BTreeSet<String> {
        SETTINGS
            .iter()
            .filter(|setting| self.effective(setting).1 == Source::Stored)
            .map(|setting| setting.key.to_owned())
            .collect()
    }
}

/// The configuration built from the environment and the stored settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub config: Config,
    pub federation: FederationConfig,
    /// The variables the configuration was built from.
    pub vars: Vars,
    /// The user policy list ([`Config::user_policy`] is the mode).
    pub user_list: BTreeSet<String>,
}

/// The configuration cannot be built.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Federation(#[from] FederationConfigError),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Builds the configuration from `sources` (environment > stored >
/// default). A stored value the parsers refuse (only possible after a
/// manual database edit: writes are validated) is logged and ignored, so
/// the default applies; an invalid environment variable is an error, as
/// before stored settings existed.
pub fn load(sources: &Sources) -> Result<Effective, LoadError> {
    let effective = parse(sources.vars(), &sources.stored_keys())?;
    Ok(with_allowlist(effective, sources))
}

/// Parses `vars`; a parser error naming one of `stored` drops that variable
/// and parses again.
fn parse(mut vars: Vars, stored: &BTreeSet<String>) -> Result<Effective, LoadError> {
    let drop_invalid = |vars: &mut Vars, name: &str, message: String| {
        if !stored.contains(name) || vars.remove(name).is_none() {
            return false;
        }
        tracing::error!(
            setting = name,
            error = message,
            "invalid stored setting ignored; the default applies"
        );
        true
    };
    loop {
        let config = match Config::from_vars(vars.clone()) {
            Ok(config) => config,
            Err(err) => {
                let message = redact_config(&err);
                if drop_invalid(&mut vars, err.name, message) {
                    continue;
                }
                return Err(err.into());
            }
        };
        match FederationConfig::from_vars(vars.clone(), &config.data_dir) {
            Ok(federation) => {
                return Ok(Effective {
                    config,
                    federation,
                    vars,
                    user_list: BTreeSet::new(),
                })
            }
            Err(err) => {
                let message = redact_federation(&err);
                if drop_invalid(&mut vars, err.name, message) {
                    continue;
                }
                return Err(err.into());
            }
        }
    }
}

/// Sets the user policy list and, on an enabled federation config, the
/// stored allowlist when it is the allowlist source ([`allowlist_source`]);
/// when no source has an allowlist, the stored (empty) one is used, which
/// fails startup like a missing file did.
fn with_allowlist(mut effective: Effective, sources: &Sources) -> Effective {
    effective.user_list.clone_from(&sources.user_list);
    let federation = &mut effective.federation;
    if !federation.enabled {
        return effective;
    }
    let source = allowlist_source(
        effective.vars.contains_key("GIM_HUB_FEDERATION_ALLOWLIST"),
        &federation.allowlist_path,
        sources.allowlist.is_empty(),
    );
    if source == AllowlistSource::Stored {
        federation.allowlist_text = Some(render_allowlist(&sources.allowlist));
    }
    effective
}

/// Where the federation allowlist comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistSource {
    /// The file at `path`. `read_only` when `GIM_HUB_FEDERATION_ALLOWLIST`
    /// is set; otherwise it is the default `$GIM_HUB_DATA_DIR/allowlist` of
    /// an existing deployment, used until an allowlist is stored.
    File { path: PathBuf, read_only: bool },
    /// The table `federation_allowlist`.
    Stored,
}

/// The allowlist source: the file when `GIM_HUB_FEDERATION_ALLOWLIST` is set
/// (`file_set`), else the stored allowlist when not empty, else the default
/// file at `path` when it exists, else the (empty) stored allowlist.
pub fn allowlist_source(file_set: bool, path: &Path, table_empty: bool) -> AllowlistSource {
    if file_set {
        return AllowlistSource::File {
            path: path.to_owned(),
            read_only: true,
        };
    }
    if table_empty && path.is_file() {
        return AllowlistSource::File {
            path: path.to_owned(),
            read_only: false,
        };
    }
    AllowlistSource::Stored
}

/// The stored allowlist in the file format: `hub_id [multiaddr ...]` lines.
pub fn render_allowlist(entries: &[(String, Vec<String>)]) -> String {
    entries
        .iter()
        .map(|(hub_id, addrs)| {
            let mut line = hub_id.clone();
            for addr in addrs {
                line.push(' ');
                line.push_str(addr);
            }
            line.push('\n');
            line
        })
        .collect()
}

/// Parses allowlist `text` (file format) into stored entries, by hub ID,
/// with the allowlist rules: the own hub is skipped, a `psk` forbids QUIC
/// addresses, and an allowlist naming no other hub is invalid.
pub fn parse_allowlist_entries(
    text: &str,
    own_hub_id: &HubId,
    psk: bool,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let hubs = parse_allowlist(text, own_hub_id, psk).map_err(|err| err.to_string())?;
    if hubs.is_empty() {
        return Err(gim_hub_s2s::PolicyError::EmptyStored.to_string());
    }
    let mut entries: Vec<_> = hubs
        .into_iter()
        .map(|(hub_id, addrs)| {
            (
                hub_id.to_string(),
                addrs.iter().map(ToString::to_string).collect(),
            )
        })
        .collect();
    entries.sort();
    Ok(entries)
}

fn is_secret_key(key: &str) -> bool {
    find(key).is_some_and(Setting::is_secret)
}

/// The parser message of `err`, without the value of a secret.
fn redact_config(err: &ConfigError) -> String {
    if is_secret_key(err.name) {
        format!("invalid {}: {}", err.name, err.reason)
    } else {
        err.to_string()
    }
}

fn redact_federation(err: &FederationConfigError) -> String {
    if is_secret_key(err.name) {
        format!("invalid {}: {}", err.name, err.reason)
    } else {
        err.to_string()
    }
}

/// Keys parsed by [`FederationConfig::from_vars`].
fn federation_parsed(setting: &Setting) -> bool {
    setting.group == "federation" || setting.key == "GIM_HUB_FETCH_BLOB_PER_MINUTE"
}

/// Validates setting `key` = `raw` (`None`: unset) in the context of
/// `sources` with the configuration parsers; returns the parser message.
///
/// The whole configuration must stay valid, so values that depend on each
/// other are written in order (e.g. the webhook secret before the URL, the
/// public URL before enabling federation). While federation is off its
/// settings are checked as if it were on, reporting only errors about the
/// written key (and, for the PSK, the listen addresses it rules out).
pub fn validate(sources: &Sources, key: &str, raw: Option<&str>) -> Result<(), String> {
    let setting = find(key).ok_or_else(|| format!("unknown setting {key}"))?;
    let mut vars = sources.vars();
    match raw {
        Some(raw) => vars.insert(key.to_owned(), raw.to_owned()),
        None => vars.remove(key),
    };
    let config = Config::from_vars(vars.clone()).map_err(|err| redact_config(&err))?;
    let enabled = vars.get("GIM_HUB_FEDERATION").map(|v| v.trim()) == Some("true");
    if enabled {
        FederationConfig::from_vars(vars, &config.data_dir)
            .map_err(|err| redact_federation(&err))?;
    } else if federation_parsed(setting) && key != "GIM_HUB_FEDERATION" {
        vars.insert("GIM_HUB_FEDERATION".into(), "true".into());
        if let Err(err) = FederationConfig::from_vars(vars, &config.data_dir) {
            let psk = matches!(key, "GIM_HUB_P2P_PSK" | "GIM_HUB_P2P_PSK_FILE");
            if err.name == key || psk {
                return Err(redact_federation(&err));
            }
        }
    }
    Ok(())
}

/// A refused settings write.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("unknown setting {0}")]
    NotFound(String),
    /// The key is set by the environment, which overrides any stored value.
    #[error("set by environment")]
    SetByEnv,
    /// `GIM_HUB_FEDERATION_ALLOWLIST` is set: the file is authoritative.
    #[error("the allowlist is the file GIM_HUB_FEDERATION_ALLOWLIST (read-only here)")]
    AllowlistFile,
    /// The parser's message.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// What a setting looks like now.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingState {
    pub setting: &'static Setting,
    /// The effective value; always `null` for secrets.
    pub value: Value,
    /// For secrets whether a value exists, otherwise `value != default`.
    pub is_set: bool,
    pub source: Source,
    /// A restart setting whose effective value differs from the value the
    /// running process uses.
    pub restart_pending: bool,
    /// ms since the Unix epoch, when stored.
    pub updated_at: Option<i64>,
    pub updated_by: Option<String>,
}

/// The state of `setting`; `startup` is the variable set the running
/// process was built from (no restart is pending without one).
pub fn state(sources: &Sources, setting: &'static Setting, startup: Option<&Vars>) -> SettingState {
    let (raw, source) = sources.effective(setting);
    let value = match &raw {
        _ if setting.is_secret() => Value::Null,
        Some(raw) => setting.json(raw),
        None => setting.default_json(),
    };
    let is_set = if setting.is_secret() {
        raw.is_some()
    } else {
        value != setting.default_json()
    };
    let restart_pending = setting.apply == Apply::Restart
        && startup.is_some_and(|startup| startup.get(setting.key) != raw.as_ref());
    let row = sources.stored.get(setting.key);
    SettingState {
        setting,
        value,
        is_set,
        source,
        restart_pending,
        updated_at: row.map(|row| row.updated_at),
        updated_by: row.map(|row| row.updated_by.clone()),
    }
}

/// The value of `setting` for an audit entry: `***` for a set secret.
fn audit_value(sources: &Sources, setting: &'static Setting) -> String {
    let state = state(sources, setting, None);
    if setting.is_secret() {
        return if state.is_set { "***" } else { "null" }.to_owned();
    }
    state.value.to_string()
}

/// Stores `key` = `value` (a JSON value, see [`Setting::raw`]) by `actor`
/// after validating it; `env` is the writer's environment. Returns the
/// audit detail `old -> new` (secrets as `***`). Nothing is stored when it
/// fails.
pub async fn set(
    db: &Db,
    env: &Vars,
    key: &str,
    value: &Value,
    actor: &str,
    now_ms: i64,
) -> Result<String, SettingsError> {
    let setting = find(key).ok_or_else(|| SettingsError::NotFound(key.to_owned()))?;
    if env.contains_key(key) {
        return Err(SettingsError::SetByEnv);
    }
    let raw = setting
        .raw(value)
        .map_err(|reason| SettingsError::Invalid(format!("invalid {key}: {reason}")))?;
    let (env, actor) = (env.clone(), actor.to_owned());
    db.write(move |tx| {
        let mut sources = Sources::read(tx, env)?;
        validate(&sources, setting.key, Some(&raw)).map_err(SettingsError::Invalid)?;
        let old = audit_value(&sources, setting);
        let row = StoredSetting {
            key: setting.key.to_owned(),
            value: setting.json(&raw).to_string(),
            updated_at: now_ms,
            updated_by: actor,
        };
        db::put(tx, &row)?;
        sources.stored.insert(row.key.clone(), row);
        Ok(format!("{old} -> {}", audit_value(&sources, setting)))
    })
    .await
}

/// Deletes the stored value of `key`, back to the default; `env` is the
/// writer's environment. Returns the audit detail `old -> new`.
pub async fn unset(db: &Db, env: &Vars, key: &str) -> Result<String, SettingsError> {
    let setting = find(key).ok_or_else(|| SettingsError::NotFound(key.to_owned()))?;
    if env.contains_key(key) {
        return Err(SettingsError::SetByEnv);
    }
    let env = env.clone();
    db.write(move |tx| {
        let mut sources = Sources::read(tx, env)?;
        validate(&sources, setting.key, None).map_err(SettingsError::Invalid)?;
        let old = audit_value(&sources, setting);
        db::delete(tx, setting.key)?;
        sources.stored.remove(setting.key);
        Ok(format!("{old} -> {}", audit_value(&sources, setting)))
    })
    .await
}

/// Replaces the stored allowlist with `entries` (from
/// [`parse_allowlist_entries`]). Refused while `GIM_HUB_FEDERATION_ALLOWLIST`
/// is set (environment or stored): the file is authoritative.
pub async fn set_allowlist(
    db: &Db,
    env: &Vars,
    entries: Vec<(String, Vec<String>)>,
) -> Result<(), SettingsError> {
    let env = env.clone();
    db.write(move |tx| {
        let sources = Sources::read(tx, env)?;
        let file = find("GIM_HUB_FEDERATION_ALLOWLIST").expect("registered");
        if sources.effective(file).0.is_some() {
            return Err(SettingsError::AllowlistFile);
        }
        db::replace_allowlist(tx, &entries)?;
        Ok(())
    })
    .await
}

/// Called with the configuration to apply after a reload.
pub type Applier = Arc<dyn Fn(&Effective) + Send + Sync>;

/// The stored settings of a running hub: the startup variables, live
/// reload and the appliers that put changed live values in force. Cheap to
/// clone.
#[derive(Clone)]
pub struct Runtime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    db: Db,
    env: Vars,
    startup: Vars,
    version: Mutex<i64>,
    appliers: Mutex<Vec<Applier>>,
    reload: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime").finish_non_exhaustive()
    }
}

impl Runtime {
    /// Reads the stored settings and builds the startup configuration
    /// ([`load`]); `env` is the process environment ([`env_vars`]).
    pub async fn load(db: Db, env: Vars) -> Result<(Self, Effective), LoadError> {
        let (sources, version) = db
            .read(move |conn| Ok::<_, DbError>((Sources::read(conn, env)?, db::version(conn)?)))
            .await?;
        let effective = load(&sources)?;
        let runtime = Self::new(db, sources.env, effective.vars.clone(), version);
        Ok((runtime, effective))
    }

    /// A runtime of a process started from the variables `startup`.
    pub fn new(db: Db, env: Vars, startup: Vars, version: i64) -> Self {
        Self {
            inner: Arc::new(RuntimeInner {
                db,
                env,
                startup,
                version: Mutex::new(version),
                appliers: Mutex::default(),
                reload: tokio::sync::Mutex::new(()),
            }),
        }
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    /// The process environment.
    pub fn env(&self) -> &Vars {
        &self.inner.env
    }

    /// The variables the running process was built from.
    pub fn startup(&self) -> &Vars {
        &self.inner.startup
    }

    /// Registers `applier`, called after every reload.
    pub fn on_apply(&self, applier: impl Fn(&Effective) + Send + Sync + 'static) {
        self.inner
            .appliers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::new(applier));
    }

    /// The current environment, stored settings and allowlist.
    pub async fn sources(&self) -> Result<Sources, DbError> {
        let env = self.inner.env.clone();
        self.inner
            .db
            .read(move |conn| Sources::read(conn, env))
            .await
    }

    /// The state of `setting` in `sources`.
    pub fn state(&self, sources: &Sources, setting: &'static Setting) -> SettingState {
        state(sources, setting, Some(&self.inner.startup))
    }

    /// The configuration to apply for `sources`: live settings at their
    /// current value, restart settings at their startup value.
    pub fn applied(&self, sources: &Sources) -> Result<Effective, LoadError> {
        let mut vars = self.inner.startup.clone();
        let mut stored = BTreeSet::new();
        for setting in SETTINGS.iter().filter(|s| s.apply == Apply::Live) {
            match sources.effective(setting) {
                (Some(raw), source) => {
                    if source == Source::Stored {
                        stored.insert(setting.key.to_owned());
                    }
                    vars.insert(setting.key.to_owned(), raw);
                }
                (None, _) => {
                    vars.remove(setting.key);
                }
            }
        }
        Ok(with_allowlist(parse(vars, &stored)?, sources))
    }

    /// Re-reads the stored settings and applies the live ones. The admin
    /// API calls it after a write; the watcher when the version changed.
    pub async fn reload(&self) -> Result<(), DbError> {
        let _reload = self.inner.reload.lock().await;
        let env = self.inner.env.clone();
        let (sources, version) = self
            .inner
            .db
            .read(move |conn| Ok::<_, DbError>((Sources::read(conn, env)?, db::version(conn)?)))
            .await?;
        *self
            .inner
            .version
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = version;
        match self.applied(&sources) {
            Ok(effective) => {
                let appliers = self
                    .inner
                    .appliers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                for applier in appliers {
                    applier(&effective);
                }
                // Users the policy no longer admits lose their sessions.
                let mode = effective.config.user_policy;
                let revoked = user_policy::revoke_not_admitted(&self.inner.db, mode).await?;
                if revoked > 0 {
                    tracing::info!(revoked, %mode, "sessions of users not admitted deleted");
                }
            }
            Err(err) => tracing::error!(%err, "stored settings not applied"),
        }
        Ok(())
    }

    /// Reloads if the settings version changed; returns whether it did.
    pub async fn check(&self) -> Result<bool, DbError> {
        let version = self.inner.db.read(db::version).await?;
        let seen = *self
            .inner
            .version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if version == seen {
            return Ok(false);
        }
        tracing::info!(version, "stored settings changed; reloading");
        self.reload().await?;
        Ok(true)
    }

    /// Checks the settings version every `every`.
    pub fn spawn_watcher(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let runtime = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if let Err(err) = runtime.check().await {
                    tracing::error!(%err, "reading the settings version failed");
                }
            }
        })
    }
}

/// Registers the applier of a running hub on `runtime`: changed live
/// settings go to `state` ([`AppState::apply_live`]: handlers, rate limits,
/// push), the user policy to `state.user_policy` and, with federation, to the hosting and DeviceList caches, the
/// outbox limits, the `FetchBlob` budget and, when it is the source, the
/// stored allowlist (applied like a SIGHUP reload of the file). `state`
/// must be the final state, with federation wired in.
pub fn install(
    runtime: &Runtime,
    state: AppState,
    federation: Option<FederationService>,
    outbox: Option<Outbox>,
) {
    let applied_allowlist = Mutex::new(None::<String>);
    runtime.on_apply(move |effective| {
        if let Err(err) = state.apply_live(effective.config.clone()) {
            tracing::error!(%err, "push settings not applied");
        }
        let mode = effective.config.user_policy;
        if state.user_policy.set(mode, effective.user_list.clone()) {
            tracing::info!(%mode, listed = effective.user_list.len(), "user policy applied");
            user_policy::warn_if_nobody_admitted(mode, effective.user_list.len());
        }
        let config = &effective.federation;
        if !config.enabled {
            return;
        }
        state
            .hosting
            .set_cache_ttl(Duration::from_secs(config.hosting_cache_seconds.into()));
        state.device_lists.set_cache_ttl(Duration::from_secs(
            u64::from(config.device_list_cache_hours) * 3600,
        ));
        if let Some(outbox) = &outbox {
            outbox.set_config(OutboxConfig {
                sweep_interval: outbox.config().sweep_interval,
                ..OutboxConfig::from(config)
            });
        }
        let Some(service) = &federation else {
            return;
        };
        if let Some(allowlist) = service.allowlist() {
            allowlist.set_fetch_blob_limit(config.fetch_blob_per_minute);
        }
        if let Some(text) = &config.allowlist_text {
            let mut applied = applied_allowlist
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if applied.as_deref() != Some(text.as_str()) {
                match service.set_allowlist_text(text) {
                    Ok(()) => *applied = Some(text.clone()),
                    Err(err) => tracing::error!(%err, "stored allowlist not applied"),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests;
