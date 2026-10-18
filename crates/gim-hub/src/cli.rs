//! `gim-hub config`: headless management of the stored settings, the
//! stored federation allowlist and the user policy list (docs/operations.md,
//! "Stored settings", "User policy").
//!
//! Works on the database of `GIM_HUB_DATA_DIR` / `GIM_HUB_DATABASE_PATH`,
//! also while the hub runs (WAL, busy timeout); a running hub picks changes
//! up within [`settings::POLL_INTERVAL`]. Values are validated like the
//! environment variables, secrets are never printed, and every change is
//! audited with actor `cli`. The precedence uses this process's
//! environment: run it with the hub's environment.

use std::{
    error::Error,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use gim_hub_api::{
    config::Bootstrap,
    settings::{self, Setting, SettingState, SettingsError, Source, Sources, Vars, SETTINGS},
    user_policy::{self, MODE_KEY},
    HubIdentity,
};
use gim_hub_db::{
    admin::{self, AuditEntry},
    handles,
    user_policy::{self as policy_db, ListEntry},
    Db, DbError,
};
use serde_json::Value;

const USAGE: &str = "usage: gim-hub config list | get <key> | set <key> <value> | unset <key> \
| allowlist list | allowlist set <file> | users list | users add <user_id|@handle> [note] \
| users remove <user_id> | users set <file>";

/// Runs `gim-hub config <args>` with the environment `env`, printing to
/// `out`.
pub async fn run(args: &[String], env: Vars, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let boot = Bootstrap::from_vars(env.clone())?;
    let cli = Cli {
        db: crate::open_db(&boot)?,
        env,
        boot,
    };
    match args.as_slice() {
        ["list"] => cli.list(out).await,
        ["get", key] => cli.get(key, out).await,
        ["set", key, value] => cli.set(key, value, out).await,
        ["unset", key] => cli.unset(key, out).await,
        ["allowlist", "list"] => cli.allowlist_list(out).await,
        ["allowlist", "set", file] => cli.allowlist_set(file, out).await,
        ["users", "list"] => cli.users_list(out).await,
        ["users", "add", user] => cli.users_add(user, None, out).await,
        ["users", "add", user, note] => cli.users_add(user, Some(note), out).await,
        ["users", "remove", user_id] => cli.users_remove(user_id, out).await,
        ["users", "set", file] => cli.users_set(file, out).await,
        _ => Err(USAGE.into()),
    }
}

struct Cli {
    db: Db,
    env: Vars,
    boot: Bootstrap,
}

/// A value for display: secrets as `(set)` / `(unset)`.
fn shown(state: &SettingState) -> String {
    match &state.value {
        _ if state.setting.is_secret() => if state.is_set { "(set)" } else { "(unset)" }.into(),
        Value::Null => "(unset)".into(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

fn find(key: &str) -> Result<&'static Setting, Box<dyn Error>> {
    settings::find(key).ok_or_else(|| {
        if settings::BOOTSTRAP.contains(&key) {
            format!("{key} is a bootstrap setting: environment only").into()
        } else {
            format!("unknown setting {key}").into()
        }
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

impl Cli {
    async fn sources(&self) -> Result<Sources, Box<dyn Error>> {
        let env = self.env.clone();
        Ok(self.db.read(move |conn| Sources::read(conn, env)).await?)
    }

    async fn audit(&self, action: &str, target: &str, result: &Result<String, SettingsError>) {
        let detail = match result {
            Ok(detail) => detail.clone(),
            Err(err) => err.to_string(),
        };
        self.audit_entry(action, target, result.is_ok(), Some(detail))
            .await;
    }

    async fn audit_entry(&self, action: &str, target: &str, ok: bool, detail: Option<String>) {
        let row = AuditEntry {
            id: 0,
            at: now_ms(),
            actor: settings::CLI_ACTOR.into(),
            action: action.into(),
            target: Some(target.into()),
            source_ip: "local".into(),
            ok,
            detail,
        };
        if let Err(err) = self.db.write(move |tx| admin::insert_audit(tx, &row)).await {
            eprintln!("gim-hub config: cannot write the audit log: {err}");
        }
    }

    async fn list(&self, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let sources = self.sources().await?;
        let rows: Vec<[String; 4]> = SETTINGS
            .iter()
            .map(|setting| {
                let state = settings::state(&sources, setting, None);
                [
                    setting.key.to_owned(),
                    shown(&state),
                    state.source.as_str().to_owned(),
                    setting.apply.as_str().to_owned(),
                ]
            })
            .collect();
        let width = |i: usize| {
            rows.iter()
                .map(|row| row[i].len())
                .max()
                .unwrap_or(0)
                .max(6)
        };
        let (key, value) = (width(0), width(1));
        writeln!(
            out,
            "{:key$}  {:value$}  {:7}  APPLY",
            "KEY", "VALUE", "SOURCE"
        )?;
        for [k, v, source, apply] in &rows {
            writeln!(out, "{k:key$}  {v:value$}  {source:7}  {apply}")?;
        }
        Ok(())
    }

    async fn get(&self, key: &str, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let setting = find(key)?;
        let state = settings::state(&self.sources().await?, setting, None);
        writeln!(out, "key:         {}", setting.key)?;
        writeln!(out, "value:       {}", shown(&state))?;
        writeln!(out, "source:      {}", state.source.as_str())?;
        writeln!(out, "apply:       {}", setting.apply.as_str())?;
        writeln!(out, "type:        {}", setting.kind.as_str())?;
        writeln!(out, "group:       {}", setting.group)?;
        let default = setting.default_json();
        if !default.is_null() {
            writeln!(out, "default:     {default}")?;
        }
        if let (Some(at), Some(by)) = (state.updated_at, &state.updated_by) {
            writeln!(out, "updated:     {} by {by}", at.div_euclid(1000))?;
        }
        writeln!(out, "description: {}", setting.description)?;
        if state.source == Source::Env {
            writeln!(
                out,
                "note:        set by the environment, which overrides any stored value"
            )?;
        }
        Ok(())
    }

    fn applies(setting: &Setting) -> &'static str {
        match setting.apply {
            settings::Apply::Live => "a running hub applies it within a few seconds",
            settings::Apply::Restart => "applies at the next restart",
        }
    }

    /// Env-set keys are refused: the environment would override the stored
    /// value anyway.
    fn refuse_env(&self, key: &str) -> Result<(), Box<dyn Error>> {
        if self.env.contains_key(key) {
            return Err(format!(
                "{key} is set by the environment, which overrides stored values; unset the \
                 variable to manage it here"
            )
            .into());
        }
        Ok(())
    }

    async fn set(
        &self,
        key: &str,
        value: &str,
        out: &mut impl Write,
    ) -> Result<(), Box<dyn Error>> {
        let setting = find(key)?;
        self.refuse_env(key)?;
        let result = settings::set(
            &self.db,
            &self.env,
            key,
            &Value::String(value.to_owned()),
            settings::CLI_ACTOR,
            now_ms(),
        )
        .await;
        self.audit("setting_update", key, &result).await;
        let detail = result?;
        writeln!(out, "{key}: {detail} ({})", Self::applies(setting))?;
        Ok(())
    }

    async fn unset(&self, key: &str, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let setting = find(key)?;
        self.refuse_env(key)?;
        let result = settings::unset(&self.db, &self.env, key).await;
        self.audit("setting_unset", key, &result).await;
        let detail = result?;
        writeln!(out, "{key}: {detail} ({})", Self::applies(setting))?;
        Ok(())
    }

    /// The allowlist file in effect when `GIM_HUB_FEDERATION_ALLOWLIST` is
    /// set (`true`), else the default file.
    fn allowlist_file(&self, sources: &Sources) -> (PathBuf, bool) {
        let setting = settings::find("GIM_HUB_FEDERATION_ALLOWLIST").expect("registered");
        match sources.effective(setting).0 {
            Some(path) => (PathBuf::from(path), true),
            None => (self.boot.data_dir.join("allowlist"), false),
        }
    }

    async fn allowlist_list(&self, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let sources = self.sources().await?;
        let (path, file_set) = self.allowlist_file(&sources);
        match settings::allowlist_source(file_set, &path, sources.allowlist.is_empty()) {
            settings::AllowlistSource::File { path, read_only } => {
                let note = if read_only {
                    "GIM_HUB_FEDERATION_ALLOWLIST, read-only here"
                } else {
                    "default file, used until an allowlist is stored"
                };
                writeln!(out, "# source: file {} ({note})", path.display())?;
                out.write_all(std::fs::read_to_string(&path)?.as_bytes())?;
            }
            settings::AllowlistSource::Stored => {
                writeln!(
                    out,
                    "# source: stored (table federation_allowlist), {} hubs",
                    sources.allowlist.len()
                )?;
                out.write_all(settings::render_allowlist(&sources.allowlist).as_bytes())?;
            }
        }
        Ok(())
    }

    async fn allowlist_set(&self, file: &str, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let text = std::fs::read_to_string(file).map_err(|err| format!("{file}: {err}"))?;
        let sources = self.sources().await?;
        let psk = ["GIM_HUB_P2P_PSK_FILE", "GIM_HUB_P2P_PSK"]
            .into_iter()
            .any(|key| {
                sources
                    .effective(find(key).expect("registered"))
                    .0
                    .is_some()
            });
        let hub = HubIdentity::load_or_create(&self.boot.hub_key_path())?;
        let result = match settings::parse_allowlist_entries(&text, hub.hub_id(), psk) {
            Ok(entries) => {
                let count = entries.len();
                settings::set_allowlist(&self.db, &self.env, entries)
                    .await
                    .map(|()| format!("{count} hubs"))
            }
            Err(message) => Err(SettingsError::Invalid(message)),
        };
        self.audit("allowlist_update", "federation_allowlist", &result)
            .await;
        let detail = result?;
        writeln!(
            out,
            "stored allowlist: {detail} (a running hub applies it within a few seconds)"
        )?;
        Ok(())
    }

    /// The list in the `users set` format, after a header with the mode:
    /// one user ID per line, the handle and note as a comment.
    async fn users_list(&self, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let sources = self.sources().await?;
        let state = settings::state(&sources, find(MODE_KEY)?, None);
        let entries = self.db.read(policy_db::load).await?;
        writeln!(
            out,
            "# mode: {} ({}), {} entries",
            shown(&state),
            state.source.as_str(),
            entries.len()
        )?;
        for listed in entries {
            let mut line = listed.entry.user_id;
            let comment: Vec<String> = listed
                .handle
                .map(|handle| format!("@{handle}"))
                .into_iter()
                .chain(listed.entry.note)
                .collect();
            if !comment.is_empty() {
                line.push_str("  # ");
                line.push_str(&comment.join(" "));
            }
            writeln!(out, "{line}")?;
        }
        Ok(())
    }

    /// `user` is a user ID or `@handle` (resolved on this hub).
    async fn users_add(
        &self,
        user: &str,
        note: Option<&str>,
        out: &mut impl Write,
    ) -> Result<(), Box<dyn Error>> {
        let user_id = if user.trim().starts_with('@') {
            let name = user_policy::handle_name(user);
            let owner = {
                let name = name.clone();
                self.db
                    .read(move |conn| handles::owner(conn, &name))
                    .await?
            };
            owner.ok_or_else(|| format!("unknown handle @{name}"))?
        } else {
            user_policy::parse_user_id(user)?
        };
        let entry = ListEntry {
            user_id: user_id.clone(),
            added_at: now_ms(),
            added_by: settings::CLI_ACTOR.into(),
            note: note
                .map(|note| note.trim().to_owned())
                .filter(|note| !note.is_empty()),
        };
        let detail = entry.note.clone();
        let added = self.db.write(move |tx| policy_db::add(tx, &entry)).await?;
        let result = if added {
            Ok(detail)
        } else {
            Err(format!("{user_id} is already listed"))
        };
        let audit = result
            .as_ref()
            .map_or_else(|err| Some(err.clone()), Clone::clone);
        self.audit_entry("users_policy_add", &user_id, added, audit)
            .await;
        result?;
        writeln!(
            out,
            "added {user_id} (a running hub applies it within a few seconds)"
        )?;
        Ok(())
    }

    async fn users_remove(
        &self,
        user_id: &str,
        out: &mut impl Write,
    ) -> Result<(), Box<dyn Error>> {
        let id = user_id.to_owned();
        let removed = self.db.write(move |tx| policy_db::remove(tx, &id)).await?;
        let error = (!removed).then(|| format!("{user_id} is not listed"));
        self.audit_entry("users_policy_remove", user_id, removed, error.clone())
            .await;
        if let Some(error) = error {
            return Err(error.into());
        }
        writeln!(
            out,
            "removed {user_id} (a running hub applies it within a few seconds)"
        )?;
        Ok(())
    }

    /// Replaces the list with the file (one user ID per line, `#`
    /// comments); nothing is stored when a line is invalid.
    async fn users_set(&self, file: &str, out: &mut impl Write) -> Result<(), Box<dyn Error>> {
        let text = std::fs::read_to_string(file).map_err(|err| format!("{file}: {err}"))?;
        let user_ids = match user_policy::parse_list(&text) {
            Ok(user_ids) => user_ids,
            Err(message) => {
                self.audit_entry("users_policy_update", file, false, Some(message.clone()))
                    .await;
                return Err(format!("{file}: {message}").into());
            }
        };
        let target = format!("{} entries", user_ids.len());
        let now = now_ms();
        let detail = self
            .db
            .write(move |tx| {
                let existing: Vec<ListEntry> = policy_db::load(tx)?
                    .into_iter()
                    .map(|listed| listed.entry)
                    .collect();
                let entries: Vec<ListEntry> = user_ids
                    .into_iter()
                    .map(|user_id| {
                        existing
                            .iter()
                            .find(|entry| entry.user_id == user_id)
                            .cloned()
                            .unwrap_or(ListEntry {
                                user_id,
                                added_at: now,
                                added_by: settings::CLI_ACTOR.into(),
                                note: None,
                            })
                    })
                    .collect();
                let added = entries
                    .iter()
                    .filter(|entry| !existing.iter().any(|e| e.user_id == entry.user_id))
                    .count();
                let removed = existing.len() + added - entries.len();
                policy_db::replace(tx, &entries)?;
                Ok::<_, DbError>(format!("{added} added, {removed} removed"))
            })
            .await?;
        self.audit_entry("users_policy_update", &target, true, Some(detail.clone()))
            .await;
        writeln!(
            out,
            "stored user list: {target}, {detail} (a running hub applies it within a few seconds)"
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run_ok(dir: &std::path::Path, env: &[(&str, &str)], args: &[&str]) -> String {
        let mut out = Vec::new();
        run(&args_of(args), vars(dir, env), &mut out).await.unwrap();
        String::from_utf8(out).unwrap()
    }

    async fn run_err(dir: &std::path::Path, env: &[(&str, &str)], args: &[&str]) -> String {
        let mut out = Vec::new();
        run(&args_of(args), vars(dir, env), &mut out)
            .await
            .unwrap_err()
            .to_string()
    }

    fn args_of(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    fn vars(dir: &std::path::Path, env: &[(&str, &str)]) -> Vars {
        let mut vars = Vars::new();
        vars.insert("GIM_HUB_DATA_DIR".into(), dir.display().to_string());
        for (k, v) in env {
            vars.insert((*k).into(), (*v).into());
        }
        vars
    }

    async fn audit(dir: &std::path::Path) -> Vec<AuditEntry> {
        let db = Db::open(&dir.join("hub.db")).unwrap();
        db.read(|conn| admin::list_audit(conn, None, 100))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn set_get_unset_with_validation_and_audit() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let out = run_ok(dir, &[], &["set", "GIM_HUB_EVENT_RETENTION_DAYS", "30"]).await;
        assert_eq!(
            out,
            "GIM_HUB_EVENT_RETENTION_DAYS: 7 -> 30 (a running hub applies it within a few \
             seconds)\n"
        );
        let out = run_ok(dir, &[], &["get", "GIM_HUB_EVENT_RETENTION_DAYS"]).await;
        assert!(out.contains("value:       30\n"), "{out}");
        assert!(out.contains("source:      stored\n"), "{out}");
        assert!(out.contains("by cli\n"), "{out}");

        let err = run_err(dir, &[], &["set", "GIM_HUB_EVENT_RETENTION_DAYS", "0"]).await;
        assert!(err.contains("must be at least 1"), "{err}");
        let out = run_ok(dir, &[], &["get", "GIM_HUB_EVENT_RETENTION_DAYS"]).await;
        assert!(out.contains("value:       30\n"), "{out}");

        let list = run_ok(dir, &[], &["list"]).await;
        let row = list
            .lines()
            .find(|line| line.starts_with("GIM_HUB_EVENT_RETENTION_DAYS "))
            .unwrap();
        assert_eq!(
            row.split_whitespace().collect::<Vec<_>>(),
            ["GIM_HUB_EVENT_RETENTION_DAYS", "30", "stored", "live"]
        );
        assert!(!list.contains("GIM_HUB_LISTEN"));

        let out = run_ok(dir, &[], &["unset", "GIM_HUB_EVENT_RETENTION_DAYS"]).await;
        assert!(
            out.starts_with("GIM_HUB_EVENT_RETENTION_DAYS: 30 -> 7 "),
            "{out}"
        );

        let audit = audit(dir).await;
        let actions: Vec<_> = audit
            .iter()
            .map(|e| (e.actor.as_str(), e.action.as_str(), e.ok))
            .collect();
        assert_eq!(
            actions,
            [
                ("cli", "setting_unset", true),
                ("cli", "setting_update", false),
                ("cli", "setting_update", true),
            ]
        );
        assert_eq!(audit[2].detail.as_deref(), Some("7 -> 30"));
        assert_eq!(
            audit[2].target.as_deref(),
            Some("GIM_HUB_EVENT_RETENTION_DAYS")
        );
    }

    #[tokio::test]
    async fn secrets_are_never_printed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let secret = "s3cr3t-".repeat(6);
        let key = "GIM_HUB_PUSH_WEBHOOK_SECRET";
        let out = run_ok(dir, &[], &["get", key]).await;
        assert!(out.contains("value:       (unset)\n"), "{out}");
        let out = run_ok(dir, &[], &["set", key, &secret]).await;
        assert!(!out.contains(&secret), "{out}");
        assert!(out.contains("null -> ***"), "{out}");
        let out = run_ok(dir, &[], &["get", key]).await;
        assert!(out.contains("value:       (set)\n"), "{out}");
        let list = run_ok(dir, &[], &["list"]).await;
        assert!(!list.contains(&secret));
        assert!(list.contains("(set)"));
        let out = run_ok(dir, &[(key, secret.as_str())], &["get", key]).await;
        assert!(
            out.contains("source:      env\n") && !out.contains(&secret),
            "{out}"
        );
        for entry in audit(dir).await {
            assert!(!entry.detail.unwrap_or_default().contains(&secret));
        }
    }

    #[tokio::test]
    async fn env_set_keys_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let env = [("GIM_HUB_PUSH_MINIMAL", "true")];
        let out = run_ok(dir, &env, &["get", "GIM_HUB_PUSH_MINIMAL"]).await;
        assert!(out.contains("source:      env\n"), "{out}");
        for args in [
            &["set", "GIM_HUB_PUSH_MINIMAL", "false"][..],
            &["unset", "GIM_HUB_PUSH_MINIMAL"],
        ] {
            let err = run_err(dir, &env, args).await;
            assert!(err.contains("set by the environment"), "{err}");
        }
        let err = run_err(dir, &[], &["get", "GIM_HUB_LISTEN"]).await;
        assert!(err.contains("bootstrap setting"), "{err}");
        let err = run_err(dir, &[], &["set", "GIM_HUB_NOPE", "1"]).await;
        assert!(err.contains("unknown setting"), "{err}");
        let err = run_err(dir, &[], &["frobnicate"]).await;
        assert!(err.starts_with("usage: gim-hub config"), "{err}");
    }

    const ALICE: &str = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa";

    /// A user of the hub at `dir` with `handle`.
    async fn user_with_handle(dir: &std::path::Path, user_id: &str, handle: &str) {
        let db = Db::open(&dir.join("hub.db")).unwrap();
        let (user_id, handle) = (user_id.to_owned(), handle.to_owned());
        db.write(move |tx| {
            gim_hub_db::users::put_device_list(
                tx,
                &gim_hub_db::users::StoredDeviceList {
                    user_id: user_id.clone(),
                    root_pubkey: vec![0; 32],
                    device_list: Vec::new(),
                    seq: 0,
                    updated_at: 1,
                },
            )?;
            handles::claim(tx, &handle, &user_id, 1).map(drop)
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn users_add_list_remove_set() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let out = run_ok(dir, &[], &["users", "list"]).await;
        assert_eq!(out, "# mode: open (default), 0 entries\n");
        let err = run_err(dir, &[], &["users", "add", "@alice"]).await;
        assert_eq!(err, "unknown handle @alice");
        user_with_handle(dir, ALICE, "alice").await;
        let out = run_ok(dir, &[], &["users", "add", "@Alice", "spam reports"]).await;
        assert!(out.starts_with(&format!("added {ALICE} ")), "{out}");
        let err = run_err(dir, &[], &["users", "add", ALICE]).await;
        assert!(err.contains("already listed"), "{err}");
        let err = run_err(dir, &[], &["users", "add", "not-a-user"]).await;
        assert!(err.contains("invalid user ID"), "{err}");
        run_ok(dir, &[], &["set", "GIM_HUB_USER_POLICY", "deny"]).await;
        let listed = run_ok(dir, &[], &["users", "list"]).await;
        assert_eq!(
            listed,
            format!("# mode: deny (stored), 1 entries\n{ALICE}  # @alice spam reports\n")
        );
        let out = run_ok(dir, &[("GIM_HUB_USER_POLICY", "allow")], &["users", "list"]).await;
        assert!(out.starts_with("# mode: allow (env), 1 entries\n"), "{out}");

        // The list output is valid `users set` input; an invalid line stores nothing.
        let file = dir.join("users.txt");
        std::fs::write(&file, format!("{listed}\n# more\nbad user\n")).unwrap();
        let err = run_err(dir, &[], &["users", "set", file.to_str().unwrap()]).await;
        assert!(
            err.contains("line 5: invalid user ID \"bad user\""),
            "{err}"
        );
        std::fs::write(&file, &listed).unwrap();
        let out = run_ok(dir, &[], &["users", "set", file.to_str().unwrap()]).await;
        assert!(
            out.starts_with("stored user list: 1 entries, 0 added, 0 removed"),
            "{out}"
        );
        assert_eq!(
            run_ok(dir, &[], &["users", "list"]).await,
            listed,
            "note kept"
        );

        let out = run_ok(dir, &[], &["users", "remove", ALICE]).await;
        assert!(out.starts_with(&format!("removed {ALICE} ")), "{out}");
        let err = run_err(dir, &[], &["users", "remove", ALICE]).await;
        assert!(err.contains("is not listed"), "{err}");

        let actions: Vec<_> = audit(dir)
            .await
            .into_iter()
            .filter(|e| e.action.starts_with("users_policy_"))
            .map(|e| (e.actor, e.action, e.target.unwrap_or_default(), e.ok))
            .collect();
        let row = |action: &str, target: &str, ok| {
            ("cli".to_owned(), action.to_owned(), target.to_owned(), ok)
        };
        assert_eq!(
            actions,
            [
                row("users_policy_remove", ALICE, false),
                row("users_policy_remove", ALICE, true),
                row("users_policy_update", "1 entries", true),
                row("users_policy_update", file.to_str().unwrap(), false),
                row("users_policy_add", ALICE, false),
                row("users_policy_add", ALICE, true),
            ]
        );
    }

    #[tokio::test]
    async fn allowlist_set_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let peer = HubIdentity::from_seed(&[7; 32]);
        let file = dir.join("peers.txt");
        std::fs::write(&file, "# nobody\n").unwrap();
        let err = run_err(dir, &[], &["allowlist", "set", file.to_str().unwrap()]).await;
        assert!(err.contains("lists no other hub"), "{err}");
        std::fs::write(
            &file,
            format!(
                "# peers\n{} /dns4/hub-b.example.eu/tcp/4001\n",
                peer.hub_id()
            ),
        )
        .unwrap();
        let out = run_ok(dir, &[], &["allowlist", "set", file.to_str().unwrap()]).await;
        assert!(out.starts_with("stored allowlist: 1 hubs"), "{out}");
        let out = run_ok(dir, &[], &["allowlist", "list"]).await;
        assert_eq!(
            out,
            format!(
                "# source: stored (table federation_allowlist), 1 hubs\n{} \
                 /dns4/hub-b.example.eu/tcp/4001\n",
                peer.hub_id()
            )
        );
        // The file is authoritative when set.
        let env = [("GIM_HUB_FEDERATION_ALLOWLIST", file.to_str().unwrap())];
        let err = run_err(dir, &env, &["allowlist", "set", file.to_str().unwrap()]).await;
        assert!(err.contains("read-only"), "{err}");
        let out = run_ok(dir, &env, &["allowlist", "list"]).await;
        assert!(out.starts_with("# source: file "), "{out}");
        let audit = audit(dir).await;
        assert_eq!(audit[0].action, "allowlist_update");
        assert!(!audit[0].ok);
        assert_eq!(audit[1].detail.as_deref(), Some("1 hubs"));
    }
}
