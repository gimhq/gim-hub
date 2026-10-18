//! The hub's user policy (docs/operations.md, "User policy").
//!
//! `GIM_HUB_USER_POLICY` (a live stored setting, overridden by the
//! environment) selects the mode; the user list is the table
//! `user_policy_list` ([`gim_hub_db::user_policy`]). A user the policy
//! rejects is "not admitted": it cannot register or sign in on this hub
//! (403 `user_not_admitted`), its sessions are deleted, and this hub refuses
//! S2S requests acting for it (`UNAUTHORIZED`, `client_code`
//! `user_not_admitted`). Every enforcement point asks
//! [`UserPolicy::admitted`]; the policy in force is replaced on every
//! settings reload ([`crate::settings::install`]).

use std::{
    collections::BTreeSet,
    str::FromStr,
    sync::{Arc, PoisonError, RwLock},
};

use gim_hub_db::{
    user_policy::{self as db, NotAdmitted},
    Db, DbError,
};
use gim_hub_identity::UserId;

/// The setting that selects the mode.
pub const MODE_KEY: &str = "GIM_HUB_USER_POLICY";

/// The policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Every user is admitted; the list is not enforced (the default).
    #[default]
    Open,
    /// Only listed users are admitted.
    Allow,
    /// Every user except the listed ones is admitted.
    Deny,
}

impl Mode {
    /// The setting's values.
    pub const CHOICES: &'static [&'static str] = &["open", "allow", "deny"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, String> {
        match raw.trim() {
            "open" => Ok(Self::Open),
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(format!("expected one of {}", Self::CHOICES.join(", "))),
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a user is admitted under `mode`, given whether it is listed.
pub fn admitted(mode: Mode, listed: bool) -> bool {
    match mode {
        Mode::Open => true,
        Mode::Allow => listed,
        Mode::Deny => !listed,
    }
}

/// The policy in force: the mode and the listed user IDs.
#[derive(Debug, Default)]
pub struct UserPolicy {
    current: RwLock<(Mode, Arc<BTreeSet<String>>)>,
}

impl UserPolicy {
    /// A policy in `mode` with an empty list.
    pub fn new(mode: Mode) -> Self {
        Self {
            current: RwLock::new((mode, Arc::default())),
        }
    }

    /// Whether `user_id` is admitted ([`admitted`]).
    pub fn admitted(&self, user_id: &str) -> bool {
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        admitted(current.0, current.1.contains(user_id))
    }

    pub fn mode(&self) -> Mode {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }

    /// Puts `mode` and `list` in force; returns whether either changed.
    pub fn set(&self, mode: Mode, list: BTreeSet<String>) -> bool {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if current.0 == mode && *current.1 == list {
            return false;
        }
        *current = (mode, Arc::new(list));
        true
    }
}

/// `raw` as a user ID, with the user ID parser.
pub fn parse_user_id(raw: &str) -> Result<String, String> {
    UserId::parse(raw.trim())
        .map(|user_id| user_id.to_string())
        .map_err(|err| format!("invalid user ID {:?}: {err}", raw.trim()))
}

/// Parses a whole list: one user ID per line; `#` starts a comment, blank
/// lines are skipped. Returns the distinct user IDs in order of appearance,
/// or `line N: reason` for the first invalid line.
pub fn parse_list(text: &str) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut user_ids = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line
            .split_once('#')
            .map_or(line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        let user_id =
            parse_user_id(line).map_err(|reason| format!("line {}: {reason}", index + 1))?;
        if seen.insert(user_id.clone()) {
            user_ids.push(user_id);
        }
    }
    Ok(user_ids)
}

/// A handle as typed by an admin (`@alice`, ` Alice `) as stored (`alice`).
pub fn handle_name(raw: &str) -> String {
    raw.trim().trim_start_matches('@').to_ascii_lowercase()
}

/// The number of users of this hub not admitted under `mode`.
pub async fn count_not_admitted(db: &Db, mode: Mode) -> Result<i64, DbError> {
    let which = match mode {
        Mode::Open => return Ok(0),
        Mode::Allow => NotAdmitted::Unlisted,
        Mode::Deny => NotAdmitted::Listed,
    };
    db.read(move |conn| db::count_not_admitted(conn, which))
        .await
}

/// Deletes the sessions and pending sign-in challenges of every user not
/// admitted under `mode` (and the stored list), as a suspension does.
/// Returns the number of sessions deleted.
pub async fn revoke_not_admitted(db: &Db, mode: Mode) -> Result<usize, DbError> {
    let which = match mode {
        Mode::Open => return Ok(0),
        Mode::Allow => NotAdmitted::Unlisted,
        Mode::Deny => NotAdmitted::Listed,
    };
    db.write(move |tx| db::revoke_not_admitted(tx, which)).await
}

/// Logs a warning when `mode` with `listed` users admits nobody.
pub fn warn_if_nobody_admitted(mode: Mode, listed: usize) {
    if mode == Mode::Allow && listed == 0 {
        tracing::warn!("{MODE_KEY}=allow with an empty user list: no user is admitted on this hub");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa";

    #[test]
    fn modes_parse_and_admit() {
        assert_eq!("allow".parse::<Mode>(), Ok(Mode::Allow));
        assert_eq!(" deny ".parse::<Mode>(), Ok(Mode::Deny));
        assert_eq!(Mode::default(), Mode::Open);
        assert_eq!(
            "closed".parse::<Mode>(),
            Err("expected one of open, allow, deny".to_owned())
        );
        for listed in [false, true] {
            assert!(admitted(Mode::Open, listed));
            assert_eq!(admitted(Mode::Allow, listed), listed);
            assert_eq!(admitted(Mode::Deny, listed), !listed);
        }
    }

    #[test]
    fn policy_in_force_is_replaced() {
        let policy = UserPolicy::default();
        assert!(policy.admitted(ALICE));
        assert!(policy.set(Mode::Allow, BTreeSet::new()));
        assert!(
            !policy.admitted(ALICE),
            "allow with an empty list admits nobody"
        );
        let list: BTreeSet<_> = [ALICE.to_owned()].into();
        assert!(policy.set(Mode::Allow, list.clone()));
        assert!(!policy.set(Mode::Allow, list.clone()));
        assert!(policy.admitted(ALICE));
        assert!(policy.set(Mode::Deny, list));
        assert!(!policy.admitted(ALICE));
        assert!(policy.admitted("someone-else"));
        assert_eq!(policy.mode(), Mode::Deny);
    }

    #[test]
    fn list_text_with_comments_blank_lines_and_errors() {
        let text = format!("# admitted users\n\n{ALICE}  # alice\n   \n{ALICE}\n");
        assert_eq!(parse_list(&text).unwrap(), [ALICE]);
        assert!(parse_list("").unwrap().is_empty());
        let err = parse_list(&format!("{ALICE}\n# ok\nnot-a-user\n")).unwrap_err();
        assert!(
            err.starts_with("line 3: invalid user ID \"not-a-user\""),
            "{err}"
        );
        assert!(parse_user_id(ALICE).is_ok());
        assert!(parse_user_id("@alice").is_err());
        assert_eq!(handle_name(" @Alice_1 "), "alice_1");
    }
}
