//! The user list of the hub's user policy (docs/operations.md, "User
//! policy"), table `user_policy_list`.
//!
//! Every write bumps the settings version ([`crate::settings::version`]), so a
//! running hub picks up changes made by another process (`gim-hub config
//! users`), as for the stored allowlist.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::{settings::bump_version, DbError};

/// A listed user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub user_id: String,
    /// ms since the Unix epoch.
    pub added_at: i64,
    /// `token`, `header:<id>` or `cli`.
    pub added_by: String,
    pub note: Option<String>,
}

/// A listed user with the handle it has on this hub, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedUser {
    pub entry: ListEntry,
    pub handle: Option<String>,
}

/// Every listed user with its handle, by user ID.
pub fn load(conn: &Connection) -> Result<Vec<ListedUser>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT l.user_id, l.added_at, l.added_by, l.note, h.handle \
         FROM user_policy_list l LEFT JOIN handles h ON h.user_id = l.user_id \
         ORDER BY l.user_id",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ListedUser {
                entry: ListEntry {
                    user_id: row.get(0)?,
                    added_at: row.get(1)?,
                    added_by: row.get(2)?,
                    note: row.get(3)?,
                },
                handle: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The listed user IDs, sorted.
pub fn user_ids(conn: &Connection) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare_cached("SELECT user_id FROM user_policy_list ORDER BY user_id")?;
    let rows = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Whether `user_id` is listed.
pub fn contains(conn: &Connection, user_id: &str) -> Result<bool, DbError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM user_policy_list WHERE user_id = ?1",
            [user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Replaces the list with `entries` and bumps the version.
pub fn replace(tx: &Transaction<'_>, entries: &[ListEntry]) -> Result<(), DbError> {
    tx.execute("DELETE FROM user_policy_list", [])?;
    let mut stmt = tx.prepare_cached(
        "INSERT OR REPLACE INTO user_policy_list (user_id, added_at, added_by, note) \
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for entry in entries {
        stmt.execute(params![
            entry.user_id,
            entry.added_at,
            entry.added_by,
            entry.note
        ])?;
    }
    bump_version(tx)
}

/// Adds `entry` and bumps the version; `false` (nothing changed) if the
/// user is already listed.
pub fn add(tx: &Transaction<'_>, entry: &ListEntry) -> Result<bool, DbError> {
    let added = tx.execute(
        "INSERT OR IGNORE INTO user_policy_list (user_id, added_at, added_by, note) \
         VALUES (?1, ?2, ?3, ?4)",
        params![entry.user_id, entry.added_at, entry.added_by, entry.note],
    )? > 0;
    if added {
        bump_version(tx)?;
    }
    Ok(added)
}

/// Removes `user_id` and bumps the version; `false` if it was not listed.
pub fn remove(tx: &Transaction<'_>, user_id: &str) -> Result<bool, DbError> {
    let removed = tx.execute("DELETE FROM user_policy_list WHERE user_id = ?1", [user_id])? > 0;
    if removed {
        bump_version(tx)?;
    }
    Ok(removed)
}

/// Which users are not admitted, for [`revoke_not_admitted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAdmitted {
    /// The listed users (deny mode).
    Listed,
    /// Every user that is not listed (allow mode).
    Unlisted,
}

/// The number of users of this hub that are not admitted.
pub fn count_not_admitted(conn: &Connection, which: NotAdmitted) -> Result<i64, DbError> {
    let filter = match which {
        NotAdmitted::Listed => "IN",
        NotAdmitted::Unlisted => "NOT IN",
    };
    Ok(conn.query_row(
        &format!(
            "SELECT count(*) FROM users WHERE user_id {filter} \
             (SELECT user_id FROM user_policy_list)"
        ),
        [],
        |row| row.get(0),
    )?)
}

/// Deletes the sessions and pending sign-in challenges of the users that
/// are not admitted, as a suspension does. Returns the number of sessions
/// deleted.
pub fn revoke_not_admitted(tx: &Transaction<'_>, which: NotAdmitted) -> Result<usize, DbError> {
    let filter = match which {
        NotAdmitted::Listed => "user_id IN (SELECT user_id FROM user_policy_list)",
        NotAdmitted::Unlisted => "user_id NOT IN (SELECT user_id FROM user_policy_list)",
    };
    let sessions = tx.execute(&format!("DELETE FROM sessions WHERE {filter}"), [])?;
    tx.execute(&format!("DELETE FROM auth_challenges WHERE {filter}"), [])?;
    Ok(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{self, Challenge, Session},
        settings::version,
        users::{self, Device, StoredDeviceList},
        Db,
    };

    fn entry(user_id: &str, note: Option<&str>) -> ListEntry {
        ListEntry {
            user_id: user_id.into(),
            added_at: 1_000,
            added_by: "token".into(),
            note: note.map(Into::into),
        }
    }

    #[tokio::test]
    async fn add_remove_replace_bump_the_version() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.read(load).await.unwrap().is_empty());
        assert!(db
            .write(|tx| add(tx, &entry("u-b", Some("spam"))))
            .await
            .unwrap());
        assert!(!db.write(|tx| add(tx, &entry("u-b", None))).await.unwrap());
        assert!(db.write(|tx| add(tx, &entry("u-a", None))).await.unwrap());
        assert_eq!(db.read(version).await.unwrap(), 2);
        assert_eq!(db.read(user_ids).await.unwrap(), ["u-a", "u-b"]);
        let loaded = db.read(load).await.unwrap();
        assert_eq!(loaded[1].entry, entry("u-b", Some("spam")));
        assert_eq!(loaded[1].handle, None);
        assert!(db.read(|conn| contains(conn, "u-a")).await.unwrap());
        assert!(!db.read(|conn| contains(conn, "u-c")).await.unwrap());

        assert!(db.write(|tx| remove(tx, "u-a")).await.unwrap());
        assert!(!db.write(|tx| remove(tx, "u-a")).await.unwrap());
        assert_eq!(db.read(version).await.unwrap(), 3);
        db.write(|tx| replace(tx, &[entry("u-c", None), entry("u-d", None)]))
            .await
            .unwrap();
        assert_eq!(db.read(user_ids).await.unwrap(), ["u-c", "u-d"]);
        assert_eq!(db.read(version).await.unwrap(), 4);
    }

    #[tokio::test]
    async fn sessions_and_challenges_of_not_admitted_users_are_revoked() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for (i, user) in ["u-listed", "u-other"].into_iter().enumerate() {
                users::put_device_list(
                    tx,
                    &StoredDeviceList {
                        user_id: user.into(),
                        root_pubkey: vec![0; 32],
                        device_list: Vec::new(),
                        seq: 0,
                        updated_at: 1,
                    },
                )?;
                users::put_device(
                    tx,
                    &Device {
                        user_id: user.into(),
                        device_id: "d1".into(),
                        sig_pubkey: vec![0; 32],
                        active: true,
                    },
                    1,
                )?;
                auth::create_session(
                    tx,
                    &[u8::try_from(i).unwrap(); 32],
                    &Session {
                        user_id: user.into(),
                        device_id: "d1".into(),
                        expires_at: 10_000,
                    },
                    1,
                )?;
                auth::insert_challenge(
                    tx,
                    &Challenge {
                        challenge_id: user.into(),
                        user_id: user.into(),
                        device_id: "d1".into(),
                        challenge: vec![1],
                        expires_at: 10_000,
                    },
                    1,
                )?;
            }
            add(tx, &entry("u-listed", None))?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let remaining = || {
            db.read(|conn| {
                let users = |table: &str| -> Result<Vec<String>, DbError> {
                    let mut stmt =
                        conn.prepare(&format!("SELECT user_id FROM {table} ORDER BY user_id"))?;
                    let rows = stmt
                        .query_map([], |row| row.get(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                };
                Ok::<_, DbError>((users("sessions")?, users("auth_challenges")?))
            })
        };
        let revoked = db
            .write(|tx| revoke_not_admitted(tx, NotAdmitted::Unlisted))
            .await
            .unwrap();
        assert_eq!(revoked, 1);
        let (sessions, challenges) = remaining().await.unwrap();
        assert_eq!(
            (sessions, challenges),
            (vec!["u-listed".to_owned()], vec!["u-listed".to_owned()])
        );
        let revoked = db
            .write(|tx| revoke_not_admitted(tx, NotAdmitted::Listed))
            .await
            .unwrap();
        assert_eq!(revoked, 1);
        let (sessions, challenges) = remaining().await.unwrap();
        assert!(sessions.is_empty() && challenges.is_empty());
        let count = |which| db.read(move |conn| count_not_admitted(conn, which));
        assert_eq!(count(NotAdmitted::Listed).await.unwrap(), 1);
        assert_eq!(count(NotAdmitted::Unlisted).await.unwrap(), 1);
    }
}
