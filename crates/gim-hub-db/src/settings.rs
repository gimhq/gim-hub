//! Stored settings and the stored federation allowlist (docs/operations.md,
//! "Stored settings").
//!
//! Every write bumps [`version`], which a running hub polls to pick up
//! changes made by another process (`gim-hub config`).

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

const VERSION_KEY: &str = "settings_version";

/// A stored setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSetting {
    pub key: String,
    /// The JSON value.
    pub value: String,
    /// ms since the Unix epoch.
    pub updated_at: i64,
    /// `token`, `header:<id>` or `cli`.
    pub updated_by: String,
}

/// Every stored setting, by key.
pub fn list(conn: &Connection) -> Result<Vec<StoredSetting>, DbError> {
    let mut stmt = conn
        .prepare_cached("SELECT key, value, updated_at, updated_by FROM settings ORDER BY key")?;
    let rows = stmt
        .query_map([], |row| {
            Ok(StoredSetting {
                key: row.get(0)?,
                value: row.get(1)?,
                updated_at: row.get(2)?,
                updated_by: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Stores `setting`, replacing any previous value, and bumps the version.
pub fn put(tx: &Transaction<'_>, setting: &StoredSetting) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value, \
         updated_at = excluded.updated_at, updated_by = excluded.updated_by",
        params![
            setting.key,
            setting.value,
            setting.updated_at,
            setting.updated_by
        ],
    )?;
    bump_version(tx)
}

/// Deletes the stored value of `key` and bumps the version; returns whether
/// one existed.
pub fn delete(tx: &Transaction<'_>, key: &str) -> Result<bool, DbError> {
    let deleted = tx.execute("DELETE FROM settings WHERE key = ?1", [key])? > 0;
    bump_version(tx)?;
    Ok(deleted)
}

/// The stored allowlist: `(hub_id, static multiaddrs)` by hub ID.
pub fn allowlist(conn: &Connection) -> Result<Vec<(String, Vec<String>)>, DbError> {
    let mut stmt =
        conn.prepare_cached("SELECT hub_id, addrs FROM federation_allowlist ORDER BY hub_id")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(hub_id, addrs)| {
            let addrs = serde_json::from_str(&addrs).map_err(|err| {
                DbError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                ))
            })?;
            Ok((hub_id, addrs))
        })
        .collect()
}

/// Replaces the stored allowlist with `entries` and bumps the version.
pub fn replace_allowlist(
    tx: &Transaction<'_>,
    entries: &[(String, Vec<String>)],
) -> Result<(), DbError> {
    tx.execute("DELETE FROM federation_allowlist", [])?;
    let mut stmt =
        tx.prepare_cached("INSERT INTO federation_allowlist (hub_id, addrs) VALUES (?1, ?2)")?;
    for (hub_id, addrs) in entries {
        stmt.execute(params![
            hub_id,
            serde_json::Value::from(addrs.clone()).to_string()
        ])?;
    }
    bump_version(tx)
}

/// The settings version: changes with every write to the settings or the
/// stored allowlist.
pub fn version(conn: &Connection) -> Result<i64, DbError> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
            [VERSION_KEY],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.unwrap_or(0))
}

pub(crate) fn bump_version(tx: &Transaction<'_>) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, '1') \
         ON CONFLICT (key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
        [VERSION_KEY],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    fn setting(key: &str, value: &str) -> StoredSetting {
        StoredSetting {
            key: key.into(),
            value: value.into(),
            updated_at: 1_000,
            updated_by: "cli".into(),
        }
    }

    #[tokio::test]
    async fn put_replace_delete_bump_the_version() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.read(version).await.unwrap(), 0);
        db.write(|tx| put(tx, &setting("GIM_HUB_B", "1")))
            .await
            .unwrap();
        db.write(|tx| put(tx, &setting("GIM_HUB_A", "true")))
            .await
            .unwrap();
        db.write(|tx| put(tx, &setting("GIM_HUB_B", "2")))
            .await
            .unwrap();
        let rows = db.read(list).await.unwrap();
        assert_eq!(
            rows,
            [setting("GIM_HUB_A", "true"), setting("GIM_HUB_B", "2")]
        );
        assert_eq!(db.read(version).await.unwrap(), 3);
        assert!(db.write(|tx| delete(tx, "GIM_HUB_A")).await.unwrap());
        assert!(!db.write(|tx| delete(tx, "GIM_HUB_A")).await.unwrap());
        assert_eq!(db.read(list).await.unwrap(), [setting("GIM_HUB_B", "2")]);
        assert_eq!(db.read(version).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn allowlist_is_replaced_as_a_whole() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.read(allowlist).await.unwrap().is_empty());
        let first = vec![
            ("hb".to_owned(), vec![]),
            (
                "ha".to_owned(),
                vec!["/dns4/a.example.eu/tcp/4001".to_owned()],
            ),
        ];
        let entries = first.clone();
        db.write(move |tx| replace_allowlist(tx, &entries))
            .await
            .unwrap();
        let mut sorted = first;
        sorted.sort();
        assert_eq!(db.read(allowlist).await.unwrap(), sorted);
        db.write(|tx| replace_allowlist(tx, &[("hc".to_owned(), vec![])]))
            .await
            .unwrap();
        assert_eq!(
            db.read(allowlist).await.unwrap(),
            [("hc".to_owned(), vec![])]
        );
        assert_eq!(db.read(version).await.unwrap(), 2);
    }
}
