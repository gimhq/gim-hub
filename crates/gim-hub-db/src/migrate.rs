//! Embedded, ordered schema migrations tracked in `PRAGMA user_version`.

use rusqlite::Connection;

use crate::DbError;

/// Migration `i` upgrades `user_version` from `i` to `i + 1`. Never edit a
/// released migration; append a new one.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_hosting.sql"),
    include_str!("../migrations/0003_remote_identity.sql"),
    include_str!("../migrations/0004_outbox.sql"),
];

/// Schema version after all migrations.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

pub(crate) fn run(conn: &mut Connection) -> Result<(), DbError> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(DbError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    for (version, sql) in (1..).zip(MIGRATIONS).skip(current as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Db, DbError, SCHEMA_VERSION};

    fn user_version(conn: &rusqlite::Connection) -> Result<i64, DbError> {
        Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    #[tokio::test]
    async fn fresh_database_gets_full_schema() {
        let db = Db::open_in_memory().unwrap();
        let (version, tables) = db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table' \
                     AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )?;
                let tables = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DbError>((user_version(conn)?, tables))
            })
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(
            tables,
            [
                "auth_challenges",
                "blobs",
                "devices",
                "events",
                "group_members",
                "groups",
                "handles",
                "hosting_records",
                "key_packages",
                "link_bundles",
                "messages",
                "meta",
                "pending_welcomes",
                "push_registrations",
                "recovery_backups",
                "remote_device_lists",
                "remote_kp_claims",
                "s2s_outbox",
                "s2s_peers",
                "sessions",
                "users",
            ]
        );
    }

    #[tokio::test]
    async fn reopening_a_file_database_keeps_data_and_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/hub.db");
        {
            let db = Db::open(&path).unwrap();
            db.write(|tx| {
                tx.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])?;
                Ok::<_, DbError>(())
            })
            .await
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let (version, journal, fk, value) = db
            .read(|conn| {
                let journal: String =
                    conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
                let fk: bool = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
                let value: String =
                    conn.query_row("SELECT value FROM meta WHERE key = 'k'", [], |row| {
                        row.get(0)
                    })?;
                Ok::<_, DbError>((user_version(conn)?, journal, fk, value))
            })
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(journal, "wal");
        assert!(fk);
        assert_eq!(value, "v");
    }

    #[test]
    fn newer_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        drop(conn);
        assert!(matches!(Db::open(&path), Err(DbError::SchemaTooNew { .. })));
    }
}
