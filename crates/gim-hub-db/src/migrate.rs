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
    include_str!("../migrations/0005_group_federation.sql"),
    include_str!("../migrations/0006_push_webpush_keys.sql"),
    include_str!("../migrations/0007_multihoming.sql"),
    include_str!("../migrations/0008_replica_detached_at.sql"),
    include_str!("../migrations/0009_message_proposal.sql"),
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
                "commit_membership",
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
                "pending_proposals",
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

    #[tokio::test]
    async fn multihoming_migration_keeps_queued_outbox_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let multihoming = super::MIGRATIONS
            .iter()
            .position(|sql| sql.contains("s2s_outbox_new"))
            .unwrap();
        {
            // A database just before the migration, with queued entries.
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            for (version, sql) in (1..).zip(&super::MIGRATIONS[..multihoming]) {
                let tx = conn.transaction().unwrap();
                tx.execute_batch(sql).unwrap();
                tx.pragma_update(None, "user_version", version).unwrap();
                tx.commit().unwrap();
            }
            conn.execute_batch(
                "INSERT INTO s2s_outbox (id, peer_hub_id, kind, gid, seq, size, created_at, \
                 expires_at, attempts) VALUES (7, 'h1', 'deliver', 'h0/g', 3, 10, 1, 100, 2); \
                 INSERT INTO s2s_outbox (id, peer_hub_id, kind, user_id, size, created_at, \
                 expires_at) VALUES (9, 'h1', 'device_list', 'u1', 2, 1, 100); \
                 INSERT INTO hosting_records (user_id, record, seq, expires_at, hosted, hub_ids, \
                 fetched_at, updated_at) VALUES ('u1', x'00', 1, 100, 0, '[]', 1, 1);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let entries = db
            .read(|conn| crate::outbox::head(conn, "h1", 0, 10))
            .await
            .unwrap();
        let summary: Vec<_> = entries
            .iter()
            .map(|e| {
                (
                    e.id,
                    e.kind,
                    e.gid.clone(),
                    e.seq,
                    e.user_id.clone(),
                    e.attempts,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    7,
                    crate::outbox::Kind::Deliver,
                    Some("h0/g".to_owned()),
                    Some(3),
                    None,
                    2
                ),
                (
                    9,
                    crate::outbox::Kind::DeviceList,
                    None,
                    None,
                    Some("u1".to_owned()),
                    0
                ),
            ]
        );
        assert_eq!(
            db.read(|conn| crate::hosting::removed_at(conn, "u1"))
                .await
                .unwrap(),
            None
        );
        // New kinds are accepted, ids continue after the copied ones, and
        // the indexes were recreated (dedup per kind).
        let limits = crate::outbox::Limits {
            ttl_ms: 1_000,
            max_entries: 100,
            max_bytes: 1_000,
        };
        let (first, again, deliver) = db
            .write(move |tx| {
                use crate::outbox::{enqueue, NewEntry};
                let first = enqueue(
                    tx,
                    "h1",
                    NewEntry::HostingRecord { user_id: "u1" },
                    &limits,
                    5,
                )?;
                let id = tx.last_insert_rowid();
                let again = enqueue(
                    tx,
                    "h1",
                    NewEntry::HostingRecord { user_id: "u1" },
                    &limits,
                    5,
                )?;
                let deliver = enqueue(
                    tx,
                    "h1",
                    NewEntry::Deliver {
                        gid: "h0/g",
                        seq: 3,
                        size: 10,
                    },
                    &limits,
                    5,
                )?;
                assert!(id > 9);
                Ok::<_, DbError>((first.queued, again.queued, deliver.queued))
            })
            .await
            .unwrap();
        assert_eq!((first, again, deliver), (true, false, false));
        let indexes: Vec<String> = db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'index' \
                     AND tbl_name = 's2s_outbox' ORDER BY name",
                )?;
                let names = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DbError>(names)
            })
            .await
            .unwrap();
        assert_eq!(
            indexes,
            [
                "s2s_outbox_deliver",
                "s2s_outbox_device_list",
                "s2s_outbox_expires_at",
                "s2s_outbox_hosting_record",
                "s2s_outbox_peer",
                "s2s_outbox_pending_welcomes",
            ]
        );
    }

    #[tokio::test]
    async fn detached_replicas_get_a_detach_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let detached_at = super::MIGRATIONS
            .iter()
            .position(|sql| sql.contains("detached_at"))
            .unwrap();
        {
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            for (version, sql) in (1..).zip(&super::MIGRATIONS[..detached_at]) {
                let tx = conn.transaction().unwrap();
                tx.execute_batch(sql).unwrap();
                tx.pragma_update(None, "user_version", version).unwrap();
                tx.commit().unwrap();
            }
            conn.execute_batch(
                "INSERT INTO groups (gid, kind, created_by_user_id, created_by_device_id, \
                 created_at, replica_from_seq, detached) VALUES \
                 ('h2/a', 'group', 'u', 'd', 0, 1, 1), ('h2/b', 'group', 'u', 'd', 0, 1, 0);",
            )
            .unwrap();
        }
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let db = Db::open(&path).unwrap();
        let rows: Vec<(String, Option<i64>)> = db
            .read(|conn| {
                let mut stmt = conn.prepare("SELECT gid, detached_at FROM groups ORDER BY gid")?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, DbError>(rows)
            })
            .await
            .unwrap();
        assert_eq!(rows[0].0, "h2/a");
        let at = rows[0].1.unwrap();
        assert!((before - 60_000..before + 60_000).contains(&at), "{at}");
        assert_eq!(rows[1], ("h2/b".to_owned(), None));
    }

    #[tokio::test]
    async fn proposal_migration_keeps_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let proposal = super::MIGRATIONS
            .iter()
            .position(|sql| sql.contains("messages_new"))
            .unwrap();
        {
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            for (version, sql) in (1..).zip(&super::MIGRATIONS[..proposal]) {
                let tx = conn.transaction().unwrap();
                tx.execute_batch(sql).unwrap();
                tx.pragma_update(None, "user_version", version).unwrap();
                tx.commit().unwrap();
            }
            conn.execute_batch(
                "INSERT INTO groups (gid, kind, epoch, last_seq, created_by_user_id, \
                 created_by_device_id, created_at) VALUES ('h1/g', 'group', 1, 2, 'u', 'd', 0); \
                 INSERT INTO messages (gid, seq, epoch, kind, sender_user_id, sender_device_id, \
                 client_id, payload, commit_hash, message_id, created_at) VALUES \
                 ('h1/g', 1, 0, 'commit', 'u', 'd', 'c1', x'01', x'aa', 'm1', 5), \
                 ('h1/g', 2, 1, 'application', 'u', 'd', 'c2', x'02', NULL, 'm2', 6);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let listed = db
            .read(|conn| crate::messages::list_from(conn, "h1/g", 1, 10))
            .await
            .unwrap();
        let summary: Vec<_> = listed
            .iter()
            .map(|m| (m.seq, m.kind.as_str(), m.message_id.as_str()))
            .collect();
        assert_eq!(summary, [(1, "commit", "m1"), (2, "application", "m2")]);
        assert_eq!(
            db.read(|conn| crate::messages::find_commit(conn, "h1/g", &[0xaa]))
                .await
                .unwrap(),
            Some((1, 0, "commit".to_owned()))
        );
        // Proposals are accepted, the constraints and the cascade kept.
        let result = db
            .write(|tx| {
                tx.execute(
                    "INSERT INTO messages (gid, seq, epoch, kind, sender_user_id, \
                     sender_device_id, client_id, payload, message_id, created_at) VALUES \
                     ('h1/g', 3, 1, 'proposal', 'u', 'd', 'c3', x'03', 'm3', 7)",
                    [],
                )?;
                let duplicate = tx.execute(
                    "INSERT INTO messages (gid, seq, epoch, kind, sender_user_id, \
                     sender_device_id, client_id, payload, message_id, created_at) VALUES \
                     ('h1/g', 4, 1, 'proposal', 'u', 'd', 'c3', x'04', 'm4', 7)",
                    [],
                );
                assert!(duplicate.is_err());
                tx.execute("DELETE FROM groups WHERE gid = 'h1/g'", [])?;
                let left: i64 = tx.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
                Ok::<_, DbError>(left)
            })
            .await
            .unwrap();
        assert_eq!(result, 0);
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
