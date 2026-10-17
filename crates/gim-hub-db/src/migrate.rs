//! Embedded, ordered schema migrations tracked in `PRAGMA user_version`.

use std::{io, path::Path, time::SystemTime};

use rusqlite::{Connection, OpenFlags, MAIN_DB};

use crate::{Backups, DbError};

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
    include_str!("../migrations/0010_remote_blobs.sql"),
    include_str!("../migrations/0011_push_opaque_provider.sql"),
    include_str!("../migrations/0012_admin.sql"),
];

/// Schema version after all migrations.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

/// Pre-migration backups kept by [`Db::open_with_backups`](crate::Db::open_with_backups).
const KEEP_BACKUPS: usize = 3;

/// Fails if the database file at `path` has a newer schema than this
/// binary knows. Opens it read-only, so nothing is written.
pub(crate) fn check_supported(path: &Path) -> Result<(), DbError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    ensure_supported(user_version(&conn)?)
}

fn user_version(conn: &Connection) -> Result<i64, DbError> {
    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

fn ensure_supported(current: i64) -> Result<(), DbError> {
    if current > SCHEMA_VERSION {
        return Err(DbError::SchemaTooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Applies pending migrations; an existing database (schema above 0) is
/// first copied to `backups`, if given.
pub(crate) fn run(conn: &mut Connection, backups: Option<&Backups>) -> Result<(), DbError> {
    let current = user_version(conn)?;
    ensure_supported(current)?;
    if let Some(backups) = backups.filter(|_| current > 0 && current < SCHEMA_VERSION) {
        backup(conn, current, backups)?;
    }
    for (version, sql) in (1..).zip(MIGRATIONS).skip(current as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}

/// Copies the database to `<dir>/hub-<from>-<release>.db` with SQLite's
/// online backup, then prunes all but the newest [`KEEP_BACKUPS`].
fn backup(conn: &Connection, from: i64, backups: &Backups) -> Result<(), DbError> {
    let release: String = backups
        .release
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '+' | '_' => c,
            _ => '_',
        })
        .collect();
    let path = backups.dir.join(format!("hub-{from}-{release}.db"));
    let fail = |err: &dyn std::fmt::Display| DbError::Backup(format!("{}: {err}", path.display()));
    std::fs::create_dir_all(&backups.dir).map_err(|err| fail(&err))?;
    let tmp = path.with_extension("db.tmp");
    match std::fs::remove_file(&tmp) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(fail(&err)),
        _ => {}
    }
    conn.backup(MAIN_DB, &tmp, None).map_err(|err| fail(&err))?;
    std::fs::rename(&tmp, &path).map_err(|err| fail(&err))?;
    prune_backups(&backups.dir, KEEP_BACKUPS).map_err(|err| fail(&err))
}

/// Deletes all but the `keep` newest (by modification time, then name)
/// `hub-*.db` files in `dir`.
fn prune_backups(dir: &Path, keep: usize) -> io::Result<()> {
    let mut files: Vec<(SystemTime, String)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with("hub-") && name.ends_with(".db") {
            files.push((entry.metadata()?.modified()?, name));
        }
    }
    files.sort_unstable_by(|a, b| b.cmp(a));
    for (_, name) in files.into_iter().skip(keep) {
        std::fs::remove_file(dir.join(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{Backups, Db, DbError, SCHEMA_VERSION};

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
                "admin_audit",
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
                "remote_blobs",
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

    #[tokio::test]
    async fn opaque_provider_migration_keeps_registrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let opaque = super::MIGRATIONS
            .iter()
            .position(|sql| sql.contains("push_registrations_new"))
            .unwrap();
        {
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            for (version, sql) in (1..).zip(&super::MIGRATIONS[..opaque]) {
                let tx = conn.transaction().unwrap();
                tx.execute_batch(sql).unwrap();
                tx.pragma_update(None, "user_version", version).unwrap();
                tx.commit().unwrap();
            }
            conn.execute_batch(
                "INSERT INTO users (user_id, root_pubkey, device_list, device_list_seq, \
                 created_at, updated_at) VALUES ('u', x'00', x'', 0, 0, 0); \
                 INSERT INTO devices (user_id, device_id, sig_pubkey, active, updated_at) VALUES \
                 ('u', 'd1', x'00', 1, 0), ('u', 'd2', x'00', 1, 0), \
                 ('u', 'd3', x'00', 1, 0), ('u', 'd4', x'00', 1, 0); \
                 INSERT INTO push_registrations (user_id, device_id, provider, token, app_id, \
                 sandbox, updated_at, p256dh, auth) VALUES \
                 ('u', 'd1', 'apns', 'ab', 'im.g.apps', 1, 1, NULL, NULL), \
                 ('u', 'd2', 'fcm', 'f', NULL, 0, 2, NULL, NULL), \
                 ('u', 'd3', 'unifiedpush', 'https://up.example.eu/x', NULL, 0, 3, x'04', x'01'), \
                 ('u', 'd4', 'log', 'l', NULL, 0, 4, NULL, NULL);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let get =
            |device: &'static str| db.read(move |conn| crate::push::get_active(conn, "u", device));
        let apns = get("d1").await.unwrap().unwrap();
        assert_eq!(
            (apns.provider.as_str(), apns.token.as_str(), apns.sandbox),
            ("apns", "ab", Some(true))
        );
        assert_eq!(apns.app_id.as_deref(), Some("im.g.apps"));
        assert_eq!(get("d2").await.unwrap().unwrap().provider, "fcm");
        let up = get("d3").await.unwrap().unwrap();
        assert_eq!(up.provider, "unifiedpush");
        assert_eq!((up.p256dh, up.auth), (Some(vec![4]), Some(vec![1])));
        assert_eq!(get("d4").await.unwrap().unwrap().sandbox, Some(false));

        // Opaque providers and an absent sandbox are accepted; the device
        // foreign key and its cascade are kept.
        let left = db
            .write(|tx| {
                tx.execute(
                    "INSERT OR REPLACE INTO push_registrations (user_id, device_id, provider, \
                     token, updated_at) VALUES ('u', 'd1', 'acme.push-2', 't', 5)",
                    [],
                )?;
                assert!(tx
                    .execute(
                        "INSERT INTO push_registrations (user_id, device_id, provider, token, \
                         updated_at) VALUES ('u', 'd9', 'x', 't', 5)",
                        [],
                    )
                    .is_err());
                tx.execute("DELETE FROM devices WHERE device_id = 'd2'", [])?;
                let left: i64 =
                    tx.query_row("SELECT count(*) FROM push_registrations", [], |r| r.get(0))?;
                Ok::<_, DbError>(left)
            })
            .await
            .unwrap();
        assert_eq!(left, 3);
        let custom = get("d1").await.unwrap().unwrap();
        assert_eq!(
            (custom.provider.as_str(), custom.sandbox),
            ("acme.push-2", None)
        );
    }

    #[tokio::test]
    async fn admin_migration_backfills_device_creation_times() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let admin = super::MIGRATIONS
            .iter()
            .position(|sql| sql.contains("admin_audit"))
            .unwrap();
        {
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            for (version, sql) in (1..).zip(&super::MIGRATIONS[..admin]) {
                let tx = conn.transaction().unwrap();
                tx.execute_batch(sql).unwrap();
                tx.pragma_update(None, "user_version", version).unwrap();
                tx.commit().unwrap();
            }
            conn.execute_batch(
                "INSERT INTO users (user_id, root_pubkey, device_list, device_list_seq, \
                 created_at, updated_at) VALUES ('u', x'00', x'', 0, 0, 0); \
                 INSERT INTO devices (user_id, device_id, sig_pubkey, active, updated_at) VALUES \
                 ('u', 'd1', x'00', 1, 42);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let (created_at, suspended_at) = db
            .read(|conn| {
                Ok::<_, DbError>(conn.query_row(
                    "SELECT d.created_at, u.suspended_at FROM devices d \
                     JOIN users u ON u.user_id = d.user_id",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!((created_at, suspended_at), (42, None));
    }

    /// Creates a file database at schema `version` holding one `meta` row.
    fn database_at(path: &std::path::Path, version: usize) {
        let mut conn = rusqlite::Connection::open(path).unwrap();
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))
            .unwrap();
        for (v, sql) in (1..).zip(&super::MIGRATIONS[..version]) {
            let tx = conn.transaction().unwrap();
            tx.execute_batch(sql).unwrap();
            tx.pragma_update(None, "user_version", v).unwrap();
            tx.commit().unwrap();
        }
        conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])
            .unwrap();
    }

    fn backups(dir: &std::path::Path, release: &str) -> Backups {
        Backups {
            dir: dir.join("backups"),
            release: release.into(),
        }
    }

    fn file_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn existing_database_is_backed_up_before_migrating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let from = SCHEMA_VERSION as usize - 1;
        database_at(&path, from);
        let db = Db::open_with_backups(&path, &backups(dir.path(), "0.2.0")).unwrap();
        assert_eq!(db.read(user_version).await.unwrap(), SCHEMA_VERSION);
        drop(db);

        let name = format!("hub-{from}-0.2.0.db");
        assert_eq!(
            file_names(&dir.path().join("backups")),
            std::slice::from_ref(&name)
        );
        let copy = rusqlite::Connection::open(dir.path().join("backups").join(name)).unwrap();
        assert_eq!(user_version(&copy).unwrap(), from as i64);
        let value: String = copy
            .query_row("SELECT value FROM meta WHERE key = 'k'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(value, "v");
    }

    #[test]
    fn fresh_or_current_database_is_not_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        let backups = backups(dir.path(), "0.2.0");
        drop(Db::open_with_backups(&path, &backups).unwrap());
        drop(Db::open_with_backups(&path, &backups).unwrap());
        assert!(!backups.dir.exists());
    }

    #[test]
    fn only_the_newest_three_backups_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let backups = backups(dir.path(), "0.2.1");
        std::fs::create_dir_all(&backups.dir).unwrap();
        let epoch = std::time::SystemTime::UNIX_EPOCH;
        for (i, name) in [
            "hub-1-0.1.0.db",
            "hub-2-0.1.1.db",
            "hub-3-0.1.2.db",
            "hub-4-0.1.3.db",
        ]
        .iter()
        .enumerate()
        {
            let file = std::fs::File::create(backups.dir.join(name)).unwrap();
            file.set_modified(epoch + std::time::Duration::from_secs(1_000 + i as u64))
                .unwrap();
        }
        std::fs::write(backups.dir.join("notes.txt"), "kept").unwrap();

        let path = dir.path().join("hub.db");
        let from = SCHEMA_VERSION as usize - 1;
        database_at(&path, from);
        drop(Db::open_with_backups(&path, &backups).unwrap());
        let mut kept = vec![
            "hub-3-0.1.2.db".to_owned(),
            "hub-4-0.1.3.db".to_owned(),
            format!("hub-{from}-0.2.1.db"),
            "notes.txt".to_owned(),
        ];
        kept.sort();
        assert_eq!(file_names(&backups.dir), kept);
    }

    #[test]
    fn release_is_sanitized_in_backup_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hub.db");
        database_at(&path, 1);
        drop(Db::open_with_backups(&path, &backups(dir.path(), "../1.0/x")).unwrap());
        assert_eq!(
            file_names(&dir.path().join("backups")),
            ["hub-1-.._1.0_x.db"]
        );
    }

    #[test]
    fn newer_schema_is_rejected_without_writes() {
        for wal in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("hub.db");
            let conn = rusqlite::Connection::open(&path).unwrap();
            if wal {
                conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| {
                    row.get::<_, String>(0)
                })
                .unwrap();
            }
            conn.execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
                .unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
            drop(conn);
            let before = std::fs::read(&path).unwrap();

            let err = Db::open(&path).err().unwrap();
            assert!(matches!(err, DbError::SchemaTooNew { .. }), "{err}");
            let message = err.to_string();
            assert!(
                message.contains(&format!("schema version {}", SCHEMA_VERSION + 1))
                    && message.contains(&format!("up to {SCHEMA_VERSION}"))
                    && message.contains("restore a backup or run a newer release"),
                "{message}"
            );
            let backups = backups(dir.path(), "0.2.0");
            assert!(matches!(
                Db::open_with_backups(&path, &backups),
                Err(DbError::SchemaTooNew { .. })
            ));
            assert_eq!(std::fs::read(&path).unwrap(), before, "wal={wal}");
            assert!(!backups.dir.exists());
        }
    }
}
