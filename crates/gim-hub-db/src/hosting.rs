//! Hosting records (docs/federation.md §4.3): the records of local users and
//! the cache of remote users' records, one row per user.
//!
//! This module stores bytes verbatim; verifying records and the seq rules
//! are the caller's job. A row is local if the user has a row in `users`.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::DbError;

/// A stored hosting record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHostingRecord {
    pub user_id: String,
    /// `SignedHostingRecord` CBOR as received.
    pub record: Vec<u8>,
    pub seq: i64,
    pub expires_at: i64,
    /// The user is local and the record lists this hub.
    pub hosted: bool,
    /// Listed hub IDs, in record order.
    pub hub_ids: Vec<String>,
    /// Last verification from a remote source (`updated_at` for local rows).
    pub fetched_at: i64,
    /// Last successful DHT put of this record (hosted rows only).
    pub published_at: Option<i64>,
    pub updated_at: i64,
}

const COLUMNS: &str =
    "user_id, record, seq, expires_at, hosted, hub_ids, fetched_at, published_at, updated_at";

fn from_row(row: &Row<'_>) -> rusqlite::Result<StoredHostingRecord> {
    let hub_ids: String = row.get(5)?;
    Ok(StoredHostingRecord {
        user_id: row.get(0)?,
        record: row.get(1)?,
        seq: row.get(2)?,
        expires_at: row.get(3)?,
        hosted: row.get(4)?,
        hub_ids: serde_json::from_str(&hub_ids).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, err.into())
        })?,
        fetched_at: row.get(6)?,
        published_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn query(
    conn: &Connection,
    filter: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<StoredHostingRecord>, DbError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM hosting_records WHERE {filter} ORDER BY user_id"
    ))?;
    let rows = stmt
        .query_map(params, from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The stored record of `user_id`, if any (expired or not).
pub fn get(conn: &Connection, user_id: &str) -> Result<Option<StoredHostingRecord>, DbError> {
    let record = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM hosting_records WHERE user_id = ?1"),
            [user_id],
            from_row,
        )
        .optional()?;
    Ok(record)
}

/// Whether `user_id` is a local user (has a row in `users`).
pub fn is_local(conn: &Connection, user_id: &str) -> Result<bool, DbError> {
    let local = conn
        .query_row("SELECT 1 FROM users WHERE user_id = ?1", [user_id], |_| {
            Ok(())
        })
        .optional()?;
    Ok(local.is_some())
}

/// Stores or replaces the record of `record.user_id`.
pub fn put(tx: &Transaction<'_>, record: &StoredHostingRecord) -> Result<(), DbError> {
    let hub_ids = serde_json::to_string(&record.hub_ids).expect("strings serialize");
    tx.execute(
        &format!(
            "INSERT INTO hosting_records ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT (user_id) DO UPDATE SET record = excluded.record, seq = excluded.seq, \
             expires_at = excluded.expires_at, hosted = excluded.hosted, \
             hub_ids = excluded.hub_ids, fetched_at = excluded.fetched_at, \
             published_at = excluded.published_at, updated_at = excluded.updated_at"
        ),
        params![
            record.user_id,
            record.record,
            record.seq,
            record.expires_at,
            record.hosted,
            hub_ids,
            record.fetched_at,
            record.published_at,
            record.updated_at,
        ],
    )?;
    Ok(())
}

/// Sets `fetched_at` of the stored record of `user_id` if it still has `seq`.
pub fn touch_fetched(
    tx: &Transaction<'_>,
    user_id: &str,
    seq: i64,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "UPDATE hosting_records SET fetched_at = ?3 WHERE user_id = ?1 AND seq = ?2",
        params![user_id, seq, now],
    )?;
    Ok(())
}

/// Records a successful DHT put of `seq` for `user_id`; a no-op if the
/// stored record has changed in the meantime.
pub fn mark_published(
    tx: &Transaction<'_>,
    user_id: &str,
    seq: i64,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "UPDATE hosting_records SET published_at = ?3 \
         WHERE user_id = ?1 AND seq = ?2 AND hosted = 1",
        params![user_id, seq, now],
    )?;
    Ok(())
}

/// Hosted records that are unexpired at `now`; with `unpublished_only`, only
/// those never published since they were stored.
pub fn hosted(
    conn: &Connection,
    now: i64,
    unpublished_only: bool,
) -> Result<Vec<StoredHostingRecord>, DbError> {
    let filter = if unpublished_only {
        "hosted = 1 AND expires_at > ?1 AND published_at IS NULL"
    } else {
        "hosted = 1 AND expires_at > ?1"
    };
    query(conn, filter, [now])
}

/// Retention at `now`: deletes expired cache rows of remote users and marks
/// expired local rows not hosted (they still order future uploads). Rows of
/// removed users are kept as tombstones (docs/multihoming.md §7.3). Returns
/// `(deleted, unhosted)`.
pub fn expire(tx: &Transaction<'_>, now: i64) -> Result<(usize, usize), DbError> {
    let deleted = tx.execute(
        "DELETE FROM hosting_records WHERE expires_at <= ?1 AND removed_at IS NULL \
         AND user_id NOT IN (SELECT user_id FROM users)",
        [now],
    )?;
    let unhosted = tx.execute(
        "UPDATE hosting_records SET hosted = 0 WHERE expires_at <= ?1 AND hosted = 1",
        [now],
    )?;
    Ok((deleted, unhosted))
}

/// Hosted records expiring in `(now, until)` that need a
/// `hosting_record.expiring` event: never notified for their seq, and not
/// notified at all after `renotify_after`.
pub fn expiring(
    conn: &Connection,
    now: i64,
    until: i64,
    renotify_after: i64,
) -> Result<Vec<StoredHostingRecord>, DbError> {
    query(
        conn,
        "hosted = 1 AND expires_at > ?1 AND expires_at < ?2 AND \
         (expiring_notified_seq IS NULL OR \
          (expiring_notified_seq != seq AND expiring_notified_at <= ?3))",
        params![now, until, renotify_after],
    )
}

/// Records that the `hosting_record.expiring` event for `seq` was emitted.
pub fn mark_expiring_notified(
    tx: &Transaction<'_>,
    user_id: &str,
    seq: i64,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "UPDATE hosting_records SET expiring_notified_seq = ?2, expiring_notified_at = ?3 \
         WHERE user_id = ?1",
        params![user_id, seq, now],
    )?;
    Ok(())
}

/// When local user `user_id` was removed from this hub (docs/multihoming.md
/// §7.3), if they are; also set on the tombstone of a purged user.
pub fn removed_at(conn: &Connection, user_id: &str) -> Result<Option<i64>, DbError> {
    let removed_at = conn
        .query_row(
            "SELECT removed_at FROM hosting_records WHERE user_id = ?1",
            [user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(removed_at.flatten())
}

/// Sets (`Some`) or clears (`None`) `removed_at` of the stored record of
/// `user_id`. [`put`] leaves the column unchanged.
pub fn set_removed_at(
    tx: &Transaction<'_>,
    user_id: &str,
    removed_at: Option<i64>,
) -> Result<(), DbError> {
    tx.execute(
        "UPDATE hosting_records SET removed_at = ?2 WHERE user_id = ?1",
        params![user_id, removed_at],
    )?;
    Ok(())
}

/// Effects of removing local user `user_id` from this hub (§7.3 steps 2 and
/// 4): deletes the user's unclaimed KeyPackages and detaches the replicas
/// whose local members all belong to removed users, at the user's
/// `removed_at`. Call after [`set_removed_at`]. Returns `(key packages
/// deleted, replicas detached)`.
pub fn remove_local_user(tx: &Transaction<'_>, user_id: &str) -> Result<(usize, usize), DbError> {
    let key_packages = tx.execute(
        "DELETE FROM key_packages WHERE user_id = ?1 AND claimed_at IS NULL",
        [user_id],
    )?;
    let detached = tx.execute(
        "UPDATE groups SET detached = 1, \
         detached_at = (SELECT removed_at FROM hosting_records WHERE user_id = ?1) \
         WHERE replica_from_seq IS NOT NULL AND detached = 0 \
         AND gid IN (SELECT gid FROM group_members WHERE user_id = ?1) \
         AND NOT EXISTS (SELECT 1 FROM group_members AS m \
             JOIN users AS u ON u.user_id = m.user_id \
             LEFT JOIN hosting_records AS h ON h.user_id = m.user_id \
             WHERE m.gid = groups.gid AND h.removed_at IS NULL)",
        [user_id],
    )?;
    Ok((key_packages, detached))
}

/// Purges the local data of users removed at or before `cutoff` (§7.3): the
/// `users` row (cascading devices, sessions, KeyPackages, handles, recovery
/// backups and push registrations), their events, pending Welcomes and the
/// remote KeyPackage claims they made. The hosting record stays as a
/// tombstone; group rosters are kept. Returns the purged user IDs.
pub fn purge_removed(tx: &Transaction<'_>, cutoff: i64) -> Result<Vec<String>, DbError> {
    let users = {
        let mut stmt = tx.prepare_cached(
            "SELECT h.user_id FROM hosting_records AS h JOIN users AS u ON u.user_id = h.user_id \
             WHERE h.removed_at IS NOT NULL AND h.removed_at <= ?1 ORDER BY h.user_id",
        )?;
        let users = stmt
            .query_map([cutoff], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        users
    };
    for user_id in &users {
        tx.execute("DELETE FROM events WHERE user_id = ?1", [user_id])?;
        tx.execute("DELETE FROM pending_welcomes WHERE user_id = ?1", [user_id])?;
        tx.execute(
            "DELETE FROM remote_kp_claims WHERE claimed_by_user_id = ?1",
            [user_id],
        )?;
        tx.execute("DELETE FROM users WHERE user_id = ?1", [user_id])?;
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        users::{put_device_list, StoredDeviceList},
        Db,
    };

    fn record(user_id: &str, seq: i64, expires_at: i64, hosted: bool) -> StoredHostingRecord {
        StoredHostingRecord {
            user_id: user_id.into(),
            record: vec![seq as u8; 4],
            seq,
            expires_at,
            hosted,
            hub_ids: vec!["ha".into(), "hb".into()],
            fetched_at: 5,
            published_at: None,
            updated_at: 5,
        }
    }

    fn local_user(tx: &Transaction<'_>, user_id: &str) -> Result<(), DbError> {
        put_device_list(
            tx,
            &StoredDeviceList {
                user_id: user_id.into(),
                root_pubkey: vec![1; 32],
                device_list: vec![0; 8],
                seq: 1,
                updated_at: 0,
            },
        )
        .map(|_| ())
    }

    #[tokio::test]
    async fn put_get_publish_and_touch() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            local_user(tx, "u1")?;
            put(tx, &record("u1", 1, 100, true))?;
            put(tx, &record("u2", 1, 100, false))
        })
        .await
        .unwrap();
        let (u1, local, remote) = db
            .read(|conn| {
                Ok::<_, DbError>((
                    get(conn, "u1")?,
                    is_local(conn, "u1")?,
                    is_local(conn, "u2")?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(u1, Some(record("u1", 1, 100, true)));
        assert!(local && !remote);

        assert_eq!(
            db.read(|conn| hosted(conn, 10, true)).await.unwrap().len(),
            1
        );
        db.write(|tx| {
            mark_published(tx, "u1", 2, 7)?; // other seq: no-op
            mark_published(tx, "u2", 1, 7)?; // not hosted: no-op
            touch_fetched(tx, "u2", 1, 9)
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|conn| hosted(conn, 10, true)).await.unwrap().len(),
            1
        );
        db.write(|tx| mark_published(tx, "u1", 1, 7)).await.unwrap();
        let u1 = db.read(|conn| get(conn, "u1")).await.unwrap().unwrap();
        assert_eq!(u1.published_at, Some(7));
        assert!(db
            .read(|conn| hosted(conn, 10, true))
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            db.read(|conn| hosted(conn, 10, false)).await.unwrap(),
            vec![u1]
        );
        assert!(db
            .read(|conn| hosted(conn, 100, false))
            .await
            .unwrap()
            .is_empty());
        let u2 = db.read(|conn| get(conn, "u2")).await.unwrap().unwrap();
        assert_eq!((u2.fetched_at, u2.published_at), (9, None));

        // Replacing resets publication.
        db.write(|tx| put(tx, &record("u1", 2, 200, true)))
            .await
            .unwrap();
        let u1 = db.read(|conn| get(conn, "u1")).await.unwrap().unwrap();
        assert_eq!((u1.seq, u1.published_at), (2, None));
    }

    #[tokio::test]
    async fn expire_deletes_remote_and_unhosts_local() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            local_user(tx, "u1")?;
            put(tx, &record("u1", 1, 100, true))?;
            put(tx, &record("u2", 1, 100, false))?;
            put(tx, &record("u3", 1, 300, false))
        })
        .await
        .unwrap();
        assert_eq!(db.write(|tx| expire(tx, 99)).await.unwrap(), (0, 0));
        assert_eq!(db.write(|tx| expire(tx, 100)).await.unwrap(), (1, 1));
        let (u1, u2, u3) = db
            .read(|conn| Ok::<_, DbError>((get(conn, "u1")?, get(conn, "u2")?, get(conn, "u3")?)))
            .await
            .unwrap();
        assert!(!u1.unwrap().hosted);
        assert!(u2.is_none());
        assert!(u3.is_some());
    }

    #[tokio::test]
    async fn removal_detaches_replicas_and_purge_keeps_the_tombstone() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for user in ["u1", "u2"] {
                local_user(tx, user)?;
                put(tx, &record(user, 1, 100, true))?;
            }
            tx.execute_batch(
                "INSERT INTO devices VALUES ('u1', 'd1', x'00', 1, 0, 0); \
                 INSERT INTO sessions VALUES (x'01', 'u1', 'd1', 0, 999); \
                 INSERT INTO key_packages (user_id, device_id, key_package, kp_ref, last_resort, \
                     created_at, claimed_at) VALUES \
                     ('u1', 'd1', x'00', x'01', 0, 0, NULL), \
                     ('u1', 'd1', x'00', x'02', 1, 0, NULL), \
                     ('u1', 'd1', x'00', x'03', 0, 0, 5); \
                 INSERT INTO events (user_id, device_id, type, payload, created_at) \
                     VALUES ('u1', 'd1', 't', '{}', 0), ('u2', 'd2', 't', '{}', 0); \
                 INSERT INTO pending_welcomes (user_id, device_id, gid, payload, created_at) \
                     VALUES ('u1', 'd1', 'h9/g1', '{}', 0); \
                 INSERT INTO remote_kp_claims VALUES (x'09', 'x', 'xd', 'h9', 'u1', 'd1', 0); \
                 INSERT INTO groups (gid, kind, created_by_user_id, created_by_device_id, \
                     created_at, replica_from_seq) VALUES \
                     ('h9/g1', 'group', 'x', 'xd', 0, 1), \
                     ('h9/g2', 'group', 'x', 'xd', 0, 1); \
                 INSERT INTO groups (gid, kind, created_by_user_id, created_by_device_id, \
                     created_at) VALUES ('h1/g3', 'group', 'u1', 'd1', 0); \
                 INSERT INTO group_members (gid, user_id, device_id, added_at) VALUES \
                     ('h9/g1', 'u1', 'd1', 0), ('h9/g1', 'x', 'xd', 0), \
                     ('h9/g2', 'u1', 'd1', 0), ('h9/g2', 'u2', 'd2', 0), \
                     ('h1/g3', 'u1', 'd1', 0);",
            )?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let removed = db
            .write(|tx| {
                put(tx, &record("u1", 2, 100, false))?;
                set_removed_at(tx, "u1", Some(10))?;
                remove_local_user(tx, "u1")
            })
            .await
            .unwrap();
        // The unclaimed one-time and last-resort packages; g1 only has u1
        // locally, g2 also has u2 (not removed); g3 is owned here.
        assert_eq!(removed, (2, 1));
        let count = |sql: &'static str| {
            let db = db.clone();
            async move {
                db.read(move |conn| Ok::<i64, DbError>(conn.query_row(sql, [], |row| row.get(0))?))
                    .await
                    .unwrap()
            }
        };
        let detached: String = db
            .read(|conn| {
                Ok::<_, DbError>(conn.query_row(
                    "SELECT group_concat(gid || ':' || detached_at) FROM groups \
                     WHERE detached = 1",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(detached, "h9/g1:10");
        assert_eq!(
            db.read(|conn| removed_at(conn, "u1")).await.unwrap(),
            Some(10)
        );
        // `put` keeps removed_at.
        db.write(|tx| put(tx, &record("u1", 3, 100, false)))
            .await
            .unwrap();
        assert_eq!(
            db.read(|conn| removed_at(conn, "u1")).await.unwrap(),
            Some(10)
        );

        assert!(db
            .write(|tx| purge_removed(tx, 9))
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.write(|tx| purge_removed(tx, 10)).await.unwrap(), ["u1"]);
        assert!(!db.read(|conn| is_local(conn, "u1")).await.unwrap());
        assert_eq!(
            count("SELECT count(*) FROM devices WHERE user_id = 'u1'").await,
            0
        );
        assert_eq!(count("SELECT count(*) FROM sessions").await, 0);
        assert_eq!(count("SELECT count(*) FROM key_packages").await, 0);
        assert_eq!(count("SELECT count(*) FROM events").await, 1);
        assert_eq!(count("SELECT count(*) FROM pending_welcomes").await, 0);
        assert_eq!(count("SELECT count(*) FROM remote_kp_claims").await, 0);
        // Rosters stay, and the tombstone outlives expiry.
        assert_eq!(
            count("SELECT count(*) FROM group_members WHERE user_id = 'u1'").await,
            3
        );
        db.write(|tx| expire(tx, 1_000)).await.unwrap();
        let tombstone = db.read(|conn| get(conn, "u1")).await.unwrap().unwrap();
        assert_eq!(tombstone.seq, 3);

        // Clearing ends the removal.
        db.write(|tx| set_removed_at(tx, "u1", None)).await.unwrap();
        assert_eq!(db.read(|conn| removed_at(conn, "u1")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn expiring_once_per_seq_and_day() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            local_user(tx, "u1")?;
            put(tx, &record("u1", 1, 1_000, true))?;
            put(tx, &record("u2", 1, 1_000, false))
        })
        .await
        .unwrap();
        let due = |now: i64, renotify_after: i64| {
            let db = db.clone();
            async move {
                db.read(move |conn| expiring(conn, now, now + 500, renotify_after))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|r| (r.user_id, r.seq))
                    .collect::<Vec<_>>()
            }
        };
        assert!(due(400, 0).await.is_empty()); // more than the window left
        assert_eq!(due(600, 0).await, vec![("u1".to_owned(), 1)]);
        db.write(|tx| mark_expiring_notified(tx, "u1", 1, 600))
            .await
            .unwrap();
        assert!(due(700, 700).await.is_empty());

        // A new seq is notified again, but not within a day of the last.
        db.write(|tx| put(tx, &record("u1", 2, 1_000, true)))
            .await
            .unwrap();
        assert!(due(700, 599).await.is_empty());
        assert_eq!(due(700, 600).await, vec![("u1".to_owned(), 2)]);
        assert!(due(1_000, 600).await.is_empty()); // expired
    }
}
