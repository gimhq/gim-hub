//! Pending Welcomes, kept per recipient device until acknowledged and
//! independently of event retention.

use rusqlite::{params, Connection, Transaction};

use crate::DbError;

/// An unacknowledged Welcome. `payload` is the `welcome` event data as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWelcome {
    pub id: i64,
    pub gid: String,
    pub payload: String,
    pub created_at: i64,
}

/// Stores a pending Welcome for one recipient device and returns its id.
pub fn insert_pending(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    gid: &str,
    payload: &str,
    now: i64,
) -> Result<i64, DbError> {
    tx.execute(
        "INSERT INTO pending_welcomes (user_id, device_id, gid, payload, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, device_id, gid, payload, now],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Stores a Welcome delivered by the owning hub for one recipient device,
/// deduplicated by `(message_id, user_id, device_id)`. Returns false for a
/// duplicate.
pub fn insert_delivered(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    gid: &str,
    payload: &str,
    message_id: &str,
    now: i64,
) -> Result<bool, DbError> {
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO pending_welcomes \
         (user_id, device_id, gid, payload, created_at, message_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![user_id, device_id, gid, payload, now, message_id],
    )?;
    Ok(inserted > 0)
}

/// An unacknowledged Welcome of one of a user's devices, with the owner's
/// `message_id` (docs/multihoming.md §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPendingWelcome {
    pub device_id: String,
    pub gid: String,
    pub message_id: String,
    pub payload: String,
    pub created_at: i64,
}

/// Unacknowledged Welcomes of every device of `user_id`, oldest first.
/// `message_id` is the stored column, else the `message_id` of the Commit
/// at the payload's `seq` in the local log; a Welcome without either is
/// skipped.
pub fn pending_for_user(
    conn: &Connection,
    user_id: &str,
) -> Result<Vec<UserPendingWelcome>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT w.device_id, w.gid, COALESCE(w.message_id, \
         (SELECT m.message_id FROM messages AS m \
          WHERE m.gid = w.gid AND m.seq = json_extract(w.payload, '$.seq'))), \
         w.payload, w.created_at FROM pending_welcomes AS w \
         WHERE w.user_id = ?1 AND w.acked_at IS NULL AND json_valid(w.payload) ORDER BY w.id",
    )?;
    let welcomes = stmt
        .query_map([user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .filter_map(|row| match row {
            Ok((device_id, gid, Some(message_id), payload, created_at)) => {
                Some(Ok(UserPendingWelcome {
                    device_id,
                    gid,
                    message_id,
                    payload,
                    created_at,
                }))
            }
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(welcomes)
}

/// Unacknowledged Welcomes of one device, oldest first, at most `limit`.
pub fn list_pending(
    conn: &Connection,
    user_id: &str,
    device_id: &str,
    limit: u32,
) -> Result<Vec<PendingWelcome>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, gid, payload, created_at FROM pending_welcomes \
         WHERE user_id = ?1 AND device_id = ?2 AND acked_at IS NULL ORDER BY id LIMIT ?3",
    )?;
    let welcomes = stmt
        .query_map(params![user_id, device_id, limit], |row| {
            Ok(PendingWelcome {
                id: row.get(0)?,
                gid: row.get(1)?,
                payload: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(welcomes)
}

/// Acknowledges every pending Welcome of one device for `gid`. Returns the
/// number of Welcomes newly acknowledged (0 if nothing was pending).
pub fn ack(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    gid: &str,
    now: i64,
) -> Result<usize, DbError> {
    let acked = tx.execute(
        "UPDATE pending_welcomes SET acked_at = ?4 \
         WHERE user_id = ?1 AND device_id = ?2 AND gid = ?3 AND acked_at IS NULL",
        params![user_id, device_id, gid, now],
    )?;
    Ok(acked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn insert_list_and_ack() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            insert_pending(tx, "u1", "d1", "g1", "{\"n\":1}", 10)?;
            insert_pending(tx, "u1", "d2", "g1", "{\"n\":2}", 10)?;
            insert_pending(tx, "u1", "d1", "g2", "{\"n\":3}", 20)
        })
        .await
        .unwrap();

        let listed = db.read(|c| list_pending(c, "u1", "d1", 10)).await.unwrap();
        assert_eq!(
            listed.iter().map(|w| w.gid.as_str()).collect::<Vec<_>>(),
            ["g1", "g2"]
        );
        assert_eq!(listed[1].payload, "{\"n\":3}");
        assert_eq!(listed[1].created_at, 20);
        assert_eq!(
            db.read(|c| list_pending(c, "u1", "d1", 1))
                .await
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            db.write(|tx| ack(tx, "u1", "d1", "g1", 30)).await.unwrap(),
            1
        );
        assert_eq!(
            db.write(|tx| ack(tx, "u1", "d1", "g1", 40)).await.unwrap(),
            0
        );
        let listed = db.read(|c| list_pending(c, "u1", "d1", 10)).await.unwrap();
        assert_eq!(
            listed.iter().map(|w| w.gid.as_str()).collect::<Vec<_>>(),
            ["g2"]
        );
        // Other devices are unaffected.
        assert_eq!(
            db.read(|c| list_pending(c, "u1", "d2", 10))
                .await
                .unwrap()
                .len(),
            1
        );

        assert!(db
            .write(|tx| insert_delivered(tx, "u1", "d1", "g3", "{}", "m1", 50))
            .await
            .unwrap());
        assert!(!db
            .write(|tx| insert_delivered(tx, "u1", "d1", "g3", "{}", "m1", 60))
            .await
            .unwrap());
        assert!(db
            .write(|tx| insert_delivered(tx, "u1", "d2", "g3", "{}", "m1", 60))
            .await
            .unwrap());
        assert_eq!(
            db.read(|c| list_pending(c, "u1", "d1", 10))
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn pending_for_user_resolves_message_ids() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO groups (gid, kind, epoch, created_by_user_id, created_by_device_id, \
                 created_at) VALUES ('h1/g', 'group', 1, 'u1', 'd1', 0)",
                [],
            )?;
            tx.execute(
                "INSERT INTO messages (gid, seq, epoch, kind, sender_user_id, sender_device_id, \
                 client_id, payload, message_id, created_at) \
                 VALUES ('h1/g', 1, 0, 'commit', 'u2', 'd2', 'c1', x'00', 'mc', 0)",
                [],
            )?;
            // Local owner path (no message_id), delivered, unresolvable,
            // acknowledged, another user.
            insert_pending(tx, "u1", "d1", "h1/g", r#"{"gid":"h1/g","seq":1}"#, 10)?;
            insert_delivered(tx, "u1", "d2", "h2/x", r#"{"seq":4}"#, "md", 20)?;
            insert_pending(tx, "u1", "d1", "h1/g", r#"{"gid":"h1/g","seq":9}"#, 30)?;
            insert_delivered(tx, "u1", "d1", "h2/y", "{}", "ma", 40)?;
            ack(tx, "u1", "d1", "h2/y", 50)?;
            insert_delivered(tx, "u2", "d1", "h2/x", "{}", "mo", 60)?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let listed = db.read(|c| pending_for_user(c, "u1")).await.unwrap();
        let ids: Vec<_> = listed
            .iter()
            .map(|w| (w.device_id.as_str(), w.gid.as_str(), w.message_id.as_str()))
            .collect();
        assert_eq!(ids, [("d1", "h1/g", "mc"), ("d2", "h2/x", "md")]);
        assert_eq!(listed[1].payload, r#"{"seq":4}"#);
        assert_eq!(listed[1].created_at, 20);
    }
}
