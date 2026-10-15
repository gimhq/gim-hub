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

        let listed = db
            .read(|c| list_pending(c, "u1", "d1", 10))
            .await
            .unwrap();
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
        let listed = db
            .read(|c| list_pending(c, "u1", "d1", 10))
            .await
            .unwrap();
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
    }
}
