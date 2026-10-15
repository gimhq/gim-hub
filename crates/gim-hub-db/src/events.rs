//! Per-device event stream with age-based retention.
//!
//! Each row is addressed to one device; its global `id` is the device's
//! cursor. Pruning deletes events older than the retention window and records
//! the highest pruned id: a cursor below it may have missed events and gets
//! 410 `cursor_expired` with the head cursor.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

const PRUNED_THROUGH_KEY: &str = "events_pruned_through";

/// A stored event. `payload` is the event's `data` as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub id: i64,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
}

/// Appends an event for one device and returns its cursor.
pub fn append(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    event_type: &str,
    payload: &str,
    now: i64,
) -> Result<i64, DbError> {
    tx.execute(
        "INSERT INTO events (user_id, device_id, type, payload, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, device_id, event_type, payload, now],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Events of one device with `id > after`, ascending, at most `limit`.
pub fn list_after(
    conn: &Connection,
    user_id: &str,
    device_id: &str,
    after: i64,
    limit: u32,
) -> Result<Vec<StoredEvent>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, type, payload, created_at FROM events \
         WHERE user_id = ?1 AND device_id = ?2 AND id > ?3 ORDER BY id LIMIT ?4",
    )?;
    let events = stmt
        .query_map(params![user_id, device_id, after, limit], |row| {
            Ok(StoredEvent {
                id: row.get(0)?,
                event_type: row.get(1)?,
                payload: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(events)
}

/// An event together with the device it is addressed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressedEvent {
    pub user_id: String,
    pub device_id: String,
    pub event: StoredEvent,
}

/// Events of every device with `id > after`, ascending, at most `limit`.
/// Lets in-process consumers (the push dispatcher) tail the event path:
/// SQLite has one writer, so ids become visible in increasing order.
pub fn list_all_after(
    conn: &Connection,
    after: i64,
    limit: u32,
) -> Result<Vec<AddressedEvent>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, type, payload, created_at, user_id, device_id FROM events \
         WHERE id > ?1 ORDER BY id LIMIT ?2",
    )?;
    let events = stmt
        .query_map(params![after, limit], |row| {
            Ok(AddressedEvent {
                event: StoredEvent {
                    id: row.get(0)?,
                    event_type: row.get(1)?,
                    payload: row.get(2)?,
                    created_at: row.get(3)?,
                },
                user_id: row.get(4)?,
                device_id: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(events)
}

/// Highest cursor ever assigned (0 if none). Never moves backwards, even
/// after every event was pruned.
pub fn head_cursor(conn: &Connection) -> Result<i64, DbError> {
    let head = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'events'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(head.unwrap_or(0))
}

/// Highest pruned cursor (0 if nothing was pruned). Events after a cursor
/// below this value may be gone.
pub fn pruned_through(conn: &Connection) -> Result<i64, DbError> {
    let value: Option<i64> = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
            [PRUNED_THROUGH_KEY],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.unwrap_or(0))
}

/// Deletes events created before `cutoff` and advances [`pruned_through`].
/// Returns the number of deleted events.
pub fn prune_before(tx: &Transaction<'_>, cutoff: i64) -> Result<usize, DbError> {
    let max_id: Option<i64> = tx.query_row(
        "SELECT max(id) FROM events WHERE created_at < ?1",
        [cutoff],
        |row| row.get(0),
    )?;
    let Some(max_id) = max_id else {
        return Ok(0);
    };
    let deleted = tx.execute("DELETE FROM events WHERE id <= ?1", [max_id])?;
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET \
         value = max(CAST(value AS INTEGER), CAST(excluded.value AS INTEGER))",
        params![PRUNED_THROUGH_KEY, max_id.to_string()],
    )?;
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn append_list_and_prune() {
        let db = Db::open_in_memory().unwrap();
        let ids = db
            .write(|tx| {
                Ok::<_, DbError>([
                    append(tx, "u1", "d1", "message", "{\"n\":1}", 100)?,
                    append(tx, "u1", "d2", "message", "{\"n\":2}", 100)?,
                    append(tx, "u1", "d1", "welcome", "{\"n\":3}", 200)?,
                    append(tx, "u2", "d1", "message", "{\"n\":4}", 200)?,
                ])
            })
            .await
            .unwrap();
        assert_eq!(ids, [1, 2, 3, 4]);

        let listed = db
            .read(|conn| list_after(conn, "u1", "d1", 0, 10))
            .await
            .unwrap();
        assert_eq!(listed.iter().map(|e| e.id).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(listed[1].event_type, "welcome");
        assert_eq!(listed[1].payload, "{\"n\":3}");
        assert_eq!(listed[1].created_at, 200);

        let limited = db
            .read(|conn| list_after(conn, "u1", "d1", 1, 1))
            .await
            .unwrap();
        assert_eq!(limited.iter().map(|e| e.id).collect::<Vec<_>>(), [3]);

        let all = db.read(|conn| list_all_after(conn, 1, 2)).await.unwrap();
        assert_eq!(
            all.iter()
                .map(|e| (e.user_id.as_str(), e.device_id.as_str(), e.event.id))
                .collect::<Vec<_>>(),
            [("u1", "d2", 2), ("u1", "d1", 3)]
        );

        assert_eq!(db.read(pruned_through).await.unwrap(), 0);
        assert_eq!(db.write(|tx| prune_before(tx, 150)).await.unwrap(), 2);
        assert_eq!(db.write(|tx| prune_before(tx, 150)).await.unwrap(), 0);
        assert_eq!(db.read(pruned_through).await.unwrap(), 2);
        let listed = db
            .read(|conn| list_after(conn, "u1", "d1", 0, 10))
            .await
            .unwrap();
        assert_eq!(listed.iter().map(|e| e.id).collect::<Vec<_>>(), [3]);

        assert_eq!(db.write(|tx| prune_before(tx, 1_000)).await.unwrap(), 2);
        assert_eq!(db.read(pruned_through).await.unwrap(), 4);
        assert_eq!(db.read(head_cursor).await.unwrap(), 4);
    }
}
