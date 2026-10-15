//! Durable S2S outbound queue and per-peer delivery state
//! (docs/federation.md §7).
//!
//! Entries are FIFO per peer by `id`. `deliver` entries carry `(gid, seq)`
//! only (the message is rebuilt at send time), `device_list` entries carry
//! the user (the latest list is read at send time) and `deliver_welcome`
//! entries carry the encoded request.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// Kind of an outbox entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Deliver,
    DeliverWelcome,
    DeviceList,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deliver => "deliver",
            Self::DeliverWelcome => "deliver_welcome",
            Self::DeviceList => "device_list",
        }
    }

    fn parse(text: &str) -> Result<Self, rusqlite::Error> {
        match text {
            "deliver" => Ok(Self::Deliver),
            "deliver_welcome" => Ok(Self::DeliverWelcome),
            "device_list" => Ok(Self::DeviceList),
            other => Err(rusqlite::Error::InvalidColumnType(
                0,
                format!("kind {other:?}"),
                rusqlite::types::Type::Text,
            )),
        }
    }
}

/// An entry to queue for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewEntry<'a> {
    /// Message `seq` of `gid`; `size` is its payload length, counted
    /// against the backlog cap.
    Deliver { gid: &'a str, seq: i64, size: i64 },
    /// An encoded `DeliverWelcomeRequest` for `gid`.
    DeliverWelcome { gid: &'a str, payload: &'a [u8] },
    /// The current DeviceList of `user_id`; coalesced per peer.
    DeviceList { user_id: &'a str },
}

/// Entry lifetime and per-peer backlog cap (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub ttl_ms: i64,
    pub max_entries: i64,
    pub max_bytes: i64,
}

/// Result of [`enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enqueued {
    /// False when an equal entry was already queued (or the new `deliver`
    /// entry was itself evicted by the cap).
    pub queued: bool,
    /// `deliver` entries evicted by the cap; the peer is then marked
    /// `needs_resync`.
    pub evicted: usize,
    /// The peer's backlog afterwards.
    pub backlog: Backlog,
}

/// Queued entries and bytes of one peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Backlog {
    pub entries: i64,
    pub bytes: i64,
}

/// A queued entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: i64,
    pub kind: Kind,
    pub gid: Option<String>,
    pub seq: Option<i64>,
    pub user_id: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub size: i64,
    pub created_at: i64,
    pub expires_at: i64,
    pub attempts: i64,
}

/// Delivery state of a peer hub.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peer {
    pub failures: i64,
    pub next_attempt_at: i64,
    pub needs_resync: bool,
    pub last_connected_at: Option<i64>,
}

/// Entries deleted by [`expire`], per peer and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expired {
    pub peer_hub_id: String,
    pub kind: Kind,
    pub count: i64,
}

/// Queues `entry` for `peer_hub_id`, then enforces the backlog cap by
/// deleting the peer's oldest `deliver` entries (marking it `needs_resync`).
/// `deliver_welcome` and `device_list` entries are never evicted, so they
/// are queued even when only they exceed the cap.
pub fn enqueue(
    tx: &Transaction<'_>,
    peer_hub_id: &str,
    entry: NewEntry<'_>,
    limits: &Limits,
    now: i64,
) -> Result<Enqueued, DbError> {
    let (kind, gid, seq, user_id, payload, size) = match entry {
        NewEntry::Deliver { gid, seq, size } => {
            (Kind::Deliver, Some(gid), Some(seq), None, None, size)
        }
        NewEntry::DeliverWelcome { gid, payload } => (
            Kind::DeliverWelcome,
            Some(gid),
            None,
            None,
            Some(payload),
            payload.len() as i64,
        ),
        NewEntry::DeviceList { user_id } => (
            Kind::DeviceList,
            None,
            None,
            Some(user_id),
            None,
            user_id.len() as i64,
        ),
    };
    let inserted = tx.execute(
        "INSERT INTO s2s_outbox \
         (peer_hub_id, kind, gid, seq, user_id, payload, size, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING",
        params![
            peer_hub_id,
            kind.as_str(),
            gid,
            seq,
            user_id,
            payload,
            size,
            now,
            now.saturating_add(limits.ttl_ms)
        ],
    )? > 0;
    let new_id = tx.last_insert_rowid();
    let mut backlog = backlog(tx, peer_hub_id)?;
    let mut evicted = Vec::new();
    if inserted && (backlog.entries > limits.max_entries || backlog.bytes > limits.max_bytes) {
        let mut stmt = tx.prepare_cached(
            "SELECT id, size FROM s2s_outbox WHERE peer_hub_id = ?1 AND kind = 'deliver' \
             ORDER BY id",
        )?;
        let mut rows = stmt.query([peer_hub_id])?;
        while backlog.entries > limits.max_entries || backlog.bytes > limits.max_bytes {
            let Some(row) = rows.next()? else { break };
            evicted.push(row.get::<_, i64>(0)?);
            backlog.entries -= 1;
            backlog.bytes -= row.get::<_, i64>(1)?;
        }
    }
    for id in &evicted {
        tx.execute("DELETE FROM s2s_outbox WHERE id = ?1", [id])?;
    }
    if !evicted.is_empty() {
        set_needs_resync(tx, peer_hub_id, true, now)?;
    }
    Ok(Enqueued {
        queued: inserted && !evicted.contains(&new_id),
        evicted: evicted.len(),
        backlog,
    })
}

/// Queued entries and bytes of `peer_hub_id`.
pub fn backlog(conn: &Connection, peer_hub_id: &str) -> Result<Backlog, DbError> {
    Ok(conn.query_row(
        "SELECT count(*), coalesce(sum(size), 0) FROM s2s_outbox WHERE peer_hub_id = ?1",
        [peer_hub_id],
        |row| {
            Ok(Backlog {
                entries: row.get(0)?,
                bytes: row.get(1)?,
            })
        },
    )?)
}

/// The oldest unexpired entries of `peer_hub_id`, at most `limit`.
pub fn head(
    conn: &Connection,
    peer_hub_id: &str,
    now: i64,
    limit: u32,
) -> Result<Vec<Entry>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, kind, gid, seq, user_id, payload, size, created_at, expires_at, attempts \
         FROM s2s_outbox WHERE peer_hub_id = ?1 AND expires_at > ?2 ORDER BY id LIMIT ?3",
    )?;
    let entries = stmt
        .query_map(params![peer_hub_id, now, limit], |row| {
            Ok(Entry {
                id: row.get(0)?,
                kind: Kind::parse(&row.get::<_, String>(1)?)?,
                gid: row.get(2)?,
                seq: row.get(3)?,
                user_id: row.get(4)?,
                payload: row.get(5)?,
                size: row.get(6)?,
                created_at: row.get(7)?,
                expires_at: row.get(8)?,
                attempts: row.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

/// Deletes the entries `ids`; returns how many existed.
pub fn delete(tx: &Transaction<'_>, ids: &[i64]) -> Result<usize, DbError> {
    let mut stmt = tx.prepare_cached("DELETE FROM s2s_outbox WHERE id = ?1")?;
    let mut deleted = 0;
    for id in ids {
        deleted += stmt.execute([id])?;
    }
    Ok(deleted)
}

/// Counts one send attempt of each entry in `ids`.
pub fn count_attempt(tx: &Transaction<'_>, ids: &[i64]) -> Result<(), DbError> {
    let mut stmt =
        tx.prepare_cached("UPDATE s2s_outbox SET attempts = attempts + 1 WHERE id = ?1")?;
    for id in ids {
        stmt.execute([id])?;
    }
    Ok(())
}

/// Deletes entries expired at `now` and marks every peer that lost a
/// `deliver` entry `needs_resync`.
pub fn expire(tx: &Transaction<'_>, now: i64) -> Result<Vec<Expired>, DbError> {
    let mut stmt = tx.prepare_cached(
        "SELECT peer_hub_id, kind, count(*) FROM s2s_outbox WHERE expires_at <= ?1 \
         GROUP BY peer_hub_id, kind ORDER BY peer_hub_id, kind",
    )?;
    let expired = stmt
        .query_map([now], |row| {
            Ok(Expired {
                peer_hub_id: row.get(0)?,
                kind: Kind::parse(&row.get::<_, String>(1)?)?,
                count: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if expired.is_empty() {
        return Ok(expired);
    }
    tx.execute("DELETE FROM s2s_outbox WHERE expires_at <= ?1", [now])?;
    for item in expired.iter().filter(|item| item.kind == Kind::Deliver) {
        set_needs_resync(tx, &item.peer_hub_id, true, now)?;
    }
    Ok(expired)
}

/// Peers with queued entries or a pending resync, with their
/// `next_attempt_at` (0 when the peer has no state yet).
pub fn pending_peers(conn: &Connection) -> Result<Vec<(String, i64)>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT pending.hub_id, coalesce(p.next_attempt_at, 0) FROM \
         (SELECT DISTINCT peer_hub_id AS hub_id FROM s2s_outbox \
          UNION SELECT hub_id FROM s2s_peers WHERE needs_resync = 1) AS pending \
         LEFT JOIN s2s_peers AS p ON p.hub_id = pending.hub_id ORDER BY pending.hub_id",
    )?;
    let peers = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peers)
}

/// Delivery state of `hub_id`; the default when it has none.
pub fn peer(conn: &Connection, hub_id: &str) -> Result<Peer, DbError> {
    Ok(conn
        .query_row(
            "SELECT failures, next_attempt_at, needs_resync, last_connected_at \
             FROM s2s_peers WHERE hub_id = ?1",
            [hub_id],
            |row| {
                Ok(Peer {
                    failures: row.get(0)?,
                    next_attempt_at: row.get(1)?,
                    needs_resync: row.get(2)?,
                    last_connected_at: row.get(3)?,
                })
            },
        )
        .optional()?
        .unwrap_or_default())
}

fn ensure_peer(tx: &Transaction<'_>, hub_id: &str, now: i64) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO s2s_peers (hub_id, updated_at) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        params![hub_id, now],
    )?;
    Ok(())
}

/// Counts a failed attempt and defers the next one to `next_attempt_at`;
/// returns the new failure count.
pub fn record_failure(
    tx: &Transaction<'_>,
    hub_id: &str,
    next_attempt_at: i64,
    now: i64,
) -> Result<i64, DbError> {
    ensure_peer(tx, hub_id, now)?;
    Ok(tx.query_row(
        "UPDATE s2s_peers SET failures = failures + 1, next_attempt_at = ?2, updated_at = ?3 \
         WHERE hub_id = ?1 RETURNING failures",
        params![hub_id, next_attempt_at, now],
        |row| row.get(0),
    )?)
}

/// Resets the backoff after a successful exchange with `hub_id`.
pub fn record_success(tx: &Transaction<'_>, hub_id: &str, now: i64) -> Result<(), DbError> {
    tx.execute(
        "UPDATE s2s_peers SET failures = 0, next_attempt_at = 0, updated_at = ?2 \
         WHERE hub_id = ?1 AND (failures != 0 OR next_attempt_at != 0)",
        params![hub_id, now],
    )?;
    Ok(())
}

/// `hub_id` connected: resets the backoff and records the time.
pub fn record_connected(tx: &Transaction<'_>, hub_id: &str, now: i64) -> Result<(), DbError> {
    ensure_peer(tx, hub_id, now)?;
    tx.execute(
        "UPDATE s2s_peers SET failures = 0, next_attempt_at = 0, last_connected_at = ?2, \
         updated_at = ?2 WHERE hub_id = ?1",
        params![hub_id, now],
    )?;
    Ok(())
}

/// Sets or clears the `needs_resync` flag of `hub_id`.
pub fn set_needs_resync(
    tx: &Transaction<'_>,
    hub_id: &str,
    needs_resync: bool,
    now: i64,
) -> Result<(), DbError> {
    ensure_peer(tx, hub_id, now)?;
    tx.execute(
        "UPDATE s2s_peers SET needs_resync = ?2, updated_at = ?3 WHERE hub_id = ?1",
        params![hub_id, needs_resync, now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    const LIMITS: Limits = Limits {
        ttl_ms: 1_000,
        max_entries: 3,
        max_bytes: 100,
    };

    fn deliver(gid: &str, seq: i64, size: i64) -> NewEntry<'_> {
        NewEntry::Deliver { gid, seq, size }
    }

    async fn ids(db: &Db, peer: &'static str) -> Vec<i64> {
        db.read(move |conn| head(conn, peer, 0, 100))
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.id)
            .collect()
    }

    #[tokio::test]
    async fn enqueue_dedups_and_keeps_fifo_order() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            enqueue(tx, "h1", deliver("g", 1, 10), &LIMITS, 5)?;
            enqueue(tx, "h1", NewEntry::DeviceList { user_id: "u" }, &LIMITS, 5)?;
            enqueue(tx, "h2", deliver("g", 1, 10), &LIMITS, 5)?;
            let again = enqueue(tx, "h1", deliver("g", 1, 10), &LIMITS, 5)?;
            assert!(!again.queued);
            let list = enqueue(tx, "h1", NewEntry::DeviceList { user_id: "u" }, &LIMITS, 6)?;
            assert!(!list.queued);
            assert_eq!(
                list.backlog,
                Backlog {
                    entries: 2,
                    bytes: 11
                }
            );
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let entries = db.read(|conn| head(conn, "h1", 5, 10)).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, Kind::Deliver);
        assert_eq!(
            (entries[0].gid.as_deref(), entries[0].seq),
            (Some("g"), Some(1))
        );
        assert_eq!(entries[0].expires_at, 1_005);
        assert_eq!(entries[1].user_id.as_deref(), Some("u"));
        assert_eq!(
            db.read(pending_peers).await.unwrap(),
            [("h1".to_owned(), 0), ("h2".to_owned(), 0)]
        );
    }

    #[tokio::test]
    async fn cap_evicts_oldest_deliver_entries_only() {
        let db = Db::open_in_memory().unwrap();
        let welcome = NewEntry::DeliverWelcome {
            gid: "g",
            payload: &[0; 20],
        };
        db.write(move |tx| {
            enqueue(tx, "h1", welcome, &LIMITS, 0)?;
            enqueue(tx, "h1", deliver("g", 1, 10), &LIMITS, 0)?;
            enqueue(tx, "h1", deliver("g", 2, 10), &LIMITS, 0)?;
            let full = enqueue(tx, "h1", deliver("g", 3, 10), &LIMITS, 0)?;
            assert_eq!((full.queued, full.evicted), (true, 1));
            assert_eq!(
                full.backlog,
                Backlog {
                    entries: 3,
                    bytes: 40
                }
            );
            // Too big for the byte cap even alone: evicted itself.
            let huge = enqueue(tx, "h1", deliver("g", 4, 200), &LIMITS, 0)?;
            assert_eq!((huge.queued, huge.evicted), (false, 3));
            // Never evicted: queued beyond the cap.
            let more = enqueue(tx, "h1", NewEntry::DeviceList { user_id: "u" }, &LIMITS, 0)?;
            assert!(more.queued);
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let kinds: Vec<_> = db
            .read(|conn| head(conn, "h1", 0, 10))
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.kind)
            .collect();
        assert_eq!(kinds, [Kind::DeliverWelcome, Kind::DeviceList]);
        assert!(db.read(|conn| peer(conn, "h1")).await.unwrap().needs_resync);
    }

    #[tokio::test]
    async fn expire_deletes_and_marks_resync() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            enqueue(tx, "h1", deliver("g", 1, 1), &LIMITS, 0)?;
            enqueue(tx, "h2", NewEntry::DeviceList { user_id: "u" }, &LIMITS, 0)?;
            enqueue(tx, "h1", deliver("g", 2, 1), &LIMITS, 500)
        })
        .await
        .unwrap();
        assert!(
            db.read(|conn| head(conn, "h1", 1_000, 10))
                .await
                .unwrap()
                .len()
                == 1
        );
        let expired = db.write(|tx| expire(tx, 1_000)).await.unwrap();
        assert_eq!(
            expired,
            [
                Expired {
                    peer_hub_id: "h1".into(),
                    kind: Kind::Deliver,
                    count: 1
                },
                Expired {
                    peer_hub_id: "h2".into(),
                    kind: Kind::DeviceList,
                    count: 1
                },
            ]
        );
        assert_eq!(ids(&db, "h1").await.len(), 1);
        assert!(db.read(|conn| peer(conn, "h1")).await.unwrap().needs_resync);
        assert!(!db.read(|conn| peer(conn, "h2")).await.unwrap().needs_resync);
    }

    #[tokio::test]
    async fn peer_state_tracks_failures_and_recovery() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            assert_eq!(record_failure(tx, "h1", 100, 0)?, 1);
            assert_eq!(record_failure(tx, "h1", 300, 50)?, 2);
            set_needs_resync(tx, "h1", true, 50)
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(pending_peers).await.unwrap(),
            [("h1".to_owned(), 300)]
        );
        db.write(|tx| record_connected(tx, "h1", 60)).await.unwrap();
        assert_eq!(
            db.read(|conn| peer(conn, "h1")).await.unwrap(),
            Peer {
                failures: 0,
                next_attempt_at: 0,
                needs_resync: true,
                last_connected_at: Some(60),
            }
        );
        db.write(|tx| {
            record_failure(tx, "h1", 100, 70)?;
            record_success(tx, "h1", 80)?;
            set_needs_resync(tx, "h1", false, 80)
        })
        .await
        .unwrap();
        assert_eq!(db.read(|conn| peer(conn, "h1")).await.unwrap().failures, 0);
        assert!(db.read(pending_peers).await.unwrap().is_empty());

        let entry = db
            .write(|tx| {
                enqueue(tx, "h1", deliver("g", 1, 1), &LIMITS, 0)?;
                let id = tx.last_insert_rowid();
                count_attempt(tx, &[id])?;
                Ok::<_, DbError>(id)
            })
            .await
            .unwrap();
        assert_eq!(
            db.read(|conn| head(conn, "h1", 0, 1)).await.unwrap()[0].attempts,
            1
        );
        assert_eq!(
            db.write(move |tx| delete(tx, &[entry, entry + 1]))
                .await
                .unwrap(),
            1
        );
    }
}
