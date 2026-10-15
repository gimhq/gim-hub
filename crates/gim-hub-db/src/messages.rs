//! Per-group message log (Commits, Proposals and application messages) and
//! the group lookups needed to accept a message.
//!
//! `seq` is assigned by bumping `groups.last_seq` inside the caller's write
//! transaction, so sequence numbers are gap-free and unique per group.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::DbError;

/// A stored message. `kind` is `commit`, `proposal` or `application`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub gid: String,
    pub seq: i64,
    pub epoch: i64,
    pub kind: String,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub client_id: String,
    pub payload: Vec<u8>,
    /// Unique opaque message ID (assigned by the owning hub).
    pub message_id: String,
    pub created_at: i64,
}

/// A membership change recorded with a Commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Added,
    Removed,
}

impl Change {
    fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
        }
    }
}

/// Devices added and removed by one Commit, as `(user_id, device_id)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Membership {
    pub added: Vec<(String, String)>,
    pub removed: Vec<(String, String)>,
}

/// A message to append with [`append`].
#[derive(Debug, Clone)]
pub struct NewMessage<'a> {
    pub gid: &'a str,
    pub epoch: i64,
    pub kind: &'a str,
    pub sender_user_id: &'a str,
    pub sender_device_id: &'a str,
    pub client_id: &'a str,
    pub payload: &'a [u8],
    /// Hash of a Commit or Proposal, used to detect retries of the same
    /// message.
    pub commit_hash: Option<&'a [u8]>,
    /// Unique opaque message ID.
    pub message_id: &'a str,
}

const COLUMNS: &str = "gid, seq, epoch, kind, sender_user_id, sender_device_id, client_id, \
                       payload, message_id, created_at";

fn from_row(row: &Row<'_>) -> rusqlite::Result<StoredMessage> {
    Ok(StoredMessage {
        gid: row.get(0)?,
        seq: row.get(1)?,
        epoch: row.get(2)?,
        kind: row.get(3)?,
        sender_user_id: row.get(4)?,
        sender_device_id: row.get(5)?,
        client_id: row.get(6)?,
        payload: row.get(7)?,
        message_id: row.get(8)?,
        created_at: row.get(9)?,
    })
}

/// The message a device sent earlier with `client_id` in a group.
pub fn find_by_client_id(
    conn: &Connection,
    gid: &str,
    sender_device_id: &str,
    client_id: &str,
) -> Result<Option<StoredMessage>, DbError> {
    let message = conn
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM messages \
                 WHERE gid = ?1 AND sender_device_id = ?2 AND client_id = ?3"
            ),
            params![gid, sender_device_id, client_id],
            from_row,
        )
        .optional()?;
    Ok(message)
}

/// Appends a message with the group's next `seq` and returns it. The group
/// must exist.
pub fn append(
    tx: &Transaction<'_>,
    message: &NewMessage<'_>,
    now: i64,
) -> Result<StoredMessage, DbError> {
    let seq: i64 = tx.query_row(
        "UPDATE groups SET last_seq = last_seq + 1 WHERE gid = ?1 RETURNING last_seq",
        [message.gid],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO messages (gid, seq, epoch, kind, sender_user_id, sender_device_id, \
         client_id, payload, commit_hash, message_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            message.gid,
            seq,
            message.epoch,
            message.kind,
            message.sender_user_id,
            message.sender_device_id,
            message.client_id,
            message.payload,
            message.commit_hash,
            message.message_id,
            now
        ],
    )?;
    Ok(StoredMessage {
        gid: message.gid.to_owned(),
        seq,
        epoch: message.epoch,
        kind: message.kind.to_owned(),
        sender_user_id: message.sender_user_id.to_owned(),
        sender_device_id: message.sender_device_id.to_owned(),
        client_id: message.client_id.to_owned(),
        payload: message.payload.to_vec(),
        message_id: message.message_id.to_owned(),
        created_at: now,
    })
}

/// The message `seq` of a group.
pub fn get(conn: &Connection, gid: &str, seq: i64) -> Result<Option<StoredMessage>, DbError> {
    let message = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM messages WHERE gid = ?1 AND seq = ?2"),
            params![gid, seq],
            from_row,
        )
        .optional()?;
    Ok(message)
}

/// The newest message of a group.
pub fn latest(conn: &Connection, gid: &str) -> Result<Option<StoredMessage>, DbError> {
    let message = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM messages WHERE gid = ?1 ORDER BY seq DESC LIMIT 1"),
            [gid],
            from_row,
        )
        .optional()?;
    Ok(message)
}

/// Records that the Commit `seq` of `gid` added or removed a device.
pub fn insert_membership(
    tx: &Transaction<'_>,
    gid: &str,
    seq: i64,
    change: Change,
    user_id: &str,
    device_id: &str,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT OR IGNORE INTO commit_membership (gid, seq, change, user_id, device_id) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![gid, seq, change.as_str(), user_id, device_id],
    )?;
    Ok(())
}

/// Devices added and removed by the Commit `seq` of `gid`, ordered.
pub fn membership(conn: &Connection, gid: &str, seq: i64) -> Result<Membership, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT change, user_id, device_id FROM commit_membership \
         WHERE gid = ?1 AND seq = ?2 ORDER BY change, user_id, device_id",
    )?;
    let mut membership = Membership::default();
    let rows = stmt.query_map(params![gid, seq], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (change, user_id, device_id) = row?;
        if change == Change::Added.as_str() {
            membership.added.push((user_id, device_id));
        } else {
            membership.removed.push((user_id, device_id));
        }
    }
    Ok(membership)
}

/// Users removed from `gid` by a Commit with `seq >= from_seq`, ordered.
pub fn removed_since(conn: &Connection, gid: &str, from_seq: i64) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT user_id FROM commit_membership \
         WHERE gid = ?1 AND seq >= ?2 AND change = 'removed' ORDER BY user_id",
    )?;
    let users = stmt
        .query_map(params![gid, from_seq], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(users)
}

/// Messages of a group with `seq >= from_seq`, ascending, at most `limit`.
pub fn list_from(
    conn: &Connection,
    gid: &str,
    from_seq: i64,
    limit: u32,
) -> Result<Vec<StoredMessage>, DbError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM messages WHERE gid = ?1 AND seq >= ?2 ORDER BY seq LIMIT ?3"
    ))?;
    let messages = stmt
        .query_map(params![gid, from_seq, limit], from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(messages)
}

/// `(seq, framing epoch, kind)` of the Commit or Proposal with
/// `commit_hash` in `gid`.
pub fn find_commit(
    conn: &Connection,
    gid: &str,
    commit_hash: &[u8],
) -> Result<Option<(u64, u64, String)>, DbError> {
    let found = conn
        .query_row(
            "SELECT seq, epoch, kind FROM messages WHERE gid = ?1 AND commit_hash = ?2",
            params![gid, commit_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(found)
}

/// Makes the Proposal `seq` of `gid`, sent in `epoch`, resolvable under each
/// of its `proposal_refs` until the epoch advances.
pub fn insert_pending_proposal(
    tx: &Transaction<'_>,
    gid: &str,
    epoch: i64,
    seq: i64,
    proposal_refs: &[Vec<u8>],
) -> Result<(), DbError> {
    let mut stmt = tx.prepare_cached(
        "INSERT OR IGNORE INTO pending_proposals (gid, proposal_ref, epoch, seq) \
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for proposal_ref in proposal_refs {
        stmt.execute(params![gid, proposal_ref, epoch, seq])?;
    }
    Ok(())
}

/// The Proposal of `gid` sent in `epoch` with `proposal_ref`, if still
/// pending.
pub fn pending_proposal(
    conn: &Connection,
    gid: &str,
    epoch: i64,
    proposal_ref: &[u8],
) -> Result<Option<StoredMessage>, DbError> {
    let message = conn
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM messages WHERE gid = ?1 AND seq = \
                 (SELECT seq FROM pending_proposals \
                  WHERE gid = ?1 AND proposal_ref = ?2 AND epoch = ?3)"
            ),
            params![gid, proposal_ref, epoch],
            from_row,
        )
        .optional()?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        groups::{group_epoch, is_member, member_devices},
        Db,
    };

    async fn db_with_group() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            tx.execute(
                "INSERT INTO groups (gid, kind, epoch, created_by_user_id, created_by_device_id, \
                 created_at) VALUES ('g1', 'group', 3, 'u1', 'd1', 0)",
                [],
            )?;
            tx.execute(
                "INSERT INTO group_members (gid, user_id, device_id, added_at) VALUES \
                 ('g1', 'u2', 'd1', 0), ('g1', 'u1', 'd1', 0)",
                [],
            )?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        db
    }

    fn new_message<'a>(client_id: &'a str, message_id: &'a str) -> NewMessage<'a> {
        NewMessage {
            gid: "g1",
            epoch: 3,
            kind: "application",
            sender_user_id: "u1",
            sender_device_id: "d1",
            client_id,
            payload: b"mls",
            commit_hash: None,
            message_id,
        }
    }

    #[tokio::test]
    async fn group_lookups() {
        let db = db_with_group().await;
        assert_eq!(db.read(|c| group_epoch(c, "g1")).await.unwrap(), Some(3));
        assert_eq!(db.read(|c| group_epoch(c, "nope")).await.unwrap(), None);
        assert!(db.read(|c| is_member(c, "g1", "u1", "d1")).await.unwrap());
        assert!(!db.read(|c| is_member(c, "g1", "u1", "d2")).await.unwrap());
        assert_eq!(
            db.read(|c| member_devices(c, "g1")).await.unwrap(),
            [("u1".into(), "d1".into()), ("u2".into(), "d1".into())]
        );
    }

    #[tokio::test]
    async fn append_assigns_seq_and_lists() {
        let db = db_with_group().await;
        let (first, second) = db
            .write(|tx| {
                Ok::<_, DbError>((
                    append(tx, &new_message("c1", "m1"), 10)?,
                    append(tx, &new_message("c2", "m2"), 20)?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((first.seq, second.seq), (1, 2));
        let last_seq: i64 = db
            .read(|c| {
                c.query_row("SELECT last_seq FROM groups WHERE gid = 'g1'", [], |r| {
                    r.get(0)
                })
                .map_err(DbError::from)
            })
            .await
            .unwrap();
        assert_eq!(last_seq, 2);

        let found = db
            .read(|c| find_by_client_id(c, "g1", "d1", "c2"))
            .await
            .unwrap();
        assert_eq!(found, Some(second.clone()));
        assert_eq!(
            db.read(|c| find_by_client_id(c, "g1", "d1", "c3"))
                .await
                .unwrap(),
            None
        );

        let listed = db.read(|c| list_from(c, "g1", 2, 10)).await.unwrap();
        assert_eq!(listed, std::slice::from_ref(&second));
        let listed = db.read(|c| list_from(c, "g1", 1, 1)).await.unwrap();
        assert_eq!(listed, std::slice::from_ref(&first));
        assert_eq!(db.read(|c| get(c, "g1", 1)).await.unwrap(), Some(first));
        assert_eq!(db.read(|c| get(c, "g1", 3)).await.unwrap(), None);
        assert_eq!(db.read(|c| latest(c, "g1")).await.unwrap(), Some(second));
        assert_eq!(db.read(|c| latest(c, "g2")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn commit_membership_is_recorded() {
        let db = db_with_group().await;
        db.write(|tx| {
            insert_membership(tx, "g1", 2, Change::Added, "u3", "d3")?;
            insert_membership(tx, "g1", 2, Change::Added, "u3", "d3")?;
            insert_membership(tx, "g1", 2, Change::Removed, "u2", "d1")?;
            insert_membership(tx, "g1", 4, Change::Removed, "u4", "d4")
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|c| membership(c, "g1", 2)).await.unwrap(),
            Membership {
                added: vec![("u3".into(), "d3".into())],
                removed: vec![("u2".into(), "d1".into())],
            }
        );
        assert_eq!(
            db.read(|c| membership(c, "g1", 3)).await.unwrap(),
            Membership::default()
        );
        assert_eq!(
            db.read(|c| removed_since(c, "g1", 2)).await.unwrap(),
            ["u2", "u4"]
        );
        assert_eq!(
            db.read(|c| removed_since(c, "g1", 3)).await.unwrap(),
            ["u4"]
        );
    }

    #[tokio::test]
    async fn pending_proposals_resolve_until_the_epoch_advances() {
        let db = db_with_group().await;
        let stored = db
            .write(|tx| {
                let stored = append(
                    tx,
                    &NewMessage {
                        kind: "proposal",
                        commit_hash: Some(b"h1"),
                        ..new_message("c1", "m1")
                    },
                    10,
                )?;
                insert_pending_proposal(
                    tx,
                    "g1",
                    3,
                    stored.seq,
                    &[b"r1".to_vec(), b"r2".to_vec()],
                )?;
                Ok::<_, DbError>(stored)
            })
            .await
            .unwrap();
        assert_eq!(
            db.read(|c| find_commit(c, "g1", b"h1")).await.unwrap(),
            Some((1, 3, "proposal".to_owned()))
        );
        for proposal_ref in [b"r1", b"r2"] {
            assert_eq!(
                db.read(move |c| pending_proposal(c, "g1", 3, proposal_ref))
                    .await
                    .unwrap(),
                Some(stored.clone())
            );
        }
        assert_eq!(
            db.read(|c| pending_proposal(c, "g1", 2, b"r1"))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.read(|c| pending_proposal(c, "g1", 3, b"r3"))
                .await
                .unwrap(),
            None
        );
        db.write(|tx| crate::groups::set_epoch(tx, "g1", 4))
            .await
            .unwrap();
        assert_eq!(
            db.read(|c| pending_proposal(c, "g1", 3, b"r1"))
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn duplicate_client_id_is_rejected() {
        let db = db_with_group().await;
        let result = db
            .write(|tx| {
                append(tx, &new_message("c1", "m1"), 10)?;
                append(tx, &new_message("c1", "m2"), 10)
            })
            .await;
        assert!(result.is_err());
    }
}
