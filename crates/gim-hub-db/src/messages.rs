//! Per-group message log (Commits and application messages) and the group
//! lookups needed to accept a message.
//!
//! `seq` is assigned by bumping `groups.last_seq` inside the caller's write
//! transaction, so sequence numbers are gap-free and unique per group.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::DbError;

/// A stored message. `kind` is `commit` or `application`.
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
    pub created_at: i64,
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
    /// Hash of a Commit, used to detect retries of the same Commit.
    pub commit_hash: Option<&'a [u8]>,
    /// Unique opaque message ID.
    pub message_id: &'a str,
}

const COLUMNS: &str = "gid, seq, epoch, kind, sender_user_id, sender_device_id, client_id, \
                       payload, created_at";

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
        created_at: row.get(8)?,
    })
}

/// Current epoch of a group, or `None` if the group does not exist.
pub fn group_epoch(conn: &Connection, gid: &str) -> Result<Option<i64>, DbError> {
    let epoch = conn
        .query_row("SELECT epoch FROM groups WHERE gid = ?1", [gid], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(epoch)
}

/// Whether a device is a member of a group.
pub fn is_member(
    conn: &Connection,
    gid: &str,
    user_id: &str,
    device_id: &str,
) -> Result<bool, DbError> {
    let found = conn
        .query_row(
            "SELECT 1 FROM group_members WHERE gid = ?1 AND user_id = ?2 AND device_id = ?3",
            params![gid, user_id, device_id],
            |_| Ok(()),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Member devices of a group as `(user_id, device_id)`, ordered.
pub fn member_devices(conn: &Connection, gid: &str) -> Result<Vec<(String, String)>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT user_id, device_id FROM group_members WHERE gid = ?1 \
         ORDER BY user_id, device_id",
    )?;
    let members = stmt
        .query_map([gid], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(members)
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
        created_at: now,
    })
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

/// `(seq, framing epoch)` of the Commit with `commit_hash` in `gid`.
pub fn find_commit(
    conn: &Connection,
    gid: &str,
    commit_hash: &[u8],
) -> Result<Option<(u64, u64)>, DbError> {
    let found = conn
        .query_row(
            "SELECT seq, epoch FROM messages WHERE gid = ?1 AND commit_hash = ?2",
            params![gid, commit_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

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
        assert_eq!(listed, [second]);
        let listed = db.read(|c| list_from(c, "g1", 1, 1)).await.unwrap();
        assert_eq!(listed, [first]);
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
