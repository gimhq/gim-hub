//! Groups, their delivery-service roster and the Welcomes stored by Commits.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// A stored group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub gid: String,
    /// `direct` or `group`.
    pub kind: String,
    pub epoch: u64,
    pub last_seq: u64,
    pub created_by_user_id: String,
    pub created_by_device_id: String,
    pub created_at: i64,
}

/// A member device and its MLS leaf index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub user_id: String,
    pub device_id: String,
    pub leaf_index: Option<u32>,
}

const GROUP_COLUMNS: &str =
    "g.gid, g.kind, g.epoch, g.last_seq, g.created_by_user_id, g.created_by_device_id, g.created_at";

fn group_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Group> {
    Ok(Group {
        gid: row.get(0)?,
        kind: row.get(1)?,
        epoch: row.get(2)?,
        last_seq: row.get(3)?,
        created_by_user_id: row.get(4)?,
        created_by_device_id: row.get(5)?,
        created_at: row.get(6)?,
    })
}

/// Stores a new group at epoch 0 whose creator device is the only member,
/// at leaf 0.
pub fn create(tx: &Transaction<'_>, group: &Group) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO groups (gid, kind, epoch, last_seq, created_by_user_id, \
         created_by_device_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            group.gid,
            group.kind,
            group.epoch,
            group.last_seq,
            group.created_by_user_id,
            group.created_by_device_id,
            group.created_at
        ],
    )?;
    add_member(
        tx,
        &group.gid,
        &group.created_by_user_id,
        &group.created_by_device_id,
        0,
        group.created_at,
    )
}

/// The group `gid`, if it exists.
pub fn get(conn: &Connection, gid: &str) -> Result<Option<Group>, DbError> {
    let group = conn
        .query_row(
            &format!("SELECT {GROUP_COLUMNS} FROM groups g WHERE g.gid = ?1"),
            [gid],
            group_row,
        )
        .optional()?;
    Ok(group)
}

/// Groups the device is a member of, oldest first.
pub fn list_for_device(
    conn: &Connection,
    user_id: &str,
    device_id: &str,
) -> Result<Vec<Group>, DbError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {GROUP_COLUMNS} FROM groups g \
         JOIN group_members m ON m.gid = g.gid \
         WHERE m.user_id = ?1 AND m.device_id = ?2 ORDER BY g.created_at, g.gid"
    ))?;
    let groups = stmt
        .query_map(params![user_id, device_id], group_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(groups)
}

/// Members of `gid` ordered by leaf index.
pub fn members(conn: &Connection, gid: &str) -> Result<Vec<Member>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT user_id, device_id, leaf_index FROM group_members WHERE gid = ?1 \
         ORDER BY leaf_index, user_id, device_id",
    )?;
    let members = stmt
        .query_map([gid], |row| {
            Ok(Member {
                user_id: row.get(0)?,
                device_id: row.get(1)?,
                leaf_index: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(members)
}

/// Adds a member device at `leaf_index`.
pub fn add_member(
    tx: &Transaction<'_>,
    gid: &str,
    user_id: &str,
    device_id: &str,
    leaf_index: u32,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO group_members (gid, user_id, device_id, leaf_index, added_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![gid, user_id, device_id, leaf_index, now],
    )?;
    Ok(())
}

/// Removes a member device.
pub fn remove_member(
    tx: &Transaction<'_>,
    gid: &str,
    user_id: &str,
    device_id: &str,
) -> Result<(), DbError> {
    tx.execute(
        "DELETE FROM group_members WHERE gid = ?1 AND user_id = ?2 AND device_id = ?3",
        params![gid, user_id, device_id],
    )?;
    Ok(())
}

/// Sets the group's epoch and last sequence number.
pub fn advance(tx: &Transaction<'_>, gid: &str, epoch: u64, last_seq: u64) -> Result<(), DbError> {
    tx.execute(
        "UPDATE groups SET epoch = ?2, last_seq = ?3 WHERE gid = ?1",
        params![gid, epoch, last_seq],
    )?;
    Ok(())
}

/// Stores a Welcome for one device until it is acknowledged. `payload` is the
/// `welcome` event data as JSON.
pub fn insert_pending_welcome(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    gid: &str,
    payload: &str,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO pending_welcomes (user_id, device_id, gid, payload, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, device_id, gid, payload, now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn create_list_and_change_roster() {
        let db = Db::open_in_memory().unwrap();
        let group = Group {
            gid: "h1/g1".into(),
            kind: "group".into(),
            epoch: 0,
            last_seq: 0,
            created_by_user_id: "u1".into(),
            created_by_device_id: "d1".into(),
            created_at: 10,
        };
        let stored = group.clone();
        db.write(move |tx| {
            create(tx, &stored)?;
            add_member(tx, "h1/g1", "u2", "d2", 1, 11)?;
            advance(tx, "h1/g1", 1, 1)
        })
        .await
        .unwrap();

        let got = db.read(|conn| get(conn, "h1/g1")).await.unwrap().unwrap();
        assert_eq!((got.epoch, got.last_seq), (1, 1));
        let listed = db
            .read(|conn| list_for_device(conn, "u2", "d2"))
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        let leaves: Vec<_> = db
            .read(|conn| members(conn, "h1/g1"))
            .await
            .unwrap()
            .into_iter()
            .map(|m| (m.device_id, m.leaf_index))
            .collect();
        assert_eq!(leaves, [("d1".into(), Some(0)), ("d2".into(), Some(1))]);

        db.write(|tx| remove_member(tx, "h1/g1", "u2", "d2"))
            .await
            .unwrap();
        assert!(db
            .read(|conn| list_for_device(conn, "u2", "d2"))
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.read(|conn| get(conn, "nope")).await.unwrap(), None);
    }
}
