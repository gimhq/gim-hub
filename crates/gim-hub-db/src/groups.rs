//! Groups, their delivery-service roster and the Welcomes stored by Commits.
//!
//! A group whose gid is prefixed by another hub's `hub_id` is a replica
//! (docs/federation.md §5.4): `replica_from_seq` holds its first local seq.

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

/// Replica state of a remote-owned group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replica {
    /// First seq held locally.
    pub from_seq: u64,
    /// No local members are left; the replica no longer receives messages.
    pub detached: bool,
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

/// Stores (or replaces) the replica of a remote-owned group from a snapshot
/// as of seq `group.last_seq`: the group, its roster (without leaf indexes)
/// and `replica_from_seq = last_seq + 1`. A replaced replica loses its log.
pub fn create_replica(
    tx: &Transaction<'_>,
    group: &Group,
    members: &[(String, String)],
    now: i64,
) -> Result<(), DbError> {
    tx.execute("DELETE FROM groups WHERE gid = ?1", [&group.gid])?;
    tx.execute(
        "INSERT INTO groups (gid, kind, epoch, last_seq, created_by_user_id, \
         created_by_device_id, created_at, replica_from_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            group.gid,
            group.kind,
            group.epoch,
            group.last_seq,
            group.created_by_user_id,
            group.created_by_device_id,
            group.created_at,
            group.last_seq + 1
        ],
    )?;
    for (user_id, device_id) in members {
        add_replica_member(tx, &group.gid, user_id, device_id, now)?;
    }
    Ok(())
}

/// Adds a member device of a replica (leaf index unknown).
pub fn add_replica_member(
    tx: &Transaction<'_>,
    gid: &str,
    user_id: &str,
    device_id: &str,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT OR IGNORE INTO group_members (gid, user_id, device_id, added_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![gid, user_id, device_id, now],
    )?;
    Ok(())
}

/// The replica state of `gid`; `None` if the group is unknown or owned here.
pub fn replica(conn: &Connection, gid: &str) -> Result<Option<Replica>, DbError> {
    let row: Option<(Option<u64>, bool)> = conn
        .query_row(
            "SELECT replica_from_seq, detached FROM groups WHERE gid = ?1",
            [gid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(
        row.and_then(|(from_seq, detached)| {
            from_seq.map(|from_seq| Replica { from_seq, detached })
        }),
    )
}

/// Marks a replica detached (or attached again).
pub fn set_detached(tx: &Transaction<'_>, gid: &str, detached: bool) -> Result<(), DbError> {
    tx.execute(
        "UPDATE groups SET detached = ?2 WHERE gid = ?1",
        params![gid, detached],
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

/// Sets the group's epoch.
pub fn set_epoch(tx: &Transaction<'_>, gid: &str, epoch: u64) -> Result<(), DbError> {
    tx.execute(
        "UPDATE groups SET epoch = ?2 WHERE gid = ?1",
        params![gid, epoch],
    )?;
    Ok(())
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

/// Member devices of a group whose user is local here (has a row in
/// `users`), as `(user_id, device_id)`, ordered. Remote members live on
/// other hubs and get no events here.
pub fn local_member_devices(
    conn: &Connection,
    gid: &str,
) -> Result<Vec<(String, String)>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT m.user_id, m.device_id FROM group_members AS m \
         WHERE m.gid = ?1 AND EXISTS (SELECT 1 FROM users AS u WHERE u.user_id = m.user_id) \
         ORDER BY m.user_id, m.device_id",
    )?;
    let members = stmt
        .query_map([gid], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(members)
}

/// Groups owned by `own_hub_id` with a member whose stored hosting record
/// lists `hub_id`, ordered.
pub fn owned_with_member_on(
    conn: &Connection,
    own_hub_id: &str,
    hub_id: &str,
) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT m.gid FROM group_members AS m \
         JOIN hosting_records AS h ON h.user_id = m.user_id \
         WHERE substr(m.gid, 1, length(?1) + 1) = ?1 || '/' \
         AND EXISTS (SELECT 1 FROM json_each(h.hub_ids) WHERE value = ?2) \
         ORDER BY m.gid",
    )?;
    let gids = stmt
        .query_map(params![own_hub_id, hub_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(gids)
}

/// Active devices of the other users sharing at least one group with
/// `user_id`, as distinct `(user_id, device_id)`, ordered.
pub fn peer_devices(conn: &Connection, user_id: &str) -> Result<Vec<(String, String)>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT d.user_id, d.device_id \
         FROM group_members AS mine \
         JOIN group_members AS peer ON peer.gid = mine.gid AND peer.user_id <> mine.user_id \
         JOIN devices AS d ON d.user_id = peer.user_id AND d.device_id = peer.device_id \
         WHERE mine.user_id = ?1 AND d.active = 1 \
         ORDER BY d.user_id, d.device_id",
    )?;
    let peers = stmt
        .query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peers)
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
            set_epoch(tx, "h1/g1", 1)
        })
        .await
        .unwrap();

        let got = db.read(|conn| get(conn, "h1/g1")).await.unwrap().unwrap();
        assert_eq!((got.epoch, got.last_seq), (1, 0));
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

    #[tokio::test]
    async fn replicas_are_created_replaced_and_detached() {
        let db = Db::open_in_memory().unwrap();
        let group = Group {
            gid: "h2/g1".into(),
            kind: "group".into(),
            epoch: 3,
            last_seq: 7,
            created_by_user_id: "u2".into(),
            created_by_device_id: "d2".into(),
            created_at: 10,
        };
        let stored = group.clone();
        db.write(move |tx| {
            create(
                tx,
                &Group {
                    gid: "h1/own".into(),
                    ..stored.clone()
                },
            )?;
            create_replica(tx, &stored, &[("u1".into(), "d1".into())], 20)?;
            tx.execute(
                "INSERT INTO users (user_id, root_pubkey, device_list, device_list_seq, \
                 created_at, updated_at) VALUES ('u1', x'00', x'', 0, 0, 0)",
                [],
            )?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|conn| replica(conn, "h2/g1")).await.unwrap(),
            Some(Replica {
                from_seq: 8,
                detached: false
            })
        );
        assert_eq!(db.read(|conn| replica(conn, "h1/own")).await.unwrap(), None);
        assert_eq!(db.read(|conn| replica(conn, "nope")).await.unwrap(), None);
        assert_eq!(
            db.read(|conn| local_member_devices(conn, "h2/g1"))
                .await
                .unwrap(),
            [("u1".to_owned(), "d1".to_owned())]
        );
        assert!(db
            .read(|conn| local_member_devices(conn, "h1/own"))
            .await
            .unwrap()
            .is_empty());

        let replaced = Group {
            last_seq: 9,
            ..group
        };
        db.write(move |tx| {
            set_detached(tx, "h2/g1", true)?;
            create_replica(tx, &replaced, &[("u3".into(), "d3".into())], 30)
        })
        .await
        .unwrap();
        let got = db.read(|conn| replica(conn, "h2/g1")).await.unwrap();
        assert_eq!(
            got,
            Some(Replica {
                from_seq: 10,
                detached: false
            })
        );
        let members = db.read(|conn| member_devices(conn, "h2/g1")).await.unwrap();
        assert_eq!(members, [("u3".to_owned(), "d3".to_owned())]);
    }

    #[tokio::test]
    async fn owned_groups_with_members_on_a_hub() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for gid in ["h1/a", "h1/b", "h2/c"] {
                create(
                    tx,
                    &Group {
                        gid: gid.into(),
                        kind: "group".into(),
                        epoch: 0,
                        last_seq: 0,
                        created_by_user_id: "u1".into(),
                        created_by_device_id: "d1".into(),
                        created_at: 0,
                    },
                )?;
                add_member(tx, gid, "u3", "d3", 1, 0)?;
            }
            add_member(tx, "h1/b", "u4", "d4", 2, 0)?;
            for (user, hubs) in [("u3", r#"["h3"]"#), ("u4", r#"["h4","h3"]"#)] {
                tx.execute(
                    "INSERT INTO hosting_records (user_id, record, seq, expires_at, hosted, \
                     hub_ids, fetched_at, updated_at) VALUES (?1, x'00', 1, 1, 0, ?2, 0, 0)",
                    [user, hubs],
                )?;
            }
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let on = |hub: &'static str| db.read(move |conn| owned_with_member_on(conn, "h1", hub));
        assert_eq!(on("h3").await.unwrap(), ["h1/a", "h1/b"]);
        assert_eq!(on("h4").await.unwrap(), ["h1/b"]);
        assert!(on("h5").await.unwrap().is_empty());
    }
}
