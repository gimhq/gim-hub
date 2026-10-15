//! Blob metadata; the content lives in `$DATA_DIR/blobs/` under a file
//! name derived from the blob id (docs/api-v2.md, Blobs).
//!
//! `blobs` holds the blobs uploaded on this hub, `remote_blobs` the cached
//! copies of blobs fetched from their origin hub (docs/federation.md §5.6).

use std::collections::BTreeSet;

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::{hosting, remote_identity, DbError};

/// Metadata of a stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub blob_id: String,
    pub size: i64,
    pub uploader_user_id: String,
    pub uploader_device_id: String,
    pub created_at: i64,
}

/// Records a stored blob.
pub fn insert(tx: &Transaction<'_>, blob: &Blob) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO blobs (blob_id, size, uploader_user_id, uploader_device_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            blob.blob_id,
            blob.size,
            blob.uploader_user_id,
            blob.uploader_device_id,
            blob.created_at
        ],
    )?;
    Ok(())
}

/// Metadata of one blob.
pub fn get(conn: &Connection, blob_id: &str) -> Result<Option<Blob>, DbError> {
    let blob = conn
        .query_row(
            "SELECT blob_id, size, uploader_user_id, uploader_device_id, created_at \
             FROM blobs WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok(Blob {
                    blob_id: row.get(0)?,
                    size: row.get(1)?,
                    uploader_user_id: row.get(2)?,
                    uploader_device_id: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(blob)
}

/// A cached copy of a blob uploaded on another hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBlob {
    pub blob_id: String,
    pub size: i64,
    pub fetched_at: i64,
}

/// Records (or replaces) a cached copy of a remote blob.
pub fn put_remote(tx: &Transaction<'_>, blob: &RemoteBlob) -> Result<(), DbError> {
    tx.execute(
        "INSERT OR REPLACE INTO remote_blobs (blob_id, size, fetched_at) VALUES (?1, ?2, ?3)",
        params![blob.blob_id, blob.size, blob.fetched_at],
    )?;
    Ok(())
}

/// The cached copy of remote blob `blob_id`, if any.
pub fn get_remote(conn: &Connection, blob_id: &str) -> Result<Option<RemoteBlob>, DbError> {
    let blob = conn
        .query_row(
            "SELECT blob_id, size, fetched_at FROM remote_blobs WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok(RemoteBlob {
                    blob_id: row.get(0)?,
                    size: row.get(1)?,
                    fetched_at: row.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(blob)
}

/// The hubs that may fetch the blobs of `user_id` (docs/federation.md
/// §5.6): [`remote_identity::device_list_peer_hubs`] plus the hubs listed
/// for every user sharing a group with `user_id`, whoever owns the group
/// (replicas included). Sorted, without `own_hub_id`.
pub fn reader_hubs(
    conn: &Connection,
    user_id: &str,
    own_hub_id: &str,
) -> Result<Vec<String>, DbError> {
    let mut hubs: BTreeSet<String> =
        remote_identity::device_list_peer_hubs(conn, user_id, own_hub_id)?
            .into_iter()
            .collect();
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT peer.user_id FROM group_members AS mine \
         JOIN group_members AS peer ON peer.gid = mine.gid AND peer.user_id <> mine.user_id \
         WHERE mine.user_id = ?1",
    )?;
    let peers = stmt
        .query_map([user_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for peer in peers {
        if let Some(record) = hosting::get(conn, &peer)? {
            hubs.extend(record.hub_ids);
        }
    }
    hubs.remove(own_hub_id);
    Ok(hubs.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        groups::{self, Group},
        hosting::StoredHostingRecord,
        Db,
    };

    #[tokio::test]
    async fn insert_and_get() {
        let db = Db::open_in_memory().unwrap();
        let blob = Blob {
            blob_id: "b_1".into(),
            size: 5,
            uploader_user_id: "u1".into(),
            uploader_device_id: "d1".into(),
            created_at: 10,
        };
        let stored = blob.clone();
        db.write(move |tx| insert(tx, &stored)).await.unwrap();
        assert_eq!(db.read(|c| get(c, "b_1")).await.unwrap(), Some(blob));
        assert_eq!(db.read(|c| get(c, "b_2")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn remote_copies_are_separate_from_uploads() {
        let db = Db::open_in_memory().unwrap();
        let copy = RemoteBlob {
            blob_id: "h2/b_1".into(),
            size: 5,
            fetched_at: 10,
        };
        let stored = copy.clone();
        db.write(move |tx| {
            put_remote(tx, &stored)?;
            put_remote(tx, &stored)
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|c| get_remote(c, "h2/b_1")).await.unwrap(),
            Some(copy)
        );
        assert_eq!(db.read(|c| get(c, "h2/b_1")).await.unwrap(), None);
        assert_eq!(db.read(|c| get_remote(c, "h2/b_2")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn reader_hubs_include_member_hubs_of_groups_owned_elsewhere() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for (gid, members) in [
                // A replica of a group owned by h3: bob's hub h2 and the
                // owner h3 count.
                ("h3/g1", &["carol", "alice", "bob"][..]),
                // Alice is not a member: frank's hub does not count.
                ("h1/g2", &["carol", "frank"][..]),
            ] {
                groups::create(
                    tx,
                    &Group {
                        gid: gid.into(),
                        kind: "group".into(),
                        epoch: 0,
                        last_seq: 0,
                        created_by_user_id: members[0].into(),
                        created_by_device_id: "d".into(),
                        created_at: 0,
                    },
                )?;
                for (leaf, member) in (1..).zip(&members[1..]) {
                    groups::add_member(tx, gid, member, "d", leaf, 0)?;
                }
            }
            for (user, hubs) in [
                ("alice", &["h1", "h6"][..]),
                ("bob", &["h2"][..]),
                ("carol", &["h3"][..]),
                ("frank", &["h5"][..]),
            ] {
                hosting::put(
                    tx,
                    &StoredHostingRecord {
                        user_id: user.into(),
                        record: vec![0],
                        seq: 1,
                        expires_at: 1,
                        hosted: false,
                        hub_ids: hubs.iter().map(|h| (*h).to_owned()).collect(),
                        fetched_at: 0,
                        published_at: None,
                        updated_at: 0,
                    },
                )?;
            }
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|c| reader_hubs(c, "alice", "h1")).await.unwrap(),
            ["h2", "h3", "h6"]
        );
        assert_eq!(
            db.read(|c| reader_hubs(c, "nobody", "h1")).await.unwrap(),
            Vec::<String>::new()
        );
    }
}
