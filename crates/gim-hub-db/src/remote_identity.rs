//! Remote identity (docs/federation.md §5.1, §5.2): the cache of remote
//! users' DeviceLists, the ledger of KeyPackages claimed from other hubs, and
//! the peer hubs a user's DeviceList is propagated to.
//!
//! This module stores bytes verbatim; verifying DeviceLists and the seq rules
//! are the caller's job.

use std::collections::BTreeSet;

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::{hosting, DbError};

/// A cached DeviceList of a remote user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRemoteDeviceList {
    pub user_id: String,
    pub root_pubkey: Vec<u8>,
    /// gim-core DeviceList CBOR as received.
    pub device_list: Vec<u8>,
    pub seq: i64,
    /// Last verification from a remote source.
    pub fetched_at: i64,
    pub updated_at: i64,
}

/// A KeyPackage claimed from another hub on behalf of a local user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteClaim {
    pub kp_ref: Vec<u8>,
    pub user_id: String,
    pub device_id: String,
    pub target_hub_id: String,
    pub claimed_by_user_id: String,
    pub claimed_by_device_id: String,
    pub claimed_at: i64,
}

/// The cached DeviceList of remote user `user_id`, if any.
pub fn get_device_list(
    conn: &Connection,
    user_id: &str,
) -> Result<Option<StoredRemoteDeviceList>, DbError> {
    let list = conn
        .query_row(
            "SELECT user_id, root_pubkey, device_list, device_list_seq, fetched_at, updated_at \
             FROM remote_device_lists WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(StoredRemoteDeviceList {
                    user_id: row.get(0)?,
                    root_pubkey: row.get(1)?,
                    device_list: row.get(2)?,
                    seq: row.get(3)?,
                    fetched_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )
        .optional()?;
    Ok(list)
}

/// Stores or replaces the cached DeviceList of `list.user_id`.
pub fn put_device_list(tx: &Transaction<'_>, list: &StoredRemoteDeviceList) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO remote_device_lists \
         (user_id, root_pubkey, device_list, device_list_seq, fetched_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT (user_id) DO UPDATE SET root_pubkey = excluded.root_pubkey, \
         device_list = excluded.device_list, device_list_seq = excluded.device_list_seq, \
         fetched_at = excluded.fetched_at, updated_at = excluded.updated_at",
        params![
            list.user_id,
            list.root_pubkey,
            list.device_list,
            list.seq,
            list.fetched_at,
            list.updated_at,
        ],
    )?;
    Ok(())
}

/// Sets `fetched_at` of the cached DeviceList of `user_id` if it still has
/// `seq`.
pub fn touch_fetched(
    tx: &Transaction<'_>,
    user_id: &str,
    seq: i64,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "UPDATE remote_device_lists SET fetched_at = ?3 \
         WHERE user_id = ?1 AND device_list_seq = ?2",
        params![user_id, seq, now],
    )?;
    Ok(())
}

/// Records a claimed remote KeyPackage. A reused (last-resort) package keeps
/// one row, describing its latest claim.
pub fn insert_claim(tx: &Transaction<'_>, claim: &RemoteClaim) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO remote_kp_claims (kp_ref, user_id, device_id, target_hub_id, \
         claimed_by_user_id, claimed_by_device_id, claimed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
         ON CONFLICT (kp_ref) DO UPDATE SET user_id = excluded.user_id, \
         device_id = excluded.device_id, target_hub_id = excluded.target_hub_id, \
         claimed_by_user_id = excluded.claimed_by_user_id, \
         claimed_by_device_id = excluded.claimed_by_device_id, \
         claimed_at = excluded.claimed_at",
        params![
            claim.kp_ref,
            claim.user_id,
            claim.device_id,
            claim.target_hub_id,
            claim.claimed_by_user_id,
            claim.claimed_by_device_id,
            claim.claimed_at,
        ],
    )?;
    Ok(())
}

/// The claim of remote KeyPackage `kp_ref`, if this hub brokered it.
pub fn get_claim(conn: &Connection, kp_ref: &[u8]) -> Result<Option<RemoteClaim>, DbError> {
    let claim = conn
        .query_row(
            "SELECT kp_ref, user_id, device_id, target_hub_id, claimed_by_user_id, \
             claimed_by_device_id, claimed_at FROM remote_kp_claims WHERE kp_ref = ?1",
            [kp_ref],
            |row| {
                Ok(RemoteClaim {
                    kp_ref: row.get(0)?,
                    user_id: row.get(1)?,
                    device_id: row.get(2)?,
                    target_hub_id: row.get(3)?,
                    claimed_by_user_id: row.get(4)?,
                    claimed_by_device_id: row.get(5)?,
                    claimed_at: row.get(6)?,
                })
            },
        )
        .optional()?;
    Ok(claim)
}

/// Deletes claims made before `cutoff`; returns how many.
pub fn prune_claims(tx: &Transaction<'_>, cutoff: i64) -> Result<usize, DbError> {
    Ok(tx.execute(
        "DELETE FROM remote_kp_claims WHERE claimed_at < ?1",
        [cutoff],
    )?)
}

/// Peer hubs that must learn about `user_id`'s DeviceList updates (§5.1):
/// the other hubs listed in `user_id`'s stored hosting record (co-hosts,
/// docs/multihoming.md §3.2), the owning hubs of the groups `user_id` is in,
/// and the hubs listed in the hosting records of the other members of the
/// groups `own_hub_id` owns that contain `user_id`. Sorted, without
/// `own_hub_id`.
pub fn device_list_peer_hubs(
    conn: &Connection,
    user_id: &str,
    own_hub_id: &str,
) -> Result<Vec<String>, DbError> {
    let mut hubs = BTreeSet::new();
    if let Some(record) = hosting::get(conn, user_id)? {
        hubs.extend(record.hub_ids);
    }
    let mut stmt =
        conn.prepare_cached("SELECT DISTINCT gid FROM group_members WHERE user_id = ?1")?;
    for gid in stmt.query_map([user_id], |row| row.get::<_, String>(0))? {
        if let Some((owner, _)) = gid?.split_once('/') {
            hubs.insert(owner.to_owned());
        }
    }
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT peer.user_id FROM group_members AS mine \
         JOIN group_members AS peer ON peer.gid = mine.gid AND peer.user_id <> mine.user_id \
         WHERE mine.user_id = ?1 AND substr(mine.gid, 1, length(?2) + 1) = ?2 || '/'",
    )?;
    let peers = stmt
        .query_map(params![user_id, own_hub_id], |row| row.get::<_, String>(0))?
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

    fn list(seq: i64, fetched_at: i64) -> StoredRemoteDeviceList {
        StoredRemoteDeviceList {
            user_id: "u1".into(),
            root_pubkey: vec![1; 32],
            device_list: vec![seq as u8],
            seq,
            fetched_at,
            updated_at: fetched_at,
        }
    }

    #[tokio::test]
    async fn device_list_cache_replace_and_touch() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            put_device_list(tx, &list(1, 10))?;
            put_device_list(tx, &list(2, 20))?;
            touch_fetched(tx, "u1", 1, 99)?;
            touch_fetched(tx, "u1", 2, 30)
        })
        .await
        .unwrap();
        let stored = db.read(|conn| get_device_list(conn, "u1")).await.unwrap();
        assert_eq!(
            stored,
            Some(StoredRemoteDeviceList {
                fetched_at: 30,
                ..list(2, 20)
            })
        );
        assert!(db
            .read(|conn| get_device_list(conn, "u2"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn claims_are_recorded_and_pruned() {
        let db = Db::open_in_memory().unwrap();
        let claim = |kp_ref: &[u8], by: &str, at: i64| RemoteClaim {
            kp_ref: kp_ref.to_vec(),
            user_id: "u1".into(),
            device_id: "d1".into(),
            target_hub_id: "h2".into(),
            claimed_by_user_id: by.into(),
            claimed_by_device_id: "b1".into(),
            claimed_at: at,
        };
        let (first, again, other) = (
            claim(b"r1", "a", 1),
            claim(b"r1", "b", 5),
            claim(b"r2", "a", 2),
        );
        let latest = again.clone();
        db.write(move |tx| {
            insert_claim(tx, &first)?;
            insert_claim(tx, &again)?;
            insert_claim(tx, &other)
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|conn| get_claim(conn, b"r1")).await.unwrap(),
            Some(latest)
        );
        assert_eq!(db.write(|tx| prune_claims(tx, 3)).await.unwrap(), 1);
        assert!(db
            .read(|conn| get_claim(conn, b"r2"))
            .await
            .unwrap()
            .is_none());
        assert!(db
            .read(|conn| get_claim(conn, b"r1"))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn peer_hubs_are_co_hosts_owners_and_member_hubs_of_owned_groups() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for (gid, members) in [
                // Owned here: carol's hubs (h3) and dave's (no record) count.
                ("h1/g1", &["alice", "carol", "dave"][..]),
                // Owned by h2: only the owner counts, not erin's hub.
                ("h2/g2", &["alice", "erin"][..]),
                // Alice is not a member.
                ("h1/g3", &["carol", "frank"][..]),
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
                // Alice's own co-host h6 counts.
                ("alice", &["h1", "h6"][..]),
                ("carol", &["h3", "h1"][..]),
                ("erin", &["h4"][..]),
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
        let hubs = db
            .read(|conn| device_list_peer_hubs(conn, "alice", "h1"))
            .await
            .unwrap();
        assert_eq!(hubs, ["h2", "h3", "h6"]);
        assert!(db
            .read(|conn| device_list_peer_hubs(conn, "nobody", "h1"))
            .await
            .unwrap()
            .is_empty());
    }
}
