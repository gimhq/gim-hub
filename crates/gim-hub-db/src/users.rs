//! Users, their stored DeviceList and the devices derived from it.
//!
//! This module stores bytes verbatim; verifying DeviceLists and deriving the
//! device set is the caller's job.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// A user's stored DeviceList.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeviceList {
    pub user_id: String,
    pub root_pubkey: Vec<u8>,
    /// gim-core DeviceList CBOR as uploaded.
    pub device_list: Vec<u8>,
    pub seq: i64,
    pub updated_at: i64,
}

/// A device certified by a user's DeviceList.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub user_id: String,
    pub device_id: String,
    pub sig_pubkey: Vec<u8>,
    pub active: bool,
}

/// The stored DeviceList of `user_id`, if any.
pub fn get_device_list(
    conn: &Connection,
    user_id: &str,
) -> Result<Option<StoredDeviceList>, DbError> {
    let list = conn
        .query_row(
            "SELECT user_id, root_pubkey, device_list, device_list_seq, updated_at \
             FROM users WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(StoredDeviceList {
                    user_id: row.get(0)?,
                    root_pubkey: row.get(1)?,
                    device_list: row.get(2)?,
                    seq: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(list)
}

/// Creates the user or replaces its DeviceList. Returns true if the user was
/// created.
pub fn put_device_list(tx: &Transaction<'_>, list: &StoredDeviceList) -> Result<bool, DbError> {
    let updated = tx.execute(
        "UPDATE users SET root_pubkey = ?2, device_list = ?3, device_list_seq = ?4, \
         updated_at = ?5 WHERE user_id = ?1",
        params![
            list.user_id,
            list.root_pubkey,
            list.device_list,
            list.seq,
            list.updated_at
        ],
    )?;
    if updated > 0 {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO users (user_id, root_pubkey, device_list, device_list_seq, created_at, \
         updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            list.user_id,
            list.root_pubkey,
            list.device_list,
            list.seq,
            list.updated_at
        ],
    )?;
    Ok(true)
}

/// Inserts or updates one device of an existing user.
pub fn put_device(tx: &Transaction<'_>, device: &Device, now: i64) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO devices (user_id, device_id, sig_pubkey, active, updated_at, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?5) \
         ON CONFLICT (user_id, device_id) DO UPDATE SET \
         sig_pubkey = excluded.sig_pubkey, active = excluded.active, updated_at = excluded.updated_at",
        params![
            device.user_id,
            device.device_id,
            device.sig_pubkey,
            device.active,
            now
        ],
    )?;
    Ok(())
}

/// Makes `active` (device ID, signing key) the only active devices of
/// `user_id`: upserts them as active, marks every other stored device of the
/// user inactive and deletes the sessions of every inactive device. Returns
/// the IDs of devices that were active before and are not anymore.
pub fn set_active_devices(
    tx: &Transaction<'_>,
    user_id: &str,
    active: &[(String, Vec<u8>)],
    now: i64,
) -> Result<Vec<String>, DbError> {
    let mut deactivated = active_device_ids(tx, user_id)?;
    deactivated.retain(|id| !active.iter().any(|(active_id, _)| active_id == id));
    tx.execute(
        "UPDATE devices SET active = 0, updated_at = ?2 WHERE user_id = ?1 AND active = 1",
        params![user_id, now],
    )?;
    for (device_id, sig_pubkey) in active {
        put_device(
            tx,
            &Device {
                user_id: user_id.to_owned(),
                device_id: device_id.clone(),
                sig_pubkey: sig_pubkey.clone(),
                active: true,
            },
            now,
        )?;
    }
    tx.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND device_id IN \
         (SELECT device_id FROM devices WHERE user_id = ?1 AND active = 0)",
        [user_id],
    )?;
    Ok(deactivated)
}

/// IDs of the active devices of `user_id`, ascending.
pub fn active_device_ids(conn: &Connection, user_id: &str) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT device_id FROM devices WHERE user_id = ?1 AND active = 1 ORDER BY device_id",
    )?;
    let ids = stmt
        .query_map([user_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    fn list(seq: i64) -> StoredDeviceList {
        StoredDeviceList {
            user_id: "u1".into(),
            root_pubkey: vec![1; 32],
            device_list: vec![seq as u8; 8],
            seq,
            updated_at: 1_000 + seq,
        }
    }

    #[tokio::test]
    async fn put_then_replace_device_list() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.write(|tx| put_device_list(tx, &list(1))).await.unwrap());
        assert!(!db.write(|tx| put_device_list(tx, &list(2))).await.unwrap());
        let stored = db.read(|conn| get_device_list(conn, "u1")).await.unwrap();
        assert_eq!(stored, Some(list(2)));
        assert_eq!(
            db.read(|conn| get_device_list(conn, "u2")).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn set_active_devices_deactivates_the_rest() {
        let db = Db::open_in_memory().unwrap();
        let key = |id: &str| (id.to_owned(), vec![9; 32]);
        let first = db
            .write(move |tx| {
                put_device_list(tx, &list(1))?;
                set_active_devices(tx, "u1", &[key("d1"), key("d2")], 10)
            })
            .await
            .unwrap();
        assert!(first.is_empty());
        let deactivated = db
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO sessions (token_hash, user_id, device_id, created_at, \
                     expires_at) VALUES (x'01', 'u1', 'd2', 0, 100)",
                    [],
                )?;
                set_active_devices(tx, "u1", &[key("d1"), key("d3")], 20)
            })
            .await
            .unwrap();
        assert_eq!(deactivated, ["d2"]);
        let (active, sessions) = db
            .read(|conn| {
                let sessions: i64 =
                    conn.query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))?;
                Ok::<_, DbError>((active_device_ids(conn, "u1")?, sessions))
            })
            .await
            .unwrap();
        assert_eq!(active, ["d1", "d3"]);
        assert_eq!(sessions, 0);
    }
}
