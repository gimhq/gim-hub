//! MLS KeyPackages of devices.
//!
//! Claimed packages are kept (with `claimed_at` set) so that the Add proposal
//! of a later Commit can be mapped back to the claimed device by `kp_ref`.
//! A device's last-resort package is handed out without being used up; when
//! it is replaced, the old row is retired (kept as claimed) for the same
//! reason.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// KeyPackage stock of one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stock {
    /// Unclaimed one-time packages.
    pub available: u32,
    pub has_last_resort: bool,
}

/// A package handed out by [`claim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub key_package: Vec<u8>,
    pub last_resort: bool,
}

/// Adds a one-time package. A package whose `kp_ref` is already stored is
/// ignored.
pub fn insert_one_time(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    key_package: &[u8],
    kp_ref: &[u8],
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO key_packages (user_id, device_id, key_package, kp_ref, last_resort, created_at) \
         VALUES (?1, ?2, ?3, ?4, 0, ?5) ON CONFLICT (kp_ref) DO NOTHING",
        params![user_id, device_id, key_package, kp_ref, now],
    )?;
    Ok(())
}

/// Replaces the device's last-resort package. The previous one is retired
/// (no longer handed out, still resolvable by `kp_ref`).
pub fn replace_last_resort(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    key_package: &[u8],
    kp_ref: &[u8],
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "UPDATE key_packages SET last_resort = 0, claimed_at = coalesce(claimed_at, ?3) \
         WHERE user_id = ?1 AND device_id = ?2 AND last_resort = 1 AND kp_ref != ?4",
        params![user_id, device_id, now, kp_ref],
    )?;
    tx.execute(
        "INSERT INTO key_packages (user_id, device_id, key_package, kp_ref, last_resort, created_at) \
         VALUES (?1, ?2, ?3, ?4, 1, ?5) ON CONFLICT (kp_ref) DO NOTHING",
        params![user_id, device_id, key_package, kp_ref, now],
    )?;
    Ok(())
}

/// KeyPackage stock of one device.
pub fn stock(conn: &Connection, user_id: &str, device_id: &str) -> Result<Stock, DbError> {
    let (available, has_last_resort) = conn.query_row(
        "SELECT \
         count(*) FILTER (WHERE last_resort = 0 AND claimed_at IS NULL), \
         count(*) FILTER (WHERE last_resort = 1) \
         FROM key_packages WHERE user_id = ?1 AND device_id = ?2",
        params![user_id, device_id],
        |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
    )?;
    Ok(Stock {
        available,
        has_last_resort: has_last_resort > 0,
    })
}

/// Active devices of `user_id`, or only `device_id` if given and active.
pub fn active_devices(
    conn: &Connection,
    user_id: &str,
    device_id: Option<&str>,
) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT device_id FROM devices WHERE user_id = ?1 AND active = 1 \
         AND (?2 IS NULL OR device_id = ?2) ORDER BY device_id",
    )?;
    let devices = stmt
        .query_map(params![user_id, device_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(devices)
}

/// Claims the device's oldest unclaimed one-time package, or else hands out
/// its last-resort package (which stays available). `None` if the device has
/// neither.
pub fn claim(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    now: i64,
) -> Result<Option<Claimed>, DbError> {
    let row: Option<(i64, Vec<u8>, bool)> = tx
        .query_row(
            "SELECT id, key_package, last_resort FROM key_packages \
             WHERE user_id = ?1 AND device_id = ?2 \
             AND ((last_resort = 0 AND claimed_at IS NULL) OR last_resort = 1) \
             ORDER BY last_resort, id LIMIT 1",
            params![user_id, device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((id, key_package, last_resort)) = row else {
        return Ok(None);
    };
    tx.execute(
        "UPDATE key_packages SET claimed_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    Ok(Some(Claimed {
        key_package,
        last_resort,
    }))
}

/// Marks the stored, unclaimed package `kp_ref` claimed ("burned", a copy
/// of it was handed out by another hub). Returns its owner
/// `(user_id, device_id)` if a package was burned.
pub fn burn(
    tx: &Transaction<'_>,
    kp_ref: &[u8],
    now: i64,
) -> Result<Option<(String, String)>, DbError> {
    let owner = tx
        .query_row(
            "UPDATE key_packages SET claimed_at = ?2 \
             WHERE kp_ref = ?1 AND claimed_at IS NULL RETURNING user_id, device_id",
            params![kp_ref, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(owner)
}

/// Owner `(user_id, device_id)` of a claimed (or last-resort) package.
pub fn claimed_owner(
    conn: &Connection,
    kp_ref: &[u8],
) -> Result<Option<(String, String)>, DbError> {
    let owner = conn
        .query_row(
            "SELECT user_id, device_id FROM key_packages \
             WHERE kp_ref = ?1 AND claimed_at IS NOT NULL",
            [kp_ref],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        users::{self, Device, StoredDeviceList},
        Db,
    };

    fn setup(tx: &Transaction<'_>) -> Result<(), DbError> {
        users::put_device_list(
            tx,
            &StoredDeviceList {
                user_id: "u1".into(),
                root_pubkey: vec![0; 32],
                device_list: Vec::new(),
                seq: 1,
                updated_at: 0,
            },
        )?;
        for (device_id, active) in [("d1", true), ("d2", false)] {
            users::put_device(
                tx,
                &Device {
                    user_id: "u1".into(),
                    device_id: device_id.into(),
                    sig_pubkey: vec![0; 32],
                    active,
                },
                0,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn one_time_first_then_last_resort() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            setup(tx)?;
            insert_one_time(tx, "u1", "d1", b"kp1", b"r1", 1)?;
            insert_one_time(tx, "u1", "d1", b"kp1", b"r1", 1)?;
            insert_one_time(tx, "u1", "d1", b"kp2", b"r2", 1)?;
            replace_last_resort(tx, "u1", "d1", b"lr1", b"l1", 1)?;
            replace_last_resort(tx, "u1", "d1", b"lr2", b"l2", 1)
        })
        .await
        .unwrap();
        let stock_now = db.read(|conn| stock(conn, "u1", "d1")).await.unwrap();
        assert_eq!(
            stock_now,
            Stock {
                available: 2,
                has_last_resort: true
            }
        );

        let claimed = db
            .write(|tx| {
                (0..4)
                    .map(|_| claim(tx, "u1", "d1", 2))
                    .collect::<Result<Vec<_>, _>>()
            })
            .await
            .unwrap();
        let packages: Vec<_> = claimed
            .iter()
            .map(|c| {
                c.as_ref()
                    .map(|c| (c.key_package.as_slice(), c.last_resort))
            })
            .collect();
        assert_eq!(
            packages,
            [
                Some((&b"kp1"[..], false)),
                Some((&b"kp2"[..], false)),
                Some((&b"lr2"[..], true)),
                Some((&b"lr2"[..], true)),
            ]
        );
        let owner = db.read(|conn| claimed_owner(conn, b"r2")).await.unwrap();
        assert_eq!(owner, Some(("u1".into(), "d1".into())));
        // The replaced last-resort package stays resolvable.
        assert!(db
            .read(|conn| claimed_owner(conn, b"l1"))
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            db.read(|conn| active_devices(conn, "u1", None))
                .await
                .unwrap(),
            ["d1"]
        );
        assert!(db
            .read(|conn| active_devices(conn, "u1", Some("d2")))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn burn_marks_only_unclaimed_packages() {
        let db = Db::open_in_memory().unwrap();
        let burned = db
            .write(|tx| {
                setup(tx)?;
                insert_one_time(tx, "u1", "d1", b"kp1", b"r1", 1)?;
                insert_one_time(tx, "u1", "d1", b"kp2", b"r2", 1)?;
                Ok::<_, DbError>((
                    burn(tx, b"r1", 2)?,
                    burn(tx, b"r1", 3)?,
                    burn(tx, b"unknown", 3)?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(burned, (Some(("u1".into(), "d1".into())), None, None));
        let claimed = db.write(|tx| claim(tx, "u1", "d1", 4)).await.unwrap();
        assert_eq!(claimed.unwrap().key_package, b"kp2");
    }
}
