//! Encrypted recovery backups, one per user, stored verbatim.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// A stored recovery backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBackup {
    pub backup: Vec<u8>,
    pub updated_at: i64,
}

/// Stores or replaces the backup of an existing user.
pub fn put(tx: &Transaction<'_>, user_id: &str, backup: &[u8], now: i64) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO recovery_backups (user_id, backup, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT (user_id) DO UPDATE SET \
         backup = excluded.backup, updated_at = excluded.updated_at",
        params![user_id, backup, now],
    )?;
    Ok(())
}

/// The backup of `user_id`, if any.
pub fn get(conn: &Connection, user_id: &str) -> Result<Option<StoredBackup>, DbError> {
    let backup = conn
        .query_row(
            "SELECT backup, updated_at FROM recovery_backups WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(StoredBackup {
                    backup: row.get(0)?,
                    updated_at: row.get(1)?,
                })
            },
        )
        .optional()?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        users::{put_device_list, StoredDeviceList},
        Db,
    };

    #[tokio::test]
    async fn put_replaces_backup() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            put_device_list(
                tx,
                &StoredDeviceList {
                    user_id: "u1".into(),
                    root_pubkey: vec![1; 32],
                    device_list: vec![0; 8],
                    seq: 1,
                    updated_at: 0,
                },
            )?;
            put(tx, "u1", b"one", 10)?;
            put(tx, "u1", b"two", 20)
        })
        .await
        .unwrap();
        assert_eq!(
            db.read(|conn| get(conn, "u1")).await.unwrap(),
            Some(StoredBackup {
                backup: b"two".to_vec(),
                updated_at: 20,
            })
        );
        assert_eq!(db.read(|conn| get(conn, "u2")).await.unwrap(), None);
    }
}
