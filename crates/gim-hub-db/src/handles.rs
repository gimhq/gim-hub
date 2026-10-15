//! Optional per-hub handle directory: at most one handle per user.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// Owner of `handle`, if claimed.
pub fn owner(conn: &Connection, handle: &str) -> Result<Option<String>, DbError> {
    let user_id = conn
        .query_row(
            "SELECT user_id FROM handles WHERE handle = ?1",
            [handle],
            |row| row.get(0),
        )
        .optional()?;
    Ok(user_id)
}

/// Handle of `user_id`, if any.
pub fn handle_of(conn: &Connection, user_id: &str) -> Result<Option<String>, DbError> {
    let handle = conn
        .query_row(
            "SELECT handle FROM handles WHERE user_id = ?1",
            [user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(handle)
}

/// Outcome of [`claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The handle now belongs to the user (any previous handle was released).
    Claimed,
    /// The handle belongs to another user.
    Taken,
}

/// Claims `handle` for `user_id`, releasing the user's previous handle.
/// Re-claiming the user's own handle is a no-op.
pub fn claim(
    tx: &Transaction<'_>,
    handle: &str,
    user_id: &str,
    now: i64,
) -> Result<Claim, DbError> {
    match owner(tx, handle)? {
        Some(owner) if owner == user_id => return Ok(Claim::Claimed),
        Some(_) => return Ok(Claim::Taken),
        None => {}
    }
    tx.execute("DELETE FROM handles WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "INSERT INTO handles (handle, user_id, created_at) VALUES (?1, ?2, ?3)",
        params![handle, user_id, now],
    )?;
    Ok(Claim::Claimed)
}

/// Deletes `handle`. Returns false if it was not claimed.
pub fn release(tx: &Transaction<'_>, handle: &str) -> Result<bool, DbError> {
    Ok(tx.execute("DELETE FROM handles WHERE handle = ?1", [handle])? > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        users::{put_device_list, StoredDeviceList},
        Db,
    };

    async fn db_with_users() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for user_id in ["u1", "u2"] {
                put_device_list(
                    tx,
                    &StoredDeviceList {
                        user_id: user_id.into(),
                        root_pubkey: vec![1; 32],
                        device_list: vec![0; 8],
                        seq: 1,
                        updated_at: 0,
                    },
                )?;
            }
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn claim_replace_and_release() {
        let db = db_with_users().await;
        let claim_as = |handle: &'static str, user: &'static str| {
            let db = db.clone();
            async move { db.write(move |tx| claim(tx, handle, user, 0)).await }
        };
        assert_eq!(claim_as("alice", "u1").await.unwrap(), Claim::Claimed);
        assert_eq!(claim_as("alice", "u1").await.unwrap(), Claim::Claimed);
        assert_eq!(claim_as("alice", "u2").await.unwrap(), Claim::Taken);
        assert_eq!(claim_as("alice2", "u1").await.unwrap(), Claim::Claimed);
        assert_eq!(db.read(|conn| owner(conn, "alice")).await.unwrap(), None);
        assert_eq!(
            db.read(|conn| handle_of(conn, "u1")).await.unwrap(),
            Some("alice2".to_owned())
        );
        assert!(db.write(|tx| release(tx, "alice2")).await.unwrap());
        assert!(!db.write(|tx| release(tx, "alice2")).await.unwrap());
        assert_eq!(db.read(|conn| handle_of(conn, "u1")).await.unwrap(), None);
    }
}
