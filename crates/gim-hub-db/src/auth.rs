//! Sign-in challenges and device sessions.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// A device session, identified by the SHA-256 of its bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    pub expires_at: i64,
}

/// Stores a session for `token_hash`.
pub fn create_session(
    tx: &Transaction<'_>,
    token_hash: &[u8; 32],
    session: &Session,
    now: i64,
) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO sessions (token_hash, user_id, device_id, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            token_hash.as_slice(),
            session.user_id,
            session.device_id,
            now,
            session.expires_at
        ],
    )?;
    Ok(())
}

/// The session for `token_hash` if it has not expired at `now` and its device
/// is still active.
pub fn lookup_session(
    conn: &Connection,
    token_hash: &[u8; 32],
    now: i64,
) -> Result<Option<Session>, DbError> {
    let session = conn
        .query_row(
            "SELECT s.user_id, s.device_id, s.expires_at FROM sessions s \
             JOIN devices d ON d.user_id = s.user_id AND d.device_id = s.device_id \
             WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND d.active = 1",
            params![token_hash.as_slice(), now],
            |row| {
                Ok(Session {
                    user_id: row.get(0)?,
                    device_id: row.get(1)?,
                    expires_at: row.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        users::{self, Device, StoredDeviceList},
        Db,
    };

    async fn db_with_device(active: bool) -> Db {
        let db = Db::open_in_memory().unwrap();
        db.write(move |tx| {
            users::put_device_list(
                tx,
                &StoredDeviceList {
                    user_id: "u1".into(),
                    root_pubkey: vec![1; 32],
                    device_list: vec![0; 8],
                    seq: 1,
                    updated_at: 0,
                },
            )?;
            users::put_device(
                tx,
                &Device {
                    user_id: "u1".into(),
                    device_id: "d1".into(),
                    sig_pubkey: vec![2; 32],
                    active,
                },
                0,
            )?;
            create_session(
                tx,
                &[7; 32],
                &Session {
                    user_id: "u1".into(),
                    device_id: "d1".into(),
                    expires_at: 1_000,
                },
                0,
            )
        })
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn lookup_finds_live_session() {
        let db = db_with_device(true).await;
        let session = db
            .read(|conn| lookup_session(conn, &[7; 32], 999))
            .await
            .unwrap();
        assert_eq!(
            session,
            Some(Session {
                user_id: "u1".into(),
                device_id: "d1".into(),
                expires_at: 1_000,
            })
        );
        let unknown = db
            .read(|conn| lookup_session(conn, &[8; 32], 999))
            .await
            .unwrap();
        assert_eq!(unknown, None);
    }

    #[tokio::test]
    async fn lookup_rejects_expired_session() {
        let db = db_with_device(true).await;
        let session = db
            .read(|conn| lookup_session(conn, &[7; 32], 1_000))
            .await
            .unwrap();
        assert_eq!(session, None);
    }

    #[tokio::test]
    async fn lookup_rejects_inactive_device() {
        let db = db_with_device(false).await;
        let session = db
            .read(|conn| lookup_session(conn, &[7; 32], 0))
            .await
            .unwrap();
        assert_eq!(session, None);
    }
}
