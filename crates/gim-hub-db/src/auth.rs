//! Sign-in challenges and device sessions.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// An issued sign-in challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Hex SHA-256 of the challenge nonce.
    pub challenge_id: String,
    pub user_id: String,
    pub device_id: String,
    /// The AuthChallenge bytes sent to the device.
    pub challenge: Vec<u8>,
    pub expires_at: i64,
}

/// Whether `device_id` of `user_id` is stored and active.
pub fn device_is_active(
    conn: &Connection,
    user_id: &str,
    device_id: &str,
) -> Result<bool, DbError> {
    let active = conn
        .query_row(
            "SELECT active FROM devices WHERE user_id = ?1 AND device_id = ?2",
            params![user_id, device_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(active.unwrap_or(false))
}

/// Stores an issued challenge and deletes the challenges expired at `now`.
pub fn insert_challenge(
    tx: &Transaction<'_>,
    challenge: &Challenge,
    now: i64,
) -> Result<(), DbError> {
    tx.execute("DELETE FROM auth_challenges WHERE expires_at <= ?1", [now])?;
    tx.execute(
        "INSERT INTO auth_challenges (challenge_id, user_id, device_id, challenge, created_at, \
         expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            challenge.challenge_id,
            challenge.user_id,
            challenge.device_id,
            challenge.challenge,
            now,
            challenge.expires_at
        ],
    )?;
    Ok(())
}

/// Consumes the challenge `challenge_id`: deletes it and returns it if it
/// had not expired at `now`. A challenge is therefore returned at most once.
pub fn take_challenge(
    tx: &Transaction<'_>,
    challenge_id: &str,
    now: i64,
) -> Result<Option<Challenge>, DbError> {
    let challenge = tx
        .query_row(
            "DELETE FROM auth_challenges WHERE challenge_id = ?1 \
             RETURNING challenge_id, user_id, device_id, challenge, expires_at",
            [challenge_id],
            |row| {
                Ok(Challenge {
                    challenge_id: row.get(0)?,
                    user_id: row.get(1)?,
                    device_id: row.get(2)?,
                    challenge: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(challenge.filter(|challenge| challenge.expires_at > now))
}

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

    fn challenge(id: &str, expires_at: i64) -> Challenge {
        Challenge {
            challenge_id: id.into(),
            user_id: "u1".into(),
            device_id: "d1".into(),
            challenge: vec![9; 4],
            expires_at,
        }
    }

    #[tokio::test]
    async fn device_activity() {
        let db = db_with_device(true).await;
        let active = |user: &'static str, device: &'static str| {
            let db = db.clone();
            async move {
                db.read(move |conn| device_is_active(conn, user, device))
                    .await
                    .unwrap()
            }
        };
        assert!(active("u1", "d1").await);
        assert!(!active("u1", "d2").await);
        assert!(!active("u2", "d1").await);
        let db = db_with_device(false).await;
        assert!(!db
            .read(|conn| device_is_active(conn, "u1", "d1"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn challenge_is_taken_once() {
        let db = db_with_device(true).await;
        db.write(|tx| insert_challenge(tx, &challenge("c1", 100), 0))
            .await
            .unwrap();
        let taken = db.write(|tx| take_challenge(tx, "c1", 99)).await.unwrap();
        assert_eq!(taken, Some(challenge("c1", 100)));
        let again = db.write(|tx| take_challenge(tx, "c1", 99)).await.unwrap();
        assert_eq!(again, None);
        let unknown = db.write(|tx| take_challenge(tx, "c2", 99)).await.unwrap();
        assert_eq!(unknown, None);
    }

    #[tokio::test]
    async fn expired_challenges_are_rejected_and_pruned() {
        let db = db_with_device(true).await;
        db.write(|tx| {
            insert_challenge(tx, &challenge("c1", 100), 0)?;
            insert_challenge(tx, &challenge("c2", 100), 0)
        })
        .await
        .unwrap();
        let expired = db.write(|tx| take_challenge(tx, "c1", 100)).await.unwrap();
        assert_eq!(expired, None);
        db.write(|tx| insert_challenge(tx, &challenge("c3", 300), 100))
            .await
            .unwrap();
        let count = db
            .read(|conn| -> Result<i64, DbError> {
                Ok(conn.query_row("SELECT COUNT(*) FROM auth_challenges", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
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
