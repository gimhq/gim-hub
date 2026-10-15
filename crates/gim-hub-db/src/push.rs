//! Push registrations: at most one per device.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::DbError;

/// A device's push registration. `provider` is one of `apns`, `fcm`,
/// `unifiedpush` or `log`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub user_id: String,
    pub device_id: String,
    pub provider: String,
    pub token: String,
    pub app_id: Option<String>,
    pub sandbox: bool,
    /// UnifiedPush only: the user agent's uncompressed P-256 public key
    /// (RFC 8291 `p256dh`).
    pub p256dh: Option<Vec<u8>>,
    /// UnifiedPush only: the RFC 8291 authentication secret.
    pub auth: Option<Vec<u8>>,
    pub updated_at: i64,
}

fn from_row(row: &Row<'_>) -> rusqlite::Result<Registration> {
    Ok(Registration {
        user_id: row.get(0)?,
        device_id: row.get(1)?,
        provider: row.get(2)?,
        token: row.get(3)?,
        app_id: row.get(4)?,
        sandbox: row.get(5)?,
        updated_at: row.get(6)?,
        p256dh: row.get(7)?,
        auth: row.get(8)?,
    })
}

/// Stores `registration`, replacing the device's previous one.
pub fn put(tx: &Transaction<'_>, registration: &Registration) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO push_registrations \
         (user_id, device_id, provider, token, app_id, sandbox, updated_at, p256dh, auth) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
         ON CONFLICT (user_id, device_id) DO UPDATE SET provider = excluded.provider, \
         token = excluded.token, app_id = excluded.app_id, sandbox = excluded.sandbox, \
         updated_at = excluded.updated_at, p256dh = excluded.p256dh, auth = excluded.auth",
        params![
            registration.user_id,
            registration.device_id,
            registration.provider,
            registration.token,
            registration.app_id,
            registration.sandbox,
            registration.updated_at,
            registration.p256dh,
            registration.auth,
        ],
    )?;
    Ok(())
}

/// Removes the device's registration; returns whether one existed.
pub fn delete(tx: &Transaction<'_>, user_id: &str, device_id: &str) -> Result<bool, DbError> {
    let deleted = tx.execute(
        "DELETE FROM push_registrations WHERE user_id = ?1 AND device_id = ?2",
        params![user_id, device_id],
    )?;
    Ok(deleted > 0)
}

/// Removes the device's registration only if it still has `provider` and
/// `token` (a provider rejected that token; a newer registration stays).
pub fn delete_token(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
    provider: &str,
    token: &str,
) -> Result<bool, DbError> {
    let deleted = tx.execute(
        "DELETE FROM push_registrations \
         WHERE user_id = ?1 AND device_id = ?2 AND provider = ?3 AND token = ?4",
        params![user_id, device_id, provider, token],
    )?;
    Ok(deleted > 0)
}

/// The registration of a device that is still active, if any.
pub fn get_active(
    conn: &Connection,
    user_id: &str,
    device_id: &str,
) -> Result<Option<Registration>, DbError> {
    let registration = conn
        .prepare_cached(
            "SELECT r.user_id, r.device_id, r.provider, r.token, r.app_id, r.sandbox, \
             r.updated_at, r.p256dh, r.auth FROM push_registrations r JOIN devices d \
             ON d.user_id = r.user_id AND d.device_id = r.device_id \
             WHERE r.user_id = ?1 AND r.device_id = ?2 AND d.active = 1",
        )?
        .query_row(params![user_id, device_id], from_row)
        .optional()?;
    Ok(registration)
}

/// The `message_id` of the stored message `(gid, seq)`, used as the push
/// collapse id.
pub fn message_id_at(conn: &Connection, gid: &str, seq: i64) -> Result<Option<String>, DbError> {
    let message_id = conn
        .prepare_cached("SELECT message_id FROM messages WHERE gid = ?1 AND seq = ?2")?
        .query_row(params![gid, seq], |row| row.get(0))
        .optional()?;
    Ok(message_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        users::{self, Device, StoredDeviceList},
        Db,
    };

    async fn seed_device(db: &Db, user_id: &str, device_id: &str, active: bool) {
        let (user_id, device_id) = (user_id.to_owned(), device_id.to_owned());
        db.write(move |tx| {
            if users::get_device_list(tx, &user_id)?.is_none() {
                users::put_device_list(
                    tx,
                    &StoredDeviceList {
                        user_id: user_id.clone(),
                        root_pubkey: vec![0; 32],
                        device_list: Vec::new(),
                        seq: 0,
                        updated_at: 0,
                    },
                )?;
            }
            users::put_device(
                tx,
                &Device {
                    user_id,
                    device_id,
                    sig_pubkey: vec![0; 32],
                    active,
                },
                0,
            )
        })
        .await
        .unwrap();
    }

    fn registration(token: &str) -> Registration {
        Registration {
            user_id: "u1".into(),
            device_id: "d1".into(),
            provider: "log".into(),
            token: token.into(),
            app_id: Some("im.g.apps".into()),
            sandbox: true,
            p256dh: Some(vec![4; 65]),
            auth: Some(vec![1; 16]),
            updated_at: 5,
        }
    }

    async fn get(db: &Db) -> Result<Option<Registration>, DbError> {
        db.read(|conn| get_active(conn, "u1", "d1")).await
    }

    #[tokio::test]
    async fn put_replaces_and_delete_token_keeps_newer() {
        let db = Db::open_in_memory().unwrap();
        seed_device(&db, "u1", "d1", true).await;

        db.write(|tx| put(tx, &registration("a"))).await.unwrap();
        assert_eq!(get(&db).await.unwrap(), Some(registration("a")));
        db.write(|tx| put(tx, &registration("b"))).await.unwrap();
        assert_eq!(get(&db).await.unwrap().unwrap().token, "b");

        let stale = db
            .write(|tx| delete_token(tx, "u1", "d1", "log", "a"))
            .await
            .unwrap();
        assert!(!stale);
        assert!(get(&db).await.unwrap().is_some());
        assert!(db
            .write(|tx| delete_token(tx, "u1", "d1", "log", "b"))
            .await
            .unwrap());
        assert!(get(&db).await.unwrap().is_none());

        db.write(|tx| put(tx, &registration("c"))).await.unwrap();
        assert!(db.write(|tx| delete(tx, "u1", "d1")).await.unwrap());
        assert!(!db.write(|tx| delete(tx, "u1", "d1")).await.unwrap());
    }

    #[tokio::test]
    async fn inactive_devices_have_no_active_registration() {
        let db = Db::open_in_memory().unwrap();
        seed_device(&db, "u1", "d1", true).await;
        db.write(|tx| put(tx, &registration("a"))).await.unwrap();
        seed_device(&db, "u1", "d1", false).await;
        assert!(db
            .read(|conn| get_active(conn, "u1", "d1"))
            .await
            .unwrap()
            .is_none());
    }
}
