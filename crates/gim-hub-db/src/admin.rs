//! Queries of the admin API (docs/admin.md): aggregate counts, user and
//! device listings, suspension, session revocation and the admin audit log.
//!
//! Metadata only: nothing here reads group membership, peers of a user or
//! message metadata.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// Row counts shown on the admin overview.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub users: i64,
    /// Active devices.
    pub devices: i64,
    pub groups: i64,
    pub blobs: i64,
}

/// Counts of users, active devices, groups and blobs.
pub fn counts(conn: &Connection) -> Result<Counts, DbError> {
    Ok(conn.query_row(
        "SELECT (SELECT count(*) FROM users), \
                (SELECT count(*) FROM devices WHERE active = 1), \
                (SELECT count(*) FROM groups), \
                (SELECT count(*) FROM blobs)",
        [],
        |row| {
            Ok(Counts {
                users: row.get(0)?,
                devices: row.get(1)?,
                groups: row.get(2)?,
                blobs: row.get(3)?,
            })
        },
    )?)
}

/// A user as listed by the admin API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSummary {
    pub user_id: String,
    pub handle: Option<String>,
    pub suspended_at: Option<i64>,
    pub created_at: i64,
    /// Active devices.
    pub device_count: i64,
    /// Latest creation time of a stored session of the user.
    pub last_seen: Option<i64>,
}

const SUMMARY_COLUMNS: &str = "u.user_id, h.handle, u.suspended_at, u.created_at, \
     (SELECT count(*) FROM devices d WHERE d.user_id = u.user_id AND d.active = 1), \
     (SELECT max(s.created_at) FROM sessions s WHERE s.user_id = u.user_id)";

fn summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserSummary> {
    Ok(UserSummary {
        user_id: row.get(0)?,
        handle: row.get(1)?,
        suspended_at: row.get(2)?,
        created_at: row.get(3)?,
        device_count: row.get(4)?,
        last_seen: row.get(5)?,
    })
}

/// Users whose user ID or handle contains `query` (case-insensitive),
/// ordered by user ID, after the user ID `after`, at most `limit`.
pub fn list_users(
    conn: &Connection,
    query: Option<&str>,
    after: Option<&str>,
    limit: u32,
) -> Result<Vec<UserSummary>, DbError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {SUMMARY_COLUMNS} FROM users u LEFT JOIN handles h ON h.user_id = u.user_id \
         WHERE (?1 IS NULL OR instr(lower(u.user_id), lower(?1)) > 0 \
                OR instr(lower(coalesce(h.handle, '')), lower(?1)) > 0) \
           AND (?2 IS NULL OR u.user_id > ?2) \
         ORDER BY u.user_id LIMIT ?3"
    ))?;
    let users = stmt
        .query_map(params![query, after, limit], summary)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(users)
}

/// The user `user_id`, if stored.
pub fn user(conn: &Connection, user_id: &str) -> Result<Option<UserSummary>, DbError> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {SUMMARY_COLUMNS} FROM users u \
                 LEFT JOIN handles h ON h.user_id = u.user_id WHERE u.user_id = ?1"
            ),
            [user_id],
            summary,
        )
        .optional()?)
}

/// A device of a user, with its unexpired sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub device_id: String,
    pub created_at: i64,
    pub active: bool,
    pub sessions: Vec<SessionInfo>,
}

/// A device session; `token_hash` is the SHA-256 of its bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub token_hash: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// The stored devices of `user_id` by device ID, each with its sessions
/// unexpired at `now` (oldest first).
pub fn devices(conn: &Connection, user_id: &str, now: i64) -> Result<Vec<DeviceInfo>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT device_id, coalesce(created_at, updated_at), active FROM devices \
         WHERE user_id = ?1 ORDER BY device_id",
    )?;
    let mut devices = stmt
        .query_map([user_id], |row| {
            Ok(DeviceInfo {
                device_id: row.get(0)?,
                created_at: row.get(1)?,
                active: row.get(2)?,
                sessions: Vec::new(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut stmt = conn.prepare_cached(
        "SELECT token_hash, created_at, expires_at FROM sessions \
         WHERE user_id = ?1 AND device_id = ?2 AND expires_at > ?3 ORDER BY created_at, token_hash",
    )?;
    for device in &mut devices {
        device.sessions = stmt
            .query_map(params![user_id, device.device_id, now], |row| {
                Ok(SessionInfo {
                    token_hash: row.get(0)?,
                    created_at: row.get(1)?,
                    expires_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
    }
    Ok(devices)
}

/// Outcome of [`suspend`] and [`unsuspend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suspension {
    /// The state changed.
    Changed,
    /// The user was already in the requested state.
    Unchanged,
    /// No such user.
    NotFound,
}

/// Suspends `user_id` at `now`: sets `suspended_at` and deletes every
/// session and pending sign-in challenge of the user.
pub fn suspend(tx: &Transaction<'_>, user_id: &str, now: i64) -> Result<Suspension, DbError> {
    let changed = tx.execute(
        "UPDATE users SET suspended_at = ?2 WHERE user_id = ?1 AND suspended_at IS NULL",
        params![user_id, now],
    )?;
    if changed == 0 {
        return unchanged_or_missing(tx, user_id);
    }
    tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM auth_challenges WHERE user_id = ?1", [user_id])?;
    Ok(Suspension::Changed)
}

/// Lifts the suspension of `user_id`.
pub fn unsuspend(tx: &Transaction<'_>, user_id: &str) -> Result<Suspension, DbError> {
    let changed = tx.execute(
        "UPDATE users SET suspended_at = NULL WHERE user_id = ?1 AND suspended_at IS NOT NULL",
        [user_id],
    )?;
    if changed == 0 {
        return unchanged_or_missing(tx, user_id);
    }
    Ok(Suspension::Changed)
}

fn unchanged_or_missing(conn: &Connection, user_id: &str) -> Result<Suspension, DbError> {
    let exists = conn
        .query_row("SELECT 1 FROM users WHERE user_id = ?1", [user_id], |_| {
            Ok(())
        })
        .optional()?
        .is_some();
    Ok(if exists {
        Suspension::Unchanged
    } else {
        Suspension::NotFound
    })
}

/// Whether `user_id` is suspended.
pub fn is_suspended(conn: &Connection, user_id: &str) -> Result<bool, DbError> {
    let suspended_at: Option<Option<i64>> = conn
        .query_row(
            "SELECT suspended_at FROM users WHERE user_id = ?1",
            [user_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(suspended_at.flatten().is_some())
}

/// Deletes the sessions of device `device_id` of `user_id`. Returns the
/// number deleted, or `None` if the device is not stored.
pub fn revoke_device_sessions(
    tx: &Transaction<'_>,
    user_id: &str,
    device_id: &str,
) -> Result<Option<usize>, DbError> {
    let exists = tx
        .query_row(
            "SELECT 1 FROM devices WHERE user_id = ?1 AND device_id = ?2",
            params![user_id, device_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(None);
    }
    Ok(Some(tx.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND device_id = ?2",
        params![user_id, device_id],
    )?))
}

/// Delivery state of a peer hub known to the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    pub hub_id: String,
    /// Queued outbox entries.
    pub backlog: i64,
    /// Consecutive failed delivery attempts.
    pub failures: i64,
    pub last_connected_at: Option<i64>,
}

/// Every peer hub with outbox entries or delivery state, by hub ID.
pub fn peer_statuses(conn: &Connection) -> Result<Vec<PeerStatus>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT known.hub_id, \
                (SELECT count(*) FROM s2s_outbox o WHERE o.peer_hub_id = known.hub_id), \
                coalesce(p.failures, 0), p.last_connected_at \
         FROM (SELECT hub_id FROM s2s_peers UNION SELECT peer_hub_id FROM s2s_outbox) AS known \
         LEFT JOIN s2s_peers p ON p.hub_id = known.hub_id ORDER BY known.hub_id",
    )?;
    let peers = stmt
        .query_map([], |row| {
            Ok(PeerStatus {
                hub_id: row.get(0)?,
                backlog: row.get(1)?,
                failures: row.get(2)?,
                last_connected_at: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peers)
}

/// An admin audit log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub source_ip: String,
    /// Whether the action succeeded.
    pub ok: bool,
    pub detail: Option<String>,
}

/// Appends an audit entry (its `id` is ignored); returns the new id.
pub fn insert_audit(tx: &Transaction<'_>, entry: &AuditEntry) -> Result<i64, DbError> {
    tx.execute(
        "INSERT INTO admin_audit (at, actor, action, target, source_ip, result, detail) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            entry.at,
            entry.actor,
            entry.action,
            entry.target,
            entry.source_ip,
            if entry.ok { "ok" } else { "error" },
            entry.detail
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Audit entries newest first, with an id below `before` if given, at most
/// `limit`.
pub fn list_audit(
    conn: &Connection,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<AuditEntry>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, at, actor, action, target, source_ip, result, detail FROM admin_audit \
         WHERE ?1 IS NULL OR id < ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let entries = stmt
        .query_map(params![before, limit], |row| {
            Ok(AuditEntry {
                id: row.get(0)?,
                at: row.get(1)?,
                actor: row.get(2)?,
                action: row.get(3)?,
                target: row.get(4)?,
                source_ip: row.get(5)?,
                ok: row.get::<_, String>(6)? == "ok",
                detail: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{self, Challenge, Session},
        handles,
        users::{self, Device, StoredDeviceList},
        Db,
    };

    async fn db_with_users() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            for (user_id, created_at) in [("u-alpha", 10), ("u-beta", 20), ("u-gamma", 30)] {
                users::put_device_list(
                    tx,
                    &StoredDeviceList {
                        user_id: user_id.into(),
                        root_pubkey: vec![1; 32],
                        device_list: vec![0; 8],
                        seq: 1,
                        updated_at: created_at,
                    },
                )?;
            }
            for (device_id, active) in [("d1", true), ("d2", false)] {
                users::put_device(
                    tx,
                    &Device {
                        user_id: "u-alpha".into(),
                        device_id: device_id.into(),
                        sig_pubkey: vec![2; 32],
                        active,
                    },
                    5,
                )?;
            }
            auth::create_session(
                tx,
                &[7; 32],
                &Session {
                    user_id: "u-alpha".into(),
                    device_id: "d1".into(),
                    expires_at: 1_000,
                },
                100,
            )?;
            auth::create_session(
                tx,
                &[8; 32],
                &Session {
                    user_id: "u-alpha".into(),
                    device_id: "d1".into(),
                    expires_at: 50,
                },
                40,
            )?;
            handles::claim(tx, "Bob", "u-beta", 0)?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn counts_users_active_devices_groups_and_blobs() {
        let db = db_with_users().await;
        let counts = db.read(counts).await.unwrap();
        assert_eq!(
            counts,
            Counts {
                users: 3,
                devices: 1,
                groups: 0,
                blobs: 0
            }
        );
    }

    #[tokio::test]
    async fn lists_users_by_substring_and_pages() {
        let db = db_with_users().await;
        let ids = |query: Option<&'static str>, after: Option<&'static str>, limit| {
            let db = db.clone();
            async move {
                db.read(move |conn| list_users(conn, query, after, limit))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|user| user.user_id)
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(ids(None, None, 2).await, ["u-alpha", "u-beta"]);
        assert_eq!(ids(None, Some("u-beta"), 2).await, ["u-gamma"]);
        assert_eq!(ids(Some("GAM"), None, 10).await, ["u-gamma"]);
        assert_eq!(ids(Some("bob"), None, 10).await, ["u-beta"]);
        assert!(ids(Some("zzz"), None, 10).await.is_empty());

        let alpha = db
            .read(|conn| user(conn, "u-alpha"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alpha.device_count, 1);
        assert_eq!(alpha.last_seen, Some(100));
        assert_eq!(alpha.created_at, 10);
        let beta = db.read(|conn| user(conn, "u-beta")).await.unwrap().unwrap();
        assert_eq!(beta.handle.as_deref(), Some("Bob"));
        assert_eq!(beta.last_seen, None);
        assert!(db.read(|conn| user(conn, "nobody")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn devices_list_unexpired_sessions() {
        let db = db_with_users().await;
        let devices = db.read(|conn| devices(conn, "u-alpha", 60)).await.unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(
            (devices[0].device_id.as_str(), devices[0].active),
            ("d1", true)
        );
        assert_eq!(devices[0].created_at, 5);
        assert_eq!(
            devices[0].sessions,
            [SessionInfo {
                token_hash: vec![7; 32],
                created_at: 100,
                expires_at: 1_000
            }]
        );
        assert!(devices[1].sessions.is_empty());
    }

    #[tokio::test]
    async fn suspension_revokes_sessions_and_challenges() {
        let db = db_with_users().await;
        db.write(|tx| {
            auth::insert_challenge(
                tx,
                &Challenge {
                    challenge_id: "c1".into(),
                    user_id: "u-alpha".into(),
                    device_id: "d1".into(),
                    challenge: vec![1],
                    expires_at: 10_000,
                },
                0,
            )
        })
        .await
        .unwrap();
        let suspend_at = |user: &'static str| db.write(move |tx| suspend(tx, user, 500));
        assert_eq!(suspend_at("u-alpha").await.unwrap(), Suspension::Changed);
        assert_eq!(suspend_at("u-alpha").await.unwrap(), Suspension::Unchanged);
        assert_eq!(suspend_at("nobody").await.unwrap(), Suspension::NotFound);
        let (sessions, challenges, suspended) = db
            .read(|conn| {
                let count = |table: &str| -> rusqlite::Result<i64> {
                    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                };
                Ok::<_, DbError>((
                    count("sessions")?,
                    count("auth_challenges")?,
                    is_suspended(conn, "u-alpha")?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((sessions, challenges, suspended), (0, 0, true));
        let summary = db
            .read(|conn| user(conn, "u-alpha"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(summary.suspended_at, Some(500));

        let lift = |user: &'static str| db.write(move |tx| unsuspend(tx, user));
        assert_eq!(lift("u-alpha").await.unwrap(), Suspension::Changed);
        assert_eq!(lift("u-alpha").await.unwrap(), Suspension::Unchanged);
        assert_eq!(lift("nobody").await.unwrap(), Suspension::NotFound);
        assert!(!db
            .read(|conn| is_suspended(conn, "u-alpha"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn device_sessions_are_revoked() {
        let db = db_with_users().await;
        let revoke = |device: &'static str| {
            db.write(move |tx| revoke_device_sessions(tx, "u-alpha", device))
        };
        assert_eq!(revoke("d1").await.unwrap(), Some(2));
        assert_eq!(revoke("d1").await.unwrap(), Some(0));
        assert_eq!(revoke("d9").await.unwrap(), None);
    }

    #[tokio::test]
    async fn peer_statuses_merge_outbox_and_peer_state() {
        let db = Db::open_in_memory().unwrap();
        db.write(|tx| {
            tx.execute_batch(
                "INSERT INTO s2s_outbox (peer_hub_id, kind, user_id, size, created_at, \
                 expires_at) VALUES ('h-b', 'device_list', 'u', 1, 0, 9), \
                 ('h-b', 'device_list', 'v', 1, 0, 9); \
                 INSERT INTO s2s_peers (hub_id, failures, last_connected_at, updated_at) \
                 VALUES ('h-a', 3, 77, 0);",
            )?;
            Ok::<_, DbError>(())
        })
        .await
        .unwrap();
        let peers = db.read(peer_statuses).await.unwrap();
        assert_eq!(
            peers,
            [
                PeerStatus {
                    hub_id: "h-a".into(),
                    backlog: 0,
                    failures: 3,
                    last_connected_at: Some(77)
                },
                PeerStatus {
                    hub_id: "h-b".into(),
                    backlog: 2,
                    failures: 0,
                    last_connected_at: None
                },
            ]
        );
    }

    #[tokio::test]
    async fn audit_log_pages_newest_first() {
        let db = Db::open_in_memory().unwrap();
        for (i, ok) in [(1, true), (2, false), (3, true)] {
            db.write(move |tx| {
                insert_audit(
                    tx,
                    &AuditEntry {
                        id: 0,
                        at: i * 1000,
                        actor: "token".into(),
                        action: format!("action_{i}"),
                        target: (i == 2).then(|| "u1".to_owned()),
                        source_ip: "127.0.0.1".into(),
                        ok,
                        detail: None,
                    },
                )
            })
            .await
            .unwrap();
        }
        let page = db.read(|conn| list_audit(conn, None, 2)).await.unwrap();
        assert_eq!(
            page.iter().map(|e| e.id).collect::<Vec<_>>(),
            [3_i64, 2_i64]
        );
        assert!(!page[1].ok);
        assert_eq!(page[1].target.as_deref(), Some("u1"));
        let rest = db.read(|conn| list_audit(conn, Some(2), 2)).await.unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].action, "action_1");
    }
}
