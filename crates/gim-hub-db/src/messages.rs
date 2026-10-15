//! Per-group message log.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

// ---------------------------------------------------------------------------
// Commits (written by POST /v2/groups/{gid}/commits)
// ---------------------------------------------------------------------------

/// A Commit to append to a group's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCommit {
    pub gid: String,
    pub seq: u64,
    /// Epoch read from the Commit's framing (the epoch it was created in).
    pub epoch: u64,
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub client_id: String,
    pub payload: Vec<u8>,
    /// SHA-256 of `payload`.
    pub commit_hash: Vec<u8>,
    pub message_id: String,
    pub created_at: i64,
}

/// Appends a Commit with kind `commit`.
pub fn append_commit(tx: &Transaction<'_>, commit: &NewCommit) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO messages (gid, seq, epoch, kind, sender_user_id, sender_device_id, \
         client_id, payload, commit_hash, message_id, created_at) \
         VALUES (?1, ?2, ?3, 'commit', ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            commit.gid,
            commit.seq,
            commit.epoch,
            commit.sender_user_id,
            commit.sender_device_id,
            commit.client_id,
            commit.payload,
            commit.commit_hash,
            commit.message_id,
            commit.created_at
        ],
    )?;
    Ok(())
}

/// `(seq, framing epoch)` of the Commit with `commit_hash` in `gid`.
pub fn find_commit(
    conn: &Connection,
    gid: &str,
    commit_hash: &[u8],
) -> Result<Option<(u64, u64)>, DbError> {
    let found = conn
        .query_row(
            "SELECT seq, epoch FROM messages WHERE gid = ?1 AND commit_hash = ?2",
            params![gid, commit_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(found)
}

/// Whether the device already used `client_id` in `gid`.
pub fn client_id_used(
    conn: &Connection,
    gid: &str,
    sender_device_id: &str,
    client_id: &str,
) -> Result<bool, DbError> {
    let used = conn
        .query_row(
            "SELECT 1 FROM messages WHERE gid = ?1 AND sender_device_id = ?2 AND client_id = ?3",
            params![gid, sender_device_id, client_id],
            |_| Ok(()),
        )
        .optional()?;
    Ok(used.is_some())
}
