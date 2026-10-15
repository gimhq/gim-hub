//! Sealed link bundles, deleted on first fetch or once expired.

use rusqlite::{params, OptionalExtension, Transaction};

use crate::DbError;

/// Stores a bundle under `link_id` until `expires_at`. An expired bundle
/// with the same ID is replaced; returns false if a live one exists.
pub fn insert(
    tx: &Transaction<'_>,
    link_id: &str,
    sealed_bundle: &[u8],
    now: i64,
    expires_at: i64,
) -> Result<bool, DbError> {
    tx.execute(
        "DELETE FROM link_bundles WHERE link_id = ?1 AND expires_at <= ?2",
        params![link_id, now],
    )?;
    let inserted = tx.execute(
        "INSERT INTO link_bundles (link_id, sealed_bundle, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (link_id) DO NOTHING",
        params![link_id, sealed_bundle, now, expires_at],
    )?;
    Ok(inserted > 0)
}

/// Deletes the bundle under `link_id` and returns it unless it had expired
/// at `now`.
pub fn take(tx: &Transaction<'_>, link_id: &str, now: i64) -> Result<Option<Vec<u8>>, DbError> {
    let row: Option<(Vec<u8>, i64)> = tx
        .query_row(
            "DELETE FROM link_bundles WHERE link_id = ?1 RETURNING sealed_bundle, expires_at",
            [link_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(row.and_then(|(bundle, expires_at)| (expires_at > now).then_some(bundle)))
}

/// Deletes bundles expired at `now`; returns how many.
pub fn prune_expired(tx: &Transaction<'_>, now: i64) -> Result<usize, DbError> {
    Ok(tx.execute("DELETE FROM link_bundles WHERE expires_at <= ?1", [now])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn insert_take_and_expire() {
        let db = Db::open_in_memory().unwrap();
        assert!(db
            .write(|tx| insert(tx, "l1", b"b1", 0, 100))
            .await
            .unwrap());
        assert!(!db
            .write(|tx| insert(tx, "l1", b"b2", 50, 150))
            .await
            .unwrap());
        assert_eq!(
            db.write(|tx| take(tx, "l1", 99)).await.unwrap(),
            Some(b"b1".to_vec())
        );
        assert_eq!(db.write(|tx| take(tx, "l1", 99)).await.unwrap(), None);

        assert!(db.write(|tx| insert(tx, "l2", b"b", 0, 100)).await.unwrap());
        assert_eq!(db.write(|tx| take(tx, "l2", 100)).await.unwrap(), None);

        assert!(db.write(|tx| insert(tx, "l3", b"b", 0, 100)).await.unwrap());
        assert!(db
            .write(|tx| insert(tx, "l3", b"c", 100, 200))
            .await
            .unwrap());
        assert!(db.write(|tx| insert(tx, "l4", b"d", 0, 300)).await.unwrap());
        assert_eq!(db.write(|tx| prune_expired(tx, 200)).await.unwrap(), 1);
        assert_eq!(
            db.write(|tx| take(tx, "l4", 200)).await.unwrap(),
            Some(b"d".to_vec())
        );
    }
}
