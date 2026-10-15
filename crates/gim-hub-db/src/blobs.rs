//! Blob metadata; the content lives in `$DATA_DIR/blobs/<blob_id>`.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::DbError;

/// Metadata of a stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub blob_id: String,
    pub size: i64,
    pub uploader_user_id: String,
    pub uploader_device_id: String,
    pub created_at: i64,
}

/// Records a stored blob.
pub fn insert(tx: &Transaction<'_>, blob: &Blob) -> Result<(), DbError> {
    tx.execute(
        "INSERT INTO blobs (blob_id, size, uploader_user_id, uploader_device_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            blob.blob_id,
            blob.size,
            blob.uploader_user_id,
            blob.uploader_device_id,
            blob.created_at
        ],
    )?;
    Ok(())
}

/// Metadata of one blob.
pub fn get(conn: &Connection, blob_id: &str) -> Result<Option<Blob>, DbError> {
    let blob = conn
        .query_row(
            "SELECT blob_id, size, uploader_user_id, uploader_device_id, created_at \
             FROM blobs WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok(Blob {
                    blob_id: row.get(0)?,
                    size: row.get(1)?,
                    uploader_user_id: row.get(2)?,
                    uploader_device_id: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Db;

    #[tokio::test]
    async fn insert_and_get() {
        let db = Db::open_in_memory().unwrap();
        let blob = Blob {
            blob_id: "b_1".into(),
            size: 5,
            uploader_user_id: "u1".into(),
            uploader_device_id: "d1".into(),
            created_at: 10,
        };
        let stored = blob.clone();
        db.write(move |tx| insert(tx, &stored)).await.unwrap();
        assert_eq!(db.read(|c| get(c, "b_1")).await.unwrap(), Some(blob));
        assert_eq!(db.read(|c| get(c, "b_2")).await.unwrap(), None);
    }
}
