//! Connection handle.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::{migrate, DbError};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared database handle (cheap to clone).
///
/// A single connection behind a mutex: SQLite serializes writers anyway and
/// the hub's queries are short. Closures passed to [`Db::read`] and
/// [`Db::write`] run on the blocking thread pool.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Opens (creating if needed) the database at `path`, enables WAL and
    /// foreign keys, and applies pending migrations.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
        Self::init(conn)
    }

    /// Opens a fresh in-memory database with the full schema.
    pub fn open_in_memory() -> Result<Self, DbError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self, DbError> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        migrate::run(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `f` with the connection outside of an explicit transaction.
    pub async fn read<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Connection) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<DbError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || f(&lock(&conn)))
            .await
            .map_err(|err| E::from(DbError::Task(err.to_string())))?
    }

    /// Runs `f` in an immediate transaction, committed if `f` returns `Ok`
    /// and rolled back otherwise.
    pub async fn write<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<DbError> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = lock(&conn);
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|err| E::from(DbError::from(err)))?;
            let value = f(&tx)?;
            tx.commit().map_err(|err| E::from(DbError::from(err)))?;
            Ok(value)
        })
        .await
        .map_err(|err| E::from(DbError::Task(err.to_string())))?
    }
}

/// A panic inside a closure rolls its transaction back when the guard drops,
/// so a poisoned connection is still consistent.
fn lock(conn: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    conn.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_rolls_back_on_error() {
        let db = Db::open_in_memory().unwrap();
        let result: Result<(), DbError> = db
            .write(|tx| {
                tx.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", [])?;
                Err(DbError::Task("abort".into()))
            })
            .await;
        assert!(result.is_err());
        let count: i64 = db
            .read(|conn| {
                conn.query_row("SELECT count(*) FROM meta", [], |row| row.get(0))
                    .map_err(DbError::from)
            })
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
