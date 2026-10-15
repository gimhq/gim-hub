//! SQLite storage for the gim hub.
//!
//! [`Db`] owns the connection; every query runs on the blocking thread pool
//! through [`Db::read`] or [`Db::write`]. Repository modules hold one area of
//! the schema each and take a `&Connection` (reads) or a `&Transaction`
//! (writes).

pub mod auth;
pub mod blobs;
pub mod events;
pub mod groups;
pub mod handles;
pub mod hosting;
pub mod keypackages;
pub mod links;
pub mod messages;
mod migrate;
pub mod outbox;
mod pool;
pub mod push;
pub mod recovery;
pub mod remote_identity;
pub mod users;
pub mod welcomes;

pub use migrate::SCHEMA_VERSION;
pub use pool::Db;
pub use rusqlite::{Connection, Transaction};

/// Storage error.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("database schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("cannot create database directory: {0}")]
    Io(#[from] std::io::Error),
    #[error("database task failed: {0}")]
    Task(String),
}
