//! Route handlers, one module per API area. Everything except `/healthz` is a
//! stub returning 501 Not Implemented until the hub logic lands; the
//! `#[utoipa::path]` annotations are the client API v2 contract.

mod auth;
mod blobs;
mod events;
mod groups;
mod handles;
mod health;
mod identity;
mod keypackages;
mod links;
mod messages;
mod push;
mod recovery;
mod welcomes;

pub use auth::*;
pub use blobs::*;
pub use events::*;
pub use groups::*;
pub use handles::*;
pub use health::*;
pub use identity::*;
pub use keypackages::*;
pub use links::*;
pub use messages::*;
pub use push::*;
pub use recovery::*;
pub use welcomes::*;

use crate::error::ApiError;

fn not_implemented() -> ApiError {
    ApiError::NotImplemented
}
