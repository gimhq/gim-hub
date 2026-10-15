//! Route handlers, one module per API area. The `#[utoipa::path]`
//! annotations are the client API v2 contract.

mod auth;
mod blobs;
mod events;
mod groups;
mod handles;
mod health;
mod hosting;
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
pub use hosting::*;
pub use identity::*;
pub use keypackages::*;
pub use links::*;
pub use messages::*;
pub use push::*;
pub use recovery::*;
pub use welcomes::*;
