//! Test helpers (feature `testing`): an [`AppState`] on an in-memory database
//! and a temporary data directory, plus direct session creation.

use std::sync::Arc;

use axum::Router;
use gim_hub_db::{
    auth::{self, Session},
    users::{self, Device, StoredDeviceList},
    Db,
};
use tempfile::TempDir;

use crate::{
    auth::token_hash, config::Config, hub::HubIdentity, notifier::Notifier, state::Clock, AppState,
};

/// Start time of the manual test clock (ms since the Unix epoch).
pub const TEST_NOW: i64 = 1_760_479_200_000;
/// Lifetime of sessions created by [`TestHub::create_session`].
pub const TEST_SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// A hub on an in-memory database with a manual clock at [`TEST_NOW`].
pub struct TestHub {
    pub state: AppState,
    _data_dir: TempDir,
}

impl TestHub {
    /// A hub with a random root key.
    pub fn new() -> Self {
        Self::with_key(None)
    }

    /// A hub whose root key has the Ed25519 seed `seed`.
    pub fn with_hub_seed(seed: [u8; 32]) -> Self {
        Self::with_key(Some(seed))
    }

    fn with_key(seed: Option<[u8; 32]>) -> Self {
        let data_dir = tempfile::tempdir().expect("create temp data dir");
        let config = Config::from_vars([(
            "GIM_HUB_DATA_DIR".to_owned(),
            data_dir.path().display().to_string(),
        )])
        .expect("test config");
        if let Some(seed) = seed {
            std::fs::write(config.hub_key_path(), seed).expect("write hub key");
        }
        let hub = HubIdentity::load_or_create(&config.hub_key_path()).expect("hub key");
        let state = AppState {
            db: Db::open_in_memory().expect("in-memory db"),
            config: Arc::new(config),
            hub,
            notifier: Notifier::default(),
            clock: Clock::manual(TEST_NOW),
        };
        Self {
            state,
            _data_dir: data_dir,
        }
    }

    /// The client API router on this state.
    pub fn router(&self) -> Router {
        crate::router(self.state.clone())
    }

    /// Stores an active device (and a placeholder user if missing) and a
    /// session for it; returns the bearer token.
    pub async fn create_session(&self, user_id: &str, device_id: &str) -> String {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).expect("random token");
        let token = hex::encode(raw);
        let hash = token_hash(&token);
        let now = self.state.clock.now_ms();
        let (user_id, device_id) = (user_id.to_owned(), device_id.to_owned());
        self.state
            .db
            .write(move |tx| {
                if users::get_device_list(tx, &user_id)?.is_none() {
                    users::put_device_list(
                        tx,
                        &StoredDeviceList {
                            user_id: user_id.clone(),
                            root_pubkey: vec![0; 32],
                            device_list: Vec::new(),
                            seq: 0,
                            updated_at: now,
                        },
                    )?;
                }
                users::put_device(
                    tx,
                    &Device {
                        user_id: user_id.clone(),
                        device_id: device_id.clone(),
                        sig_pubkey: vec![0; 32],
                        active: true,
                    },
                    now,
                )?;
                auth::create_session(
                    tx,
                    &hash,
                    &Session {
                        user_id,
                        device_id,
                        expires_at: now + TEST_SESSION_TTL_MS,
                    },
                    now,
                )
            })
            .await
            .expect("create session");
        token
    }

    /// Marks a stored device active or inactive.
    pub async fn set_device_active(&self, user_id: &str, device_id: &str, active: bool) {
        let now = self.state.clock.now_ms();
        let (user_id, device_id) = (user_id.to_owned(), device_id.to_owned());
        self.state
            .db
            .write(move |tx| {
                users::put_device(
                    tx,
                    &Device {
                        user_id,
                        device_id,
                        sig_pubkey: vec![0; 32],
                        active,
                    },
                    now,
                )
            })
            .await
            .expect("update device");
    }
}

impl Default for TestHub {
    fn default() -> Self {
        Self::new()
    }
}
