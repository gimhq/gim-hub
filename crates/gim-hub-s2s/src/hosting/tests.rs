//! Hosting records: the DHT validator, and publication and resolution
//! between in-process hubs on 127.0.0.1 with ephemeral ports.

use std::{sync::Arc, time::Duration};

use gim_hub_db::users::{self, StoredDeviceList};
use gim_hub_identity::SigningKey;
use gim_hub_proto::s2s::ErrorCode;
use tempfile::TempDir;

use super::{testing::sign_record, *};
use crate::{
    policy::AllowlistPolicy,
    transport::{now_ms, RecordDecision, RecordValidator},
};

const HOUR: i64 = 60 * 60 * 1000;
const DAY: u64 = 24 * 60 * 60 * 1000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn hub_id(seed: u8) -> HubId {
    HubId::from_root_pubkey(&key(seed).verifying_key())
}

fn user_id(seed: u8) -> UserId {
    UserId::from_root_pubkey(&key(seed).verifying_key())
}

fn system_now() -> Now {
    Arc::new(|| now_ms() as i64)
}

#[test]
fn validator_applies_key_signature_and_seq_rules() {
    const NOW: u64 = 1_792_000_000_000;
    let key_of = |seed: u8| user_record_key(user_id(seed).as_str());
    let validate = |key: &str, value: &[u8], existing: Option<&[u8]>| {
        UserRecordValidator.validate(key, value, existing, NOW)
    };
    let v1 = sign_record(&key(50), 1, NOW + DAY, &[(&key(1), 0)]);
    let v2 = sign_record(&key(50), 2, NOW + DAY, &[(&key(1), 0)]);
    let v2_other = sign_record(&key(50), 2, NOW + DAY, &[(&key(2), 0)]);

    assert_eq!(validate(&key_of(50), &v1, None), RecordDecision::Store);
    assert_eq!(validate(&key_of(50), &v2, Some(&v1)), RecordDecision::Store);
    assert_eq!(validate(&key_of(50), &v2, Some(&v2)), RecordDecision::Keep);
    let reject = |decision: RecordDecision| match decision {
        RecordDecision::Reject(reason) => reason,
        other => panic!("expected a rejection, got {other:?}"),
    };
    assert_eq!(reject(validate(&key_of(50), &v1, Some(&v2))), "stale_seq");
    assert_eq!(
        reject(validate(&key_of(50), &v2_other, Some(&v2))),
        "seq_conflict"
    );
    // Another user's key, an invalid user_id, another prefix, expired.
    assert_eq!(reject(validate(&key_of(51), &v1, None)), "user_id_mismatch");
    assert_eq!(
        reject(validate("/gim/user/unot-a-user", &v1, None)),
        "invalid_user_id"
    );
    assert!(matches!(
        validate("/gim/hub/x", &v1, None),
        RecordDecision::Reject(_)
    ));
    let expired = sign_record(&key(50), 3, NOW, &[(&key(1), 0)]);
    assert_eq!(reject(validate(&key_of(50), &expired, None)), "expired");
    assert!(matches!(
        validate(&key_of(50), &vec![0; MAX_RECORD_BYTES + 1], None),
        RecordDecision::Reject(_)
    ));
}

struct Hub {
    seed: u8,
    dir: TempDir,
    policy: Arc<AllowlistPolicy>,
    service: FederationService,
    db: Db,
}

/// Starts hub `seed` on TCP loopback, allowing `allowed` (no addresses).
async fn start_hub(seed: u8, allowed: &[u8]) -> Hub {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowlist");
    let text: String = allowed
        .iter()
        .map(|seed| format!("{}\n", hub_id(*seed)))
        .collect();
    std::fs::write(&path, text).unwrap();
    let policy = Arc::new(AllowlistPolicy::load(&path, &hub_id(seed), None).unwrap());
    let config = FederationConfig {
        enabled: true,
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        s2s_timeout: Duration::from_secs(3),
        ..FederationConfig::disabled(dir.path())
    };
    let service = FederationService::start(&config, &key(seed), policy.clone())
        .await
        .unwrap();
    Hub {
        seed,
        dir,
        policy,
        service,
        db: Db::open_in_memory().unwrap(),
    }
}

impl Hub {
    /// Hosting on this hub with a cache lifetime of `cache_ttl`.
    fn hosting(&self, cache_ttl: Duration) -> Hosting {
        let hosting = Hosting::new(
            self.db.clone(),
            hub_id(self.seed),
            Arc::new(self.service.clone()),
            Some(self.service.transport().clone()),
            HostingSettings {
                cache_ttl,
                ..HostingSettings::default()
            },
            system_now(),
        );
        hosting.register(&self.service);
        hosting
    }

    /// Adds `other` with its addresses to the allowlist and binds it.
    async fn connect(&self, other: &Hub, extra: &[u8]) {
        let mut text = other.service.hub_id().to_string();
        for addr in other.service.transport().advertised_addrs() {
            text.push_str(&format!(" {addr}"));
        }
        text.push('\n');
        for seed in extra {
            text.push_str(&format!("{}\n", hub_id(*seed)));
        }
        std::fs::write(self.dir.path().join("allowlist"), text).unwrap();
        self.policy.reload().unwrap();
        self.service.transport().policy_changed();
        self.service.transport().bootstrap().await;
        assert_eq!(
            self.service.transport().bound_hubs(),
            vec![other.service.hub_id().clone()]
        );
    }

    /// Stores `record` for local user `user` (created if missing).
    async fn store_local(&self, user: u8, record: Vec<u8>) {
        let record = HostingRecord::verify(&record, &user_id(user), now_ms()).unwrap();
        let hosted = record.entry(&hub_id(self.seed)).is_some();
        let stored = stored_record(&record, hosted, now_ms() as i64).unwrap();
        self.db
            .write(move |tx| {
                if users::get_device_list(tx, &stored.user_id)?.is_none() {
                    users::put_device_list(
                        tx,
                        &StoredDeviceList {
                            user_id: stored.user_id.clone(),
                            root_pubkey: vec![0; 32],
                            device_list: Vec::new(),
                            seq: 0,
                            updated_at: 0,
                        },
                    )?;
                }
                store::put(tx, &stored)
            })
            .await
            .unwrap();
    }

    async fn row(&self, user: u8) -> Option<StoredHostingRecord> {
        let user_id = user_id(user).to_string();
        self.db
            .read(move |conn| store::get(conn, &user_id))
            .await
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_are_published_and_resolved_between_hubs() {
    let a = start_hub(1, &[2]).await;
    let b = start_hub(2, &[1]).await;
    a.connect(&b, &[]).await;
    let a_hosting = a.hosting(Duration::from_secs(600));
    let b_hosting = b.hosting(Duration::ZERO);
    let expires = now_ms() + 7 * DAY;

    // A republishes its hosted users at startup.
    a.store_local(50, sign_record(&key(50), 1, expires, &[(&key(1), 0)]))
        .await;
    assert_eq!(
        a_hosting
            .require_hosting_record(user_id(50).as_str())
            .await
            .unwrap()
            .seq(),
        1
    );
    let republisher = a_hosting.spawn_republisher().unwrap();
    for _ in 0..150 {
        if a.row(50).await.unwrap().published_at.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a.row(50).await.unwrap().published_at.is_some());
    republisher.abort();

    // B has nothing cached: the DHT answers, and B caches the record.
    let record = b_hosting.resolve(user_id(50).as_str()).await.unwrap();
    assert_eq!(record.seq(), 1);
    let cached = b.row(50).await.unwrap();
    assert_eq!((cached.seq, cached.hosted), (1, false));
    assert_eq!(cached.hub_ids, vec![hub_id(1).to_string()]);
    assert!(matches!(
        b_hosting.require_hosting_record(user_id(50).as_str()).await,
        Err(HostingError::Required)
    ));

    // A stores seq 2 without publishing it; B's stale cache asks the
    // primary hub with GetHostingRecord.
    a.store_local(50, sign_record(&key(50), 2, expires, &[(&key(1), 0)]))
        .await;
    assert_eq!(
        b_hosting.resolve(user_id(50).as_str()).await.unwrap().seq(),
        2
    );
    assert_eq!(b.row(50).await.unwrap().seq, 2);

    // A fresh cache answers without the network, unless it does not list
    // the authorizing caller: then the caller is asked first.
    let b_cached = b.hosting(Duration::from_secs(600));
    a.store_local(51, sign_record(&key(51), 2, expires, &[(&key(1), 0)]))
        .await;
    let moved = sign_record(&key(51), 1, expires, &[(&key(3), 0)]);
    let moved = HostingRecord::verify(&moved, &user_id(51), now_ms()).unwrap();
    let stored = stored_record(&moved, false, now_ms() as i64).unwrap();
    b.db.write(move |tx| store::put(tx, &stored)).await.unwrap();
    assert_eq!(
        b_cached.resolve(user_id(51).as_str()).await.unwrap().seq(),
        1
    );
    let refreshed = b_cached
        .resolve_for(user_id(51).as_str(), Purpose::Authorize(hub_id(1)))
        .await
        .unwrap();
    assert_eq!(refreshed.seq(), 2);
    assert_eq!(b.row(51).await.unwrap().seq, 2);

    // Unknown users: NOT_FOUND from the op, 404 from resolution; a caller
    // that cannot be reached with nothing in the DHT is unavailable.
    let response = b
        .service
        .send(
            &hub_id(1),
            S2sRequest {
                request_id: "r".into(),
                op: Some(Op::GetHostingRecord(GetHostingRecordRequest {
                    user_id: user_id(52).to_string(),
                })),
            },
        )
        .await
        .unwrap();
    assert_eq!(response.error.unwrap().code(), ErrorCode::NotFound);
    assert!(matches!(
        b_hosting.resolve(user_id(52).as_str()).await,
        Err(HostingError::NotFound)
    ));
    assert!(matches!(
        b_hosting
            .resolve_for(user_id(52).as_str(), Purpose::Authorize(hub_id(3)))
            .await,
        Err(HostingError::Unavailable(_))
    ));

    a.service.shutdown();
    b.service.shutdown();
}

#[tokio::test]
async fn without_federation_the_cache_answers_until_expiry() {
    let db = Db::open_in_memory().unwrap();
    let now = Arc::new(std::sync::atomic::AtomicI64::new(1_000 * HOUR));
    let clock = now.clone();
    let hosting = Hosting::local(
        db.clone(),
        hub_id(1),
        Arc::new(move || clock.load(std::sync::atomic::Ordering::Relaxed)),
    );
    let expires = (1_002 * HOUR) as u64;
    let user = user_id(50).to_string();
    let record = sign_record(&key(50), 1, expires, &[(&key(2), 0)]);
    let record = HostingRecord::verify(&record, &user_id(50), 0).unwrap();
    let stored = stored_record(&record, false, 0).unwrap();
    db.write(move |tx| store::put(tx, &stored)).await.unwrap();

    // A cached remote record serves lookups while fresh and unexpired.
    assert_eq!(hosting.resolve(&user).await.unwrap().seq(), 1);
    assert!(hosting.local_record(&user).await.unwrap().is_none());
    now.store(expires as i64, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        hosting.resolve(&user).await,
        Err(HostingError::NotFound)
    ));
    assert!(matches!(
        hosting.resolve("not-a-user").await,
        Err(HostingError::NotFound)
    ));
}

#[test]
fn entries_encode_as_in_records() {
    let entry = HostingEntry::sign(&key(1), &user_id(50), 7);
    let record = sign_record(&key(50), 1, 10, &[(&key(1), 7)]);
    let bytes = encode_entry(&entry);
    assert_eq!(bytes.len(), 1 + 34 + 1 + 66);
    assert!(record.windows(bytes.len()).any(|window| window == bytes));
}
