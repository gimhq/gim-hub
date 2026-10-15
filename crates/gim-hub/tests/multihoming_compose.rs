//! Compose acceptance driver for multi-homing (docs/multihoming.md §11,
//! MH1-MH9; plan acceptance M2c). Same harness as `fed_compose.rs`: the
//! client API v2 over HTTP to hub-a, hub-b and hub-c of
//! `deploy/federation/compose.yaml` with the multi-homing override
//! `compose.mh.yaml` (`GIM_HUB_UNHOSTED_GRACE_HOURS=1`,
//! `GIM_HUB_PUSH_FAILOVER_SECONDS=5`, the push log endpoint), real MLS
//! clients, and hub stops and starts through the Docker API.
//!
//! Users: alice on A (A+B from MH1, A primary), bob on B, carol on C, and
//! mia, who migrates from A to C in MH8 (§11 runs MH8 with alice on A only;
//! alice is multi-homed by then, so a second user takes that role). Group G
//! is owned by C (alice, bob, carol, mia), H by A (alice, carol, mia), W by C
//! (carol; alice's Welcome stays unacknowledged).
//!
//! Message events carry no `message_id` (api-v2 `Message`), so views are
//! merged by `(gid, seq)`, which the owner assigns once, and the copies on
//! each hub are compared byte for byte. Pushes are matched by the `gid` and
//! `seq` of their payload (`collapse_id` = `message_id`).
//!
//! Ignored by default: `GIM_FED_SUITE=mh scripts/fed-test.sh` starts the
//! topology and runs it with `--ignored`. Environment as `fed_compose.rs`
//! (`GIM_FED_HUB_{A,B,C}`, `GIM_FED_PROJECT`, `GIM_FED_DOCKER_SOCKET`).

mod compose_support;
#[path = "../../gim-hub-api/tests/mls_support/mod.rs"]
mod mls_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use hyper::{Method, StatusCode};
use openmls::prelude::{tls_codec::Serialize, MlsGroup};
use serde_json::{json, Value};

use compose_support::{
    application, commit_body, eventually, hosting_record, http, now_ms, with_welcome, Hub, User,
    CONVERGE, DAY_MS,
};
use mls_support::{b64, code, device_list, group_path, unb64, user_id};

/// `GIM_HUB_PUSH_FAILOVER_SECONDS` of `compose.mh.yaml`.
const FAILOVER: Duration = Duration::from_secs(5);
/// The push gate reloads its view every 10 s (multihoming.md §8).
const GATE_REFRESH: Duration = Duration::from_secs(10);

const ALICE: u8 = 1;
const BOB: u8 = 2;
const CAROL: u8 = 3;
const MIA: u8 = 6;

/// Prints a step result with the time since `start`.
fn ok(step: &str, start: Instant) {
    println!("mh: ok   {step} ({:.1}s)", start.elapsed().as_secs_f64());
}

// ---------------------------------------------------------------------------
// Client API helpers
// ---------------------------------------------------------------------------

/// PUTs the DeviceList `seq` of user `key(root)` to `hub`.
async fn put_device_list(hub: &Hub, root: u8, seq: u64, active: &[u8], revoked: &[u8]) {
    let list = device_list(root, seq, active, revoked);
    let (status, body) = hub
        .call(
            Method::PUT,
            &format!("/v2/users/{}/device-list", user_id(root)),
            None,
            Some(json!({ "device_list": b64(&list) })),
        )
        .await;
    assert!(
        status.is_success(),
        "device list {seq} on {}: {body}",
        hub.service
    );
}

/// The hub-signed entry (CBOR) for `session`'s user at `priority`.
async fn entry(session: &User, priority: u8) -> Vec<u8> {
    let (status, body) = session
        .call(
            Method::POST,
            &format!("/v2/users/{}/hosting-entry", session.user_id),
            Some(json!({ "priority": priority })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{} entry: {body}", session.name);
    unb64(&body["entry"])
}

/// Signs record `seq` of user `key(root)` listing `entries` (canonical
/// order: by priority, then hub key) and PUTs it to `hubs`, in order
/// (multihoming.md §4.1 step 4: the added hub first).
async fn publish(root: u8, seq: u64, entries: &[&[u8]], hubs: &[&Hub]) {
    let record = hosting_record(root, seq, now_ms() + 7 * DAY_MS, entries);
    for hub in hubs {
        let (status, body) = hub
            .call(
                Method::PUT,
                &format!("/v2/users/{}/hosting-record", user_id(root)),
                None,
                Some(json!({ "hosting_record": b64(&record) })),
            )
            .await;
        assert!(
            status.is_success(),
            "record {seq} on {}: {body}",
            hub.service
        );
    }
}

/// `(seq, hosted)` of the record `hub` returns for `uid`.
async fn record_on(hub: &Hub, uid: &str) -> Option<(u64, bool)> {
    let (status, body) = hub
        .call(
            Method::GET,
            &format!("/v2/users/{uid}/hosting-record"),
            None,
            None,
        )
        .await;
    (status == StatusCode::OK).then(|| (body["seq"].as_u64().unwrap(), body["hosted"] == true))
}

async fn wait_record(hub: &Hub, uid: &str, seq: u64, hosted: bool) {
    eventually(&format!("record {seq} on {}", hub.service), || async {
        record_on(hub, uid).await == Some((seq, hosted))
    })
    .await;
}

async fn register_push(session: &User, token: &str) {
    let (status, body) = session
        .call(
            Method::PUT,
            "/v2/push/registration",
            Some(json!({ "provider": "log", "token": token })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// `(gid, seq, sent_at)` of the `message` pushes `hub` sent to `device_id`.
async fn pushes(hub: &Hub, device_id: &str) -> Vec<(String, u64, i64)> {
    let (status, body) = hub
        .call(
            Method::GET,
            &format!("/v2/debug/push-log?device_id={device_id}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["notifications"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["payload"]["type"] == "message")
        .map(|n| {
            (
                n["payload"]["gid"].as_str().unwrap().to_owned(),
                n["payload"]["seq"].as_u64().unwrap(),
                n["sent_at"].as_i64().unwrap(),
            )
        })
        .collect()
}

/// Uploads `count` new KeyPackages of `mls`'s device through `session`;
/// returns them base64-encoded.
async fn upload_key_packages(
    mls: &User,
    session: &User,
    count: usize,
    last_resort: bool,
) -> Vec<String> {
    let packages: Vec<String> = (0..count).map(|_| b64(&mls.key_package())).collect();
    let (status, body) = session
        .call(
            Method::POST,
            "/v2/keypackages",
            Some(json!({ "key_packages": packages, "last_resort": last_resort })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{} key packages: {body}",
        session.name
    );
    packages
}

/// One claim of `target`'s device through `session`: `(key_package,
/// last_resort)`, retrying while nothing is returned.
async fn claim_raw(session: &User, target: &User) -> (String, bool) {
    let request =
        json!({ "targets": [{ "user_id": target.user_id, "device_id": target.device_id }] });
    let mut last = Value::Null;
    let deadline = Instant::now() + CONVERGE;
    while Instant::now() < deadline {
        let (status, body) = session
            .call(Method::POST, "/v2/keypackages/claim", Some(request.clone()))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if let Some(package) = body["key_packages"].get(0) {
            return (
                package["key_package"].as_str().unwrap().to_owned(),
                package["last_resort"] == true,
            );
        }
        last = body;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{} could not claim {}: {last}", session.name, target.name);
}

async fn pending_welcome_gids(session: &User) -> BTreeSet<String> {
    let (status, body) = session
        .call(Method::GET, "/v2/welcomes/pending?limit=200", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["welcomes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["gid"].as_str().unwrap().to_owned())
        .collect()
}

async fn last_seq(session: &User, gid: &str) -> u64 {
    let (status, body) = session.call(Method::GET, &group_path(gid), None).await;
    assert_eq!(status, StatusCode::OK, "{} group: {body}", session.name);
    body["last_seq"].as_u64().unwrap()
}

/// The `message` events of `gid` on every session of one device, merged by
/// `seq`; asserts that each hub delivered each seq at most once and that the
/// copies are identical.
async fn view(sessions: &[&User], gid: &str) -> BTreeMap<u64, String> {
    let mut merged = BTreeMap::new();
    for session in sessions {
        let mut seen = BTreeSet::new();
        for event in session.events_of("message").await {
            if event["gid"] != gid {
                continue;
            }
            let seq = event["seq"].as_u64().unwrap();
            assert!(
                seen.insert(seq),
                "{}: seq {seq} delivered twice",
                session.name
            );
            let mls = event["mls_message"].as_str().unwrap().to_owned();
            if let Some(other) = merged.insert(seq, mls.clone()) {
                assert_eq!(
                    other, mls,
                    "{}: seq {seq} differs between hubs",
                    session.name
                );
            }
        }
    }
    merged
}

/// Asserts that `session` got a `message` event for each of `seqs` exactly
/// once, waiting for the last one.
async fn received_once(session: &User, gid: &str, seqs: &[u64]) {
    session.wait_message(gid, *seqs.last().unwrap()).await;
    eventually(&format!("{} to receive {seqs:?}", session.name), || async {
        let got = session.message_seqs(gid).await;
        seqs.iter()
            .all(|seq| got.iter().filter(|s| *s == seq).count() == 1)
    })
    .await;
}

/// Posts the same application message until the answer is not 503 (peers
/// still binding after a restart).
async fn post_until_available(
    session: &User,
    gid: &str,
    client_id: &str,
    mls: &[u8],
) -> (StatusCode, Value) {
    let deadline = Instant::now() + CONVERGE;
    loop {
        let result = session.post_message(gid, client_id, mls).await;
        if result.0 != StatusCode::SERVICE_UNAVAILABLE || Instant::now() > deadline {
            return result;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The member's MLS group of a group, and the next seq the owner assigns.
struct Group {
    gid: String,
    next: u64,
}

impl Group {
    fn take(&mut self) -> u64 {
        let seq = self.next;
        self.next += 1;
        seq
    }
}

/// MLS state of the scenario.
struct Mls {
    alice_g: MlsGroup,
    alice_h: MlsGroup,
    bob_g: MlsGroup,
    carol_g: MlsGroup,
    mia_h: MlsGroup,
}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs deploy/federation/compose.{yaml,mh.yaml}; run by GIM_FED_SUITE=mh scripts/fed-test.sh"]
async fn compose_multihoming() {
    let a = Hub::from_env("hub-a", "GIM_FED_HUB_A");
    let b = Hub::from_env("hub-b", "GIM_FED_HUB_B");
    let c = Hub::from_env("hub-c", "GIM_FED_HUB_C");
    for hub in [&a, &b, &c] {
        hub.wait_healthy().await;
    }

    let start = Instant::now();
    let alice = User::sign_up("alice", &a, ALICE, 11, 2).await;
    let bob = User::sign_up("bob", &b, BOB, 21, 1).await;
    let carol = User::sign_up("carol", &c, CAROL, 31, 1).await;
    let mia = User::sign_up("mia", &a, MIA, 61, 3).await;
    register_push(&alice, "alice-a").await;
    for (hub, user) in [
        (&b, &alice),
        (&c, &alice),
        (&c, &mia),
        (&a, &carol),
        (&c, &bob),
    ] {
        wait_record(hub, &user.user_id, 1, false).await;
    }

    // G owned by C: alice, bob, mia; H owned by A: carol, mia; W owned by C:
    // alice's Welcome stays unacknowledged.
    let (g_id, mut carol_g) = carol.create_group("group").await;
    let kps = vec![
        carol.claim(&alice).await,
        carol.claim(&bob).await,
        carol.claim(&mia).await,
    ];
    let (commit, welcome, _) = carol_g
        .add_members(&carol.provider, &carol.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("g1", &commit), &welcome, &[&alice, &bob, &mia]);
    let (status, result) = carol.submit_commit(&g_id, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    carol_g.merge_pending_commit(&carol.provider).unwrap();
    let alice_g = alice.join(&g_id).await;
    let bob_g = bob.join(&g_id).await;
    let mut g = Group { gid: g_id, next: 2 };
    let seq = g.take();
    carol.send_text(&mut carol_g, &g.gid, "g-hello", seq).await;

    let (h_id, mut alice_h) = alice.create_group("group").await;
    let kps = vec![alice.claim(&carol).await, alice.claim(&mia).await];
    let (commit, welcome, _) = alice_h
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("h1", &commit), &welcome, &[&carol, &mia]);
    let (status, result) = alice.submit_commit(&h_id, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_h.merge_pending_commit(&alice.provider).unwrap();
    let mia_h = mia.join(&h_id).await;
    let mut h = Group { gid: h_id, next: 2 };
    let seq = h.take();
    alice.send_text(&mut alice_h, &h.gid, "h-hello", seq).await;

    let (w_id, mut carol_w) = carol.create_group("group").await;
    let kp = carol.claim(&alice).await;
    let (commit, welcome, _) = carol_w
        .add_members(&carol.provider, &carol.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("w1", &commit), &welcome, &[&alice]);
    let (status, result) = carol.submit_commit(&w_id, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    eventually("alice's pending Welcome for W on A", || async {
        pending_welcome_gids(&alice).await.contains(&w_id)
    })
    .await;
    let mut mls = Mls {
        alice_g,
        alice_h,
        bob_g,
        carol_g,
        mia_h,
    };
    ok("setup: users, groups G (C), H (A), W (C)", start);

    let alice_b = mh1_add_hub(&a, &b, &c, &alice, &carol, &g, &h, &w_id).await;
    mh2_fan_out(&a, &b, &alice, &alice_b, &bob, &carol, &mut g, &mut mls).await;
    let mh3_alice = mh3_hub_stopped(&a, &b, &alice, &alice_b, &bob, &carol, &mut g, &mut mls).await;
    mh4_no_duplicates(
        &a, &b, &alice, &alice_b, &bob, &carol, &mia, &mut g, &mut mls, &mh3_alice,
    )
    .await;
    mh5_key_packages(&a, &alice, &alice_b, &bob, &carol).await;
    mh6_device_lists(&a, &b, &alice).await;
    mh7_owner_stopped(&a, &alice, &alice_b, &carol, &mut h, &mut mls).await;
    mh8_migration(&a, &c, &alice, bob, &carol, &mia, &mut g, &mut h, mls).await;
    mh9_removal_notice(&a, &b, &alice, &alice_b).await;
    println!("mh: PASS ({:.1}s)", start.elapsed().as_secs_f64());
}

/// MH1: alice (on A, in G and H, Welcome for W pending) adds B (§4.1).
#[allow(clippy::too_many_arguments)]
async fn mh1_add_hub(
    a: &Hub,
    b: &Hub,
    c: &Hub,
    alice: &User,
    carol: &User,
    g: &Group,
    h: &Group,
    w_id: &str,
) -> User {
    let start = Instant::now();
    // Steps 1-4: DeviceList and sign-in on B, B's entry, record seq 2 PUT to
    // the added hub B first, then A.
    put_device_list(b, ALICE, 1, &[11], &[]).await;
    let alice_b = User::sign_in("alice@B", b, ALICE, 11, 0).await;
    let (entry_a, entry_b) = (entry(alice, 0).await, entry(&alice_b, 1).await);
    publish(ALICE, 2, &[&entry_a, &entry_b], &[b, a]).await;

    let (status, body) = b
        .call(
            Method::GET,
            &format!("/v2/users/{}", alice.user_id),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "alice on B: {body}");
    assert_eq!(record_on(b, &alice.user_id).await, Some((2, true)));
    wait_record(a, &alice.user_id, 2, true).await;
    wait_record(c, &alice.user_id, 2, false).await;

    // B serves both groups to alice at the owners' last_seq. H is seeded by
    // A: no history before the seed. B already holds a live replica of G
    // for bob, so C's seed is ignored (§4.3) and the full log stays.
    for (group, owner_view) in [(g, carol), (h, alice)] {
        let owner_seq = last_seq(owner_view, &group.gid).await;
        assert_eq!(owner_seq, group.next - 1);
        eventually(&format!("B's replica of {}", group.gid), || async {
            let (status, body) = alice_b
                .call(Method::GET, &group_path(&group.gid), None)
                .await;
            status == StatusCode::OK && body["last_seq"] == owner_seq
        })
        .await;
        let log = alice_b.log(&group.gid).await;
        if group.gid == g.gid {
            assert_eq!(log, carol.log(&g.gid).await);
        } else {
            assert!(log.is_empty(), "history before the seed: {log:?}");
        }
    }
    // W: C only caches alice's record and B has no replica of it, the
    // §4.3 race case. The record reached B first (§4.1), so C's seed lands.
    eventually("B's replica of W seeded by C", || async {
        let (status, body) = alice_b.call(Method::GET, &group_path(w_id), None).await;
        status == StatusCode::OK && body["last_seq"] == 1
    })
    .await;
    assert!(alice_b.log(w_id).await.is_empty());
    eventually("W's Welcome copied to B", || async {
        pending_welcome_gids(&alice_b).await.contains(w_id)
    })
    .await;

    let updated = |events: Vec<Value>| -> Vec<Value> {
        events
            .into_iter()
            .filter(|e| e["user_id"] == json!(alice.user_id))
            .collect()
    };
    // B supersedes the record it cached for alice as a remote user (seq 1).
    for session in [alice, &alice_b] {
        let events = updated(session.events_of("hosting_record.updated").await);
        assert_eq!(events.len(), 1, "{}: {events:?}", session.name);
        assert_eq!(events[0]["seq"], 2);
        assert_eq!(events[0]["hosted"], true);
        assert_eq!(events[0]["hubs"].as_array().unwrap().len(), 2);
    }

    register_push(&alice_b, "alice-b").await;
    ok(
        "MH1 add hub: B has alice, A and C store seq 2, B serves G (live replica) and H (seeded \
         by A at last_seq) and W (seeded by C, record cached only), \
         W's Welcome copied, one hosting_record.updated per hub",
        start,
    );
    alice_b
}

/// MH2: bob and carol send 20 messages each to G; carol adds a new device of
/// alice, whose Welcome reaches A and B.
#[allow(clippy::too_many_arguments)]
async fn mh2_fan_out(
    a: &Hub,
    b: &Hub,
    alice: &User,
    alice_b: &User,
    bob: &User,
    carol: &User,
    g: &mut Group,
    mls: &mut Mls,
) {
    let start = Instant::now();
    let first = g.next;
    for i in 0..20 {
        let seq = g.take();
        bob.send_text(&mut mls.bob_g, &g.gid, &format!("mh2-b{i}"), seq)
            .await;
        let seq = g.take();
        carol
            .send_text(&mut mls.carol_g, &g.gid, &format!("mh2-c{i}"), seq)
            .await;
    }

    // A new device of alice (DeviceList seq 2 on both hubs), added by carol.
    put_device_list(a, ALICE, 2, &[11, 12], &[]).await;
    put_device_list(b, ALICE, 2, &[11, 12], &[]).await;
    let alice2 = User::sign_in("alice2", a, ALICE, 12, 1).await;
    let alice2_b = User::sign_in("alice2@B", b, ALICE, 12, 0).await;
    let kp = carol.claim(&alice2).await;
    let (commit, welcome, _) = mls
        .carol_g
        .add_members(&carol.provider, &carol.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("mh2-add", &commit), &welcome, &[&alice2]);
    let (status, result) = carol.submit_commit(&g.gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let commit_seq = g.take();
    assert_eq!(result["seq"], commit_seq, "{result}");
    mls.carol_g.merge_pending_commit(&carol.provider).unwrap();
    alice.receive(&mut mls.alice_g, &g.gid, commit_seq).await;
    bob.receive(&mut mls.bob_g, &g.gid, commit_seq).await;

    let seqs: Vec<u64> = (first..=commit_seq).collect();
    // Each hub delivered each message once; `view` checks that both copies
    // are byte-identical.
    received_once(alice, &g.gid, &seqs).await;
    received_once(alice_b, &g.gid, &seqs).await;
    let merged = view(&[alice, alice_b], &g.gid).await;
    let tail: Vec<u64> = merged.keys().copied().filter(|s| *s >= first).collect();
    assert_eq!(tail, seqs, "alice's view: 40 + 1 in seq order");

    for session in [&alice2, &alice2_b] {
        eventually(&format!("{}'s pending Welcome", session.name), || async {
            pending_welcome_gids(session).await.contains(&g.gid)
        })
        .await;
    }

    // Push: only the primary A, while it is up.
    eventually("A to push G to alice", || async {
        pushes(a, &alice.device_id)
            .await
            .iter()
            .any(|(gid, seq, _)| *gid == g.gid && seqs.contains(seq))
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let on_b = pushes(b, &alice.device_id).await;
    assert!(on_b.is_empty(), "B pushed while A is up: {on_b:?}");
    ok(
        "MH2 fan-out: A and B got the 40 messages + 1 Commit once, identical; new device's \
         Welcome on A and B; push from A only",
        start,
    );
}

/// MH3: hub-a stopped; alice sends 20 to G via B, bob and carol 20; B takes
/// over push. Returns alice's seqs.
#[allow(clippy::too_many_arguments)]
async fn mh3_hub_stopped(
    a: &Hub,
    b: &Hub,
    alice: &User,
    alice_b: &User,
    bob: &User,
    carol: &User,
    g: &mut Group,
    mls: &mut Mls,
) -> Vec<u64> {
    let start = Instant::now();
    let stopped_at = i64::try_from(now_ms()).unwrap();
    a.stop();
    let (mut mine, mut others) = (Vec::new(), Vec::new());
    for i in 0..20 {
        let text = format!("mh3-a{i}");
        let message = application(alice, &mut mls.alice_g, text.as_bytes());
        let (status, body) = alice_b.post_message(&g.gid, &text, &message).await;
        assert_eq!(status, StatusCode::CREATED, "alice via B: {body}");
        let seq = g.take();
        assert_eq!(body["seq"], seq, "{body}");
        mine.push(seq);
        let (user, group) = if i % 2 == 0 {
            (bob, &mut mls.bob_g)
        } else {
            (carol, &mut mls.carol_g)
        };
        let seq = g.take();
        user.send_text(group, &g.gid, &format!("mh3-o{i}"), seq)
            .await;
        others.push(seq);
    }
    received_once(bob, &g.gid, &mine).await;
    received_once(carol, &g.gid, &mine).await;
    received_once(alice_b, &g.gid, &others).await;
    let log: BTreeSet<u64> = alice_b.log(&g.gid).await.iter().map(|m| m.0).collect();
    assert!(mine.iter().chain(&others).all(|seq| log.contains(seq)));

    // B pushes once A has been down for the failover delay; bob keeps
    // sending until it does.
    let deadline = Instant::now() + FAILOVER + GATE_REFRESH + Duration::from_secs(15);
    let first_push = loop {
        let found = pushes(b, &alice.device_id)
            .await
            .into_iter()
            .filter(|(gid, ..)| *gid == g.gid)
            .map(|(_, seq, sent_at)| (sent_at, seq))
            .min();
        if let Some(found) = found {
            break found;
        }
        assert!(Instant::now() < deadline, "B never pushed for alice");
        let seq = g.take();
        bob.send_text(&mut mls.bob_g, &g.gid, &format!("mh3-nudge{seq}"), seq)
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let delay = (first_push.0 - stopped_at) as f64 / 1000.0;
    assert!(first_push.0 >= stopped_at, "B pushed while A was up");
    assert!(
        delay <= (FAILOVER + GATE_REFRESH).as_secs_f64(),
        "B pushed {delay:.1}s after A stopped"
    );
    ok(
        &format!(
            "MH3 hub-a stopped: alice's 20 via B reached bob and carol once, her view on B has \
             all 40; B pushed for alice {delay:.1}s after the stop (failover 5s)"
        ),
        start,
    );
    mine
}

/// MH4: hub-a back; the same client_id via A and B is sequenced once; A
/// catches up; push returns to A only.
#[allow(clippy::too_many_arguments)]
async fn mh4_no_duplicates(
    a: &Hub,
    b: &Hub,
    alice: &User,
    alice_b: &User,
    bob: &User,
    carol: &User,
    mia: &User,
    g: &mut Group,
    mls: &mut Mls,
    mh3_alice: &[u64],
) {
    let start = Instant::now();
    a.start().await;
    let message = application(alice, &mut mls.alice_g, b"mh4-x");
    let (status, first) = post_until_available(alice, &g.gid, "mh4-x", &message).await;
    assert_eq!(status, StatusCode::CREATED, "X via A: {first}");
    let seq = g.take();
    assert_eq!(first["seq"], seq, "{first}");
    let (status, again) = alice_b.post_message(&g.gid, "mh4-x", &message).await;
    assert_eq!(status, StatusCode::OK, "X via B: {again}");
    assert_eq!(again["seq"], seq, "{again}");
    let on_c = carol.log(&g.gid).await;
    assert_eq!(
        on_c.iter().filter(|m| m.1 == "mh4-x").count(),
        1,
        "X sequenced once"
    );

    // A drains its backlog; A's and B's replicas match the owner's log.
    eventually("A's replica of G to match C's log", || async {
        alice.log(&g.gid).await == carol.log(&g.gid).await
    })
    .await;
    let on_c = carol.log(&g.gid).await;
    let on_b = alice_b.log(&g.gid).await;
    let seeded = on_b[0].0;
    assert_eq!(
        on_b,
        on_c.iter()
            .filter(|m| m.0 >= seeded)
            .cloned()
            .collect::<Vec<_>>()
    );
    received_once(mia, &g.gid, mh3_alice).await;
    // No duplicate seq on either hub; identical copies (asserted by view).
    view(&[alice, alice_b], &g.gid).await;

    // Push back to A only, once B sees A again.
    let deadline = Instant::now() + CONVERGE;
    loop {
        let seq = g.take();
        bob.send_text(&mut mls.bob_g, &g.gid, &format!("mh4-p{seq}"), seq)
            .await;
        let pushed = |pushes: Vec<(String, u64, i64)>| {
            pushes.iter().any(|(gid, s, _)| *gid == g.gid && *s == seq)
        };
        let mut on_a = false;
        for _ in 0..10 {
            on_a = pushed(pushes(a, &alice.device_id).await);
            if on_a {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let on_b = pushed(pushes(b, &alice.device_id).await);
        if on_a && !on_b {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "push did not return to A only (A {on_a}, B {on_b})"
        );
    }
    ok(
        "MH4 hub-a back: X via A then B sequenced once (B 200, same seq), A drained, replicas \
         identical, no duplicates, push from A only",
        start,
    );
}

/// MH5: disjoint KeyPackages on A and B; local claims on B, routed claims
/// from C (A first, then B while A is stopped).
async fn mh5_key_packages(a: &Hub, alice: &User, alice_b: &User, bob: &User, carol: &User) {
    let start = Instant::now();
    let on_a: BTreeSet<String> = upload_key_packages(alice, alice, 5, false)
        .await
        .into_iter()
        .collect();
    upload_key_packages(alice, alice, 1, true).await;
    let on_b: BTreeSet<String> = upload_key_packages(alice, alice_b, 5, false)
        .await
        .into_iter()
        .collect();
    let lr_b = upload_key_packages(alice, alice_b, 1, true).await.remove(0);

    let mut one_time = BTreeSet::new();
    for _ in 0..3 {
        let (kp, last_resort) = claim_raw(bob, alice).await;
        assert!(
            !last_resort && on_b.contains(&kp),
            "bob's claim not from B's set"
        );
        assert!(one_time.insert(kp), "one-time KeyPackage handed out twice");
    }
    for _ in 0..4 {
        let (kp, last_resort) = claim_raw(carol, alice).await;
        assert!(
            !last_resort && on_a.contains(&kp),
            "carol's claim not from A's set"
        );
        assert!(one_time.insert(kp), "one-time KeyPackage handed out twice");
    }
    a.stop();
    let mut fallback = Vec::new();
    for _ in 0..4 {
        fallback.push(claim_raw(carol, alice).await);
    }
    for (kp, last_resort) in &fallback[..2] {
        assert!(!last_resort && on_b.contains(kp), "{fallback:?}");
        assert!(
            one_time.insert(kp.clone()),
            "one-time KeyPackage handed out twice"
        );
    }
    for (kp, last_resort) in &fallback[2..] {
        assert!(*last_resort && *kp == lr_b, "{fallback:?}");
    }
    a.start().await;
    ok(
        "MH5 KeyPackages: bob@B 3x from B, carol@C 4x from A, 4x from B with A stopped (2 \
         one-time, then B's last resort); all one-time packages distinct",
        start,
    );
}

/// MH6: a device linked on A only reaches B; its revocation uploaded on B
/// only reaches A and ends the device's long-poll there.
async fn mh6_device_lists(a: &Hub, b: &Hub, alice: &User) {
    let start = Instant::now();
    let path = format!("/v2/users/{}/device-list", alice.user_id);
    let linking = device_list(ALICE, 3, &[11, 12, 13], &[]);
    put_device_list(a, ALICE, 3, &[11, 12, 13], &[]).await;
    let alice3 = User::sign_in("alice3", a, ALICE, 13, 0).await;
    eventually("B to have DeviceList 3", || async {
        let (status, body) = b.call(Method::GET, &path, None, None).await;
        status == StatusCode::OK && body["device_list"] == json!(b64(&linking))
    })
    .await;
    User::sign_in("alice3@B", b, ALICE, 13, 0).await;

    // A long-poll of the new device on A, then the revocation on B only.
    let mut cursor = 0;
    loop {
        let (status, body) = alice3
            .call(
                Method::GET,
                &format!("/v2/events?cursor={cursor}&limit=500"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body["events"].as_array().unwrap().is_empty() {
            break;
        }
        cursor = body["next_cursor"].as_u64().unwrap();
    }
    let poll = {
        let (base, token) = (a.base.clone(), alice3.token.clone());
        tokio::spawn(async move {
            let started = Instant::now();
            let result = http(
                &base,
                Method::GET,
                &format!("/v2/events?cursor={cursor}&wait=20"),
                Some(&token),
                None,
            )
            .await;
            (result, started.elapsed())
        })
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    let revoking = device_list(ALICE, 4, &[11, 12], &[13]);
    put_device_list(b, ALICE, 4, &[11, 12], &[13]).await;
    let (result, elapsed) = poll.await.unwrap();
    let (status, body) = result.unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        elapsed < Duration::from_secs(12),
        "long-poll ended after {elapsed:?}, not woken by the revocation"
    );
    let (status, body) = a.call(Method::GET, &path, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["device_list"], json!(b64(&revoking)));
    ok(
        &format!(
            "MH6 DeviceLists: device linked on A signs in on B; revocation on B reached A and \
             ended the device's long-poll on A after {:.1}s (401)",
            elapsed.as_secs_f64()
        ),
        start,
    );
}

/// MH7: the owner of H (hub-a) is stopped: alice's send via B is 503, reads
/// on B work; after the restart the same send succeeds.
async fn mh7_owner_stopped(
    a: &Hub,
    alice: &User,
    alice_b: &User,
    carol: &User,
    h: &mut Group,
    mls: &mut Mls,
) {
    let start = Instant::now();
    let before = alice_b.log(&h.gid).await;
    a.stop();
    let message = application(alice, &mut mls.alice_h, b"mh7");
    let (status, body) = alice_b.post_message(&h.gid, "mh7", &message).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(code(&body), "peer_unavailable");
    let (status, body) = alice_b.call(Method::GET, &group_path(&h.gid), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(alice_b.log(&h.gid).await, before);
    a.start().await;
    let (status, body) = post_until_available(alice_b, &h.gid, "mh7", &message).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let seq = h.take();
    assert_eq!(body["seq"], seq, "{body}");
    carol.wait_message(&h.gid, seq).await;
    ok(
        "MH7 owner hub-a stopped: send to H via B 503 peer_unavailable, reads on B served, \
         delivered after the restart",
        start,
    );
}

/// Sends to G as bob every 500 ms until `stop`; returns bob, his group and
/// the seqs sent.
fn spawn_sender(
    bob: User,
    mut group: MlsGroup,
    gid: String,
    mut next: u64,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<(User, MlsGroup, Vec<u64>)> {
    tokio::spawn(async move {
        let mut sent = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            bob.send_text(&mut group, &gid, &format!("mh8-{next}"), next)
                .await;
            sent.push(next);
            next += 1;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        (bob, group, sent)
    })
}

/// MH8: mia migrates from A to C (add C, make C primary, drain, remove A)
/// while bob sends to G at 2 msg/s.
#[allow(clippy::too_many_arguments)]
async fn mh8_migration(
    a: &Hub,
    c: &Hub,
    alice: &User,
    bob: User,
    carol: &User,
    mia: &User,
    g: &mut Group,
    h: &mut Group,
    mut mls: Mls,
) {
    let start = Instant::now();
    // A package of mia claimed through C (brokered from A) before C hosts her.
    let brokered = carol.claim(mia).await.tls_serialize_detached().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let first = g.next;
    let sender = spawn_sender(bob, mls.bob_g, g.gid.clone(), first, stop.clone());

    // Add C (seq 2): DeviceList and sign-in on C, record PUT to C first.
    put_device_list(c, MIA, 1, &[61], &[]).await;
    let mia_c = User::sign_in("mia@C", c, MIA, 61, 0).await;
    let (entry_a, entry_c) = (entry(mia, 0).await, entry(&mia_c, 1).await);
    publish(MIA, 2, &[&entry_a, &entry_c], &[c, a]).await;
    wait_record(a, &mia.user_id, 2, true).await;
    // Each phase spans a few of bob's messages.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let on_c: BTreeSet<String> = upload_key_packages(mia, &mia_c, 3, false)
        .await
        .into_iter()
        .collect();
    upload_key_packages(mia, &mia_c, 1, true).await;
    let (status, body) = mia_c
        .call(
            Method::POST,
            "/v2/keypackages",
            Some(json!({ "key_packages": [b64(&brokered)] })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(code(&body), "duplicate_key_package", "{body}");

    // Switch (seq 3): C primary.
    let (entry_a, entry_c) = (entry(mia, 1).await, entry(&mia_c, 0).await);
    publish(MIA, 3, &[&entry_c, &entry_a], &[c, a]).await;
    wait_record(a, &mia.user_id, 3, true).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Drain check (§7.1).
    let gids = BTreeSet::from([g.gid.clone(), h.gid.clone()]);
    eventually("mia's groups on C", || async {
        let (status, body) = mia_c.call(Method::GET, "/v2/groups", None).await;
        status == StatusCode::OK
            && body["groups"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|group| group["gid"].as_str())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                .is_superset(&gids)
    })
    .await;
    eventually("mia's pending Welcomes copied to C", || async {
        pending_welcome_gids(&mia_c)
            .await
            .is_superset(&pending_welcome_gids(mia).await)
    })
    .await;
    mia.events_of("message").await;

    // Remove A (seq 4), PUT to C and A.
    publish(MIA, 4, &[&entry_c], &[c, a]).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    stop.store(true, Ordering::SeqCst);
    let (_bob, bob_g, sent) = sender.await.unwrap();
    mls.bob_g = bob_g;
    g.next = sent.last().map_or(first, |seq| seq + 1);

    // mia's view (A, then C) has every bob message, gap-free.
    eventually("mia's view to contain every bob message", || async {
        let merged = view(&[mia, &mia_c], &g.gid).await;
        sent.iter().all(|seq| merged.contains_key(seq))
    })
    .await;
    let merged = view(&[mia, &mia_c], &g.gid).await;
    let span: Vec<u64> = merged
        .keys()
        .copied()
        .filter(|seq| (first..g.next).contains(seq))
        .collect();
    assert_eq!(
        span,
        (first..g.next).collect::<Vec<_>>(),
        "gap in mia's view"
    );

    // A: removed state.
    let removed = mia
        .events_of("hosting_record.updated")
        .await
        .into_iter()
        .find(|e| e["seq"] == 4)
        .expect("hosting_record.updated seq 4 on A");
    assert_eq!(removed["hosted"], false);
    assert_eq!(record_on(a, &mia.user_id).await, Some((4, false)));
    let (status, body) = mia
        .call(
            Method::POST,
            "/v2/keypackages",
            Some(json!({ "key_packages": [b64(&mia.key_package())] })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "hosting_record_required");
    let message = application(mia, &mut mls.mia_h, b"mh8-via-a");
    let (status, body) = mia.post_message(&h.gid, "mh8-via-a", &message).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "hosting_record_required");
    // The user row stays during the grace period (the purge is covered by
    // multihoming_records.rs, the clock cannot be advanced here).
    let (status, body) = a
        .call(
            Method::GET,
            &format!("/v2/users/{}", mia.user_id),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A claim of mia on A routes by her record to C: A serves none of its own.
    let (kp, _) = claim_raw(alice, mia).await;
    assert!(on_c.contains(&kp), "claim through A not served by C");

    // mia's messages to H (owned by the removed hub A) via C.
    let message = application(mia, &mut mls.mia_h, b"mh8-via-c");
    let (status, body) = mia_c.post_message(&h.gid, "mh8-via-c", &message).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let seq = h.take();
    assert_eq!(body["seq"], seq, "{body}");
    let text = alice.receive(&mut mls.alice_h, &h.gid, seq).await;
    assert_eq!(text.unwrap(), b"mh8-via-c");
    ok(
        &format!(
            "MH8 migration A -> C: {} bob messages gap-free in mia's view; A removed (event \
             hosted:false, 403 hosting_record_required, tombstone seq 4, claims routed to C); \
             H via C sequenced on A; 409 duplicate_key_package for a brokered package",
            sent.len()
        ),
        start,
    );
}

/// MH9: hub-b stopped; alice removes B with a PUT to A only; B learns it
/// from A's outbox after the restart.
async fn mh9_removal_notice(a: &Hub, b: &Hub, alice: &User, alice_b: &User) {
    let start = Instant::now();
    b.stop();
    let entry_a = entry(alice, 0).await;
    publish(ALICE, 3, &[&entry_a], &[a]).await;
    b.start().await;
    wait_record(b, &alice.user_id, 3, false).await;
    eventually("hosting_record.updated hosted:false on B", || async {
        alice_b
            .events_of("hosting_record.updated")
            .await
            .iter()
            .any(|e| e["seq"] == 3 && e["hosted"] == false)
    })
    .await;
    let (status, body) = alice_b
        .call(
            Method::POST,
            "/v2/keypackages",
            Some(json!({ "key_packages": [b64(&alice.key_package())] })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "hosting_record_required");
    ok(
        "MH9 removal notice: B got record seq 3 from A's outbox after its restart and is in the \
         removed state",
        start,
    );
}
