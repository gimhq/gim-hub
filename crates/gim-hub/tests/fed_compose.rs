//! Compose acceptance driver for closed federation (docs/federation.md
//! §11.2, §11.3; plan acceptance M2b). It speaks the client API v2 over HTTP
//! to the hubs of `deploy/federation/compose.yaml` with real MLS clients
//! (openmls, 0xF001 credentials, DeviceLists, hosting records) and stops and
//! starts hub containers through the Docker API for the outage cases.
//!
//! Ignored by default: `scripts/fed-test.sh` starts the topology and runs it
//! with `--ignored` in a container attached to the federation network.
//!
//! Environment: `GIM_FED_HUB_{A,B,C,X}` (base URLs), `GIM_FED_HUB_X_ID`
//! (hub-x's hub_id), `GIM_FED_HUB_B_ID` (hub-b's hub_id; the base URLs are
//! also the hubs' `GIM_HUB_PUBLIC_URL`),
//! `GIM_FED_PUSH_MOCK` (base URL of the mock push server), `GIM_FED_PROJECT` (compose project name, for container
//! names), `GIM_FED_DOCKER_SOCKET` (default `/var/run/docker.sock`),
//! `GIM_FED_PSK` (`1`: hub-a, hub-b and hub-c run with a pnet key that
//! hub-x lacks, `deploy/federation/compose.psk.yaml`).

mod compose_support;
#[path = "../../gim-hub-api/tests/mls_support/mod.rs"]
mod mls_support;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hyper::{Method, StatusCode};
use openmls::prelude::{
    tls_codec::Deserialize, LeafNodeParameters, MlsGroup, MlsMessageIn, OpenMlsProvider,
    ProcessedMessageContent,
};
use serde_json::{json, Value};

use compose_support::{
    application, commit_body, eventually, http_bytes, leaf_of, sorted, with_welcome, Hub, User,
    CONVERGE,
};
use mls_support::{b64, code, device_list, group_path, unb64};

/// Prints a step result with the time since `start`.
fn ok(step: &str, start: Instant) {
    println!("fed: ok   {step} ({:.1}s)", start.elapsed().as_secs_f64());
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs deploy/federation/compose.yaml; run by scripts/fed-test.sh"]
async fn compose_federation() {
    let a = Hub::from_env("hub-a", "GIM_FED_HUB_A");
    let b = Hub::from_env("hub-b", "GIM_FED_HUB_B");
    let c = Hub::from_env("hub-c", "GIM_FED_HUB_C");
    let x = Hub::from_env("hub-x", "GIM_FED_HUB_X");
    let x_id = std::env::var("GIM_FED_HUB_X_ID").expect("GIM_FED_HUB_X_ID is not set");
    let psk = std::env::var("GIM_FED_PSK").is_ok_and(|value| value == "1");
    for hub in [&a, &b, &c, &x] {
        hub.wait_healthy().await;
    }

    let start = Instant::now();
    let b_id = std::env::var("GIM_FED_HUB_B_ID").expect("GIM_FED_HUB_B_ID is not set");
    b.check_proof(&b_id).await;
    ok(
        "hub-b proves possession of its hub_id at its public URL",
        start,
    );
    let alice = User::sign_up("alice", &a, 1, 11, 2).await;
    let bob = User::sign_up("bob", &b, 2, 21, 2).await;
    let carol = User::sign_up("carol", &c, 3, 31, 2).await;
    let dave = User::sign_up("dave", &c, 4, 41, 2).await;
    let eve = User::sign_up("eve", &x, 5, 51, 2).await;
    // Remote hubs resolve the records (DHT or GetHostingRecord).
    for (hub, user) in [(&b, &alice), (&c, &alice), (&a, &bob), (&a, &carol)] {
        let path = format!("/v2/users/{}/hosting-record", user.user_id);
        eventually(
            &format!("{}'s record on {}", user.name, hub.service),
            || async {
                let (status, body) = hub.call(Method::GET, &path, None, None).await;
                status == StatusCode::OK && body["seq"] == 1
            },
        )
        .await;
    }
    ok("sign-up, hosting records resolved across hubs", start);

    cross_hub_dm(&alice, &bob).await;
    cross_hub_blobs(&a, &alice, &bob).await;
    revoked_device(&b, &alice, &bob).await;
    let (gid, mut groups) = three_hub_group(&alice, &bob, &carol, &dave).await;
    concurrent_commits(&gid, &alice, &bob, &dave, &mut groups).await;
    member_hub_outage(&gid, &c, &alice, &bob, &dave, &mut groups).await;
    owner_hub_outage(&gid, &a, &alice, &bob, &dave, &mut groups).await;
    refusal(&a, &x_id, &alice, &eve, psk).await;
    leave_by_proposal(&a, &b, &c, &alice).await;
    webhook_push(&a, &b, &alice).await;
    println!("fed: PASS ({:.1}s)", start.elapsed().as_secs_f64());
}

/// T2: bob@B opens a direct group with alice@A; both send three messages.
async fn cross_hub_dm(alice: &User, bob: &User) {
    let start = Instant::now();
    let (gid, mut bob_group) = bob.create_group("direct").await;
    let kp = bob.claim(alice).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[alice]);
    let (status, result) = bob.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 1, "epoch": 1, "duplicate": false }));
    bob_group.merge_pending_commit(&bob.provider).unwrap();

    let mut alice_group = alice.join(&gid).await;
    for i in 0..3u64 {
        bob.send_text(&mut bob_group, &gid, &format!("b{i}"), 2 + i)
            .await;
    }
    for i in 0..3u64 {
        let text = alice.receive(&mut alice_group, &gid, 2 + i).await;
        assert_eq!(text.unwrap(), format!("b{i}").into_bytes());
    }
    let mut first = None;
    for i in 0..3u64 {
        let mls = application(alice, &mut alice_group, format!("a{i}").as_bytes());
        let (status, message) = alice.post_message(&gid, &format!("a{i}"), &mls).await;
        assert_eq!(status, StatusCode::CREATED, "{message}");
        assert_eq!(message["seq"], 5 + i);
        first.get_or_insert((mls, message));
    }
    for i in 0..3u64 {
        let text = bob.receive(&mut bob_group, &gid, 5 + i).await;
        assert_eq!(text.unwrap(), format!("a{i}").into_bytes());
    }
    // client_id replay through the member hub: the stored message.
    let (mls, message) = first.unwrap();
    let (status, replay) = alice.post_message(&gid, "a0", &mls).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay, message);

    let on_a = alice.log(&gid).await;
    assert_eq!(on_a, bob.log(&gid).await);
    assert_eq!(
        on_a.iter().map(|(seq, ..)| *seq).collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    assert_eq!(alice.message_seqs(&gid).await, [2, 3, 4]);
    assert_eq!(bob.message_seqs(&gid).await, [5, 6, 7]);
    ok("cross-hub DM (B owns, A member)", start);
}

/// Uploads `data` as `user` on their hub; returns the blob id.
async fn upload_blob(user: &User, data: &[u8]) -> String {
    let (status, _, body) = http_bytes(
        &user.hub.base,
        Method::POST,
        "/v2/blobs",
        Some(&user.token),
        &[],
        data.to_vec(),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::CREATED);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["size"], data.len());
    body["blob_id"].as_str().unwrap().to_owned()
}

/// `GET /v2/blobs/{blob_id}` as `user` on their hub, with an optional Range.
async fn download_blob(
    user: &User,
    blob_id: &str,
    range: Option<&str>,
) -> (StatusCode, hyper::HeaderMap, Vec<u8>) {
    let headers: Vec<_> = range
        .map(|range| (hyper::header::RANGE, range.to_owned()))
        .into_iter()
        .collect();
    let path = format!("/v2/blobs/{}", blob_id.replace('/', "%2F"));
    let (status, headers, body) = http_bytes(
        &user.hub.base,
        Method::GET,
        &path,
        Some(&user.token),
        &headers,
        Vec::new(),
    )
    .await
    .unwrap();
    (status, headers, body.to_vec())
}

/// H5-B1: alice@A uploads attachments of the DM with bob@B; hub-b fetches
/// them from the origin hub-a (FetchBlob, more than one chunk) and serves
/// later reads from its cache, also while hub-a is down. A blob hub-b never
/// fetched is 503 during the outage and served after the restart.
async fn cross_hub_blobs(a: &Hub, alice: &User, bob: &User) {
    let start = Instant::now();
    let big: Vec<u8> = (0..5 * 1024 * 1024 + 7).map(|i| (i % 251) as u8).collect();
    let cached = upload_blob(alice, &big).await;
    assert!(cached.contains('/'), "{cached}");
    let fresh = upload_blob(alice, b"fetched after the outage").await;

    let (status, _, body) = download_blob(bob, &cached, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body == big, "blob bytes differ");
    let (status, headers, body) = download_blob(bob, &cached, Some("bytes=10-19")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, big[10..20]);
    assert_eq!(
        headers[hyper::header::CONTENT_RANGE],
        format!("bytes 10-19/{}", big.len())
    );

    a.stop();
    let (status, _, body) = download_blob(bob, &cached, None).await;
    assert_eq!(status, StatusCode::OK, "cached copy while hub-a is down");
    assert!(body == big);
    let (status, headers, body) = download_blob(bob, &fresh, None).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(headers.contains_key(hyper::header::RETRY_AFTER));
    a.start().await;
    let deadline = Instant::now() + CONVERGE;
    let (status, _, body) = loop {
        let result = download_blob(bob, &fresh, None).await;
        if result.0 != StatusCode::SERVICE_UNAVAILABLE || Instant::now() > deadline {
            break result;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"fetched after the outage");
    ok(
        "cross-hub blobs: fetched from the origin, cached, 503 while it is down",
        start,
    );
}

/// T6: alice@A certifies a second device, which uploads a KeyPackage that
/// bob@B claims, and then revokes it (DeviceList seq 2 and 3). Once the owner
/// hub-b has the new list, bob's Commit adding that KeyPackage is rejected.
async fn revoked_device(b: &Hub, alice: &User, bob: &User) {
    let start = Instant::now();
    let path = format!("/v2/users/{}/device-list", alice.user_id);
    let path = &path;
    let publish = |list: Vec<u8>| async move {
        let (status, body) = alice
            .hub
            .call(
                Method::PUT,
                path,
                None,
                Some(json!({ "device_list": b64(&list) })),
            )
            .await;
        assert!(status.is_success(), "alice device list: {body}");
    };
    publish(device_list(1, 2, &[11, 12], &[])).await;
    let alice2 = User::sign_in("alice2", &alice.hub, 1, 12, 1).await;
    let kp = bob.claim(&alice2).await;

    let revoking = device_list(1, 3, &[11], &[12]);
    publish(revoking.clone()).await;
    let expected = json!(b64(&revoking));
    eventually("hub-b to have alice's revoking DeviceList", || async {
        let (status, body) = b.call(Method::GET, path, None, None).await;
        status == StatusCode::OK && body["device_list"] == expected
    })
    .await;

    let (gid, mut group) = bob.create_group("group").await;
    let (commit, _, _) = group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let (status, body) = bob.submit_commit(&gid, commit_body("c1", &commit)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code(&body), "validation_failed", "{body}");
    assert_eq!(
        body["error"]["message"], "invalid MLS credential (revoked_device)",
        "{body}"
    );
    assert!(bob.log(&gid).await.is_empty());
    ok(
        "revoked device of alice@A rejected by owner hub-b (400 revoked_device)",
        start,
    );
}

/// MLS groups of the group scenarios, per member.
struct Groups {
    alice: MlsGroup,
    bob: MlsGroup,
    dave: MlsGroup,
}

/// T3/T4: alice@A creates a group with bob@B and carol@C; everyone sends;
/// bob (non-owning hub) adds dave@C and removes carol.
async fn three_hub_group(alice: &User, bob: &User, carol: &User, dave: &User) -> (String, Groups) {
    let start = Instant::now();
    let (gid, mut alice_group) = alice.create_group("group").await;
    let kps = vec![alice.claim(bob).await, alice.claim(carol).await];
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[bob, carol]);
    let (status, result) = alice.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let mut bob_group = bob.join(&gid).await;
    let mut carol_group = carol.join(&gid).await;
    let three = sorted(&[&alice.device_id, &bob.device_id, &carol.device_id]);
    for user in [bob, carol] {
        eventually(&format!("{}'s replica roster", user.name), || async {
            user.roster(&gid).await == (StatusCode::OK, three.clone())
        })
        .await;
    }

    alice
        .send_text(&mut alice_group, &gid, "hello from A", 2)
        .await;
    bob.send_text(&mut bob_group, &gid, "hello from B", 3).await;
    carol
        .send_text(&mut carol_group, &gid, "hello from C", 4)
        .await;
    for (user, group, seqs) in [
        (alice, &mut alice_group, [3, 4]),
        (bob, &mut bob_group, [2, 4]),
        (carol, &mut carol_group, [2, 3]),
    ] {
        for seq in seqs {
            assert!(user.receive(group, &gid, seq).await.is_some());
        }
        assert_eq!(user.message_seqs(&gid).await, seqs);
    }
    ok("3-hub group: every member gets every message once", start);

    // bob@B adds dave@C: the Commit is forwarded to the owner A.
    let start = Instant::now();
    let kp = bob.claim(dave).await;
    let (commit, welcome, _) = bob_group
        .add_members(&bob.provider, &bob.signer, &[kp])
        .unwrap();
    let body = with_welcome(commit_body("c2", &commit), &welcome, &[dave]);
    let (status, result) = bob.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 5, "epoch": 2, "duplicate": false }));
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    alice.receive(&mut alice_group, &gid, 5).await;
    carol.receive(&mut carol_group, &gid, 5).await;
    let mut dave_group = dave.join(&gid).await;

    // bob removes carol; C keeps its replica for dave.
    let (commit, _, _) = bob_group
        .remove_members(&bob.provider, &bob.signer, &[leaf_of(&bob_group, carol)])
        .unwrap();
    let (status, result) = bob.submit_commit(&gid, commit_body("c3", &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["seq"], 6);
    bob_group.merge_pending_commit(&bob.provider).unwrap();
    alice.receive(&mut alice_group, &gid, 6).await;
    dave.receive(&mut dave_group, &gid, 6).await;
    carol.wait_message(&gid, 6).await;
    for user in [alice, bob, carol, dave] {
        let of_group = |events: Vec<Value>| -> Vec<Value> {
            events.into_iter().filter(|e| e["gid"] == gid).collect()
        };
        eventually(&format!("{}'s membership events", user.name), || async {
            of_group(user.events_of("group.member_added").await)
                .iter()
                .any(|e| e["user_id"] == json!(dave.user_id) && e["seq"] == 5)
                && !of_group(user.events_of("group.member_removed").await).is_empty()
        })
        .await;
        let removed = of_group(user.events_of("group.member_removed").await);
        assert_eq!(removed.len(), 1, "{}: {removed:?}", user.name);
        assert_eq!(removed[0]["user_id"], json!(carol.user_id));
        assert_eq!(removed[0]["seq"], 6);
    }
    let roster = sorted(&[&alice.device_id, &bob.device_id, &dave.device_id]);
    assert_eq!(dave.roster(&gid).await, (StatusCode::OK, roster));
    let (status, body) = carol.call(Method::GET, &group_path(&gid), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "not_member");
    // Nothing reaches carol after the removing Commit.
    alice
        .send_text(&mut alice_group, &gid, "after removal", 7)
        .await;
    for (user, group) in [(bob, &mut bob_group), (dave, &mut dave_group)] {
        assert!(user.receive(group, &gid, 7).await.is_some());
    }
    assert_eq!(carol.message_seqs(&gid).await, [2, 3, 5, 6]);
    ok(
        "add (dave@C) and remove (carol@C) from non-owning hub B",
        start,
    );

    (
        gid,
        Groups {
            alice: alice_group,
            bob: bob_group,
            dave: dave_group,
        },
    )
}

/// T5: bob@B and dave@C commit at the same epoch through their member hubs.
async fn concurrent_commits(gid: &str, alice: &User, bob: &User, dave: &User, groups: &mut Groups) {
    let start = Instant::now();
    let bob_commit = groups
        .bob
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();
    let dave_commit = groups
        .dave
        .self_update(&dave.provider, &dave.signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();
    let (bob_body, dave_body) = (
        commit_body("u-bob", &bob_commit),
        commit_body("u-dave", &dave_commit),
    );
    let (bob_result, dave_result) = tokio::join!(
        bob.submit_commit(gid, bob_body.clone()),
        dave.submit_commit(gid, dave_body.clone()),
    );
    let mut statuses = [bob_result.0, dave_result.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::CONFLICT],
        "{bob_result:?} {dave_result:?}"
    );
    let bob_won = bob_result.0 == StatusCode::CREATED;
    let (won, lost) = if bob_won {
        (&bob_result.1, &dave_result.1)
    } else {
        (&dave_result.1, &bob_result.1)
    };
    assert_eq!(won, &json!({ "seq": 8, "epoch": 4, "duplicate": false }));
    assert_eq!(code(lost), "stale_epoch", "{lost}");
    assert_eq!(lost["current_epoch"], 4);

    let (winner, loser, winner_body) = if bob_won {
        (bob, dave, bob_body)
    } else {
        (dave, bob, dave_body)
    };
    // Resubmitting the winner is a duplicate.
    let (status, again) = winner.submit_commit(gid, winner_body).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again, json!({ "seq": 8, "epoch": 4, "duplicate": true }));

    let (winner_group, loser_group) = if bob_won {
        (&mut groups.bob, &mut groups.dave)
    } else {
        (&mut groups.dave, &mut groups.bob)
    };
    winner_group.merge_pending_commit(&winner.provider).unwrap();
    alice.receive(&mut groups.alice, gid, 8).await;
    // The loser catches up and retries successfully.
    loser_group
        .clear_pending_commit(loser.provider.storage())
        .unwrap();
    loser.receive(loser_group, gid, 8).await;
    let retry = loser_group
        .self_update(
            &loser.provider,
            &loser.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    let (status, result) = loser
        .submit_commit(gid, commit_body("u-retry", &retry))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 9, "epoch": 5, "duplicate": false }));
    loser_group.merge_pending_commit(&loser.provider).unwrap();
    alice.receive(&mut groups.alice, gid, 9).await;
    winner.receive(winner_group, gid, 9).await;

    // Same log on every hub.
    let on_a = alice.log(gid).await;
    assert_eq!(on_a.len(), 9);
    eventually("replicas to reach seq 9", || async {
        bob.log(gid).await == on_a && dave.log(gid).await == on_a
    })
    .await;
    ok(
        &format!(
            "concurrent Commit conflict ({} won, {} got 409 stale_epoch, retry ok)",
            winner.name, loser.name
        ),
        start,
    );
}

/// T7: hub-c (dave) is stopped while alice@A and bob@B send 50 messages;
/// after the restart dave receives all of them once, in order.
async fn member_hub_outage(
    gid: &str,
    c: &Hub,
    alice: &User,
    bob: &User,
    dave: &User,
    groups: &mut Groups,
) {
    let start = Instant::now();
    c.stop();
    for i in 0..50u64 {
        let (user, group) = if i % 2 == 0 {
            (alice, &mut groups.alice)
        } else {
            (bob, &mut groups.bob)
        };
        user.send_text(group, gid, &format!("outage-{i}"), 10 + i)
            .await;
    }
    c.start().await;
    for i in 0..50u64 {
        let text = dave.receive(&mut groups.dave, gid, 10 + i).await;
        assert_eq!(text.unwrap(), format!("outage-{i}").into_bytes());
    }
    // Exactly once, in order.
    let seqs = dave.message_seqs(gid).await;
    let tail: Vec<u64> = seqs.iter().copied().filter(|seq| *seq >= 10).collect();
    assert_eq!(tail, (10..60).collect::<Vec<_>>(), "{seqs:?}");
    let mut unique = seqs.clone();
    unique.dedup();
    assert_eq!(unique, seqs, "duplicate deliveries");
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    eventually("C's replica to match A's log", || async {
        dave.log(gid).await == alice.log(gid).await
    })
    .await;
    ok(
        "member hub outage (stop/start hub-c): 50 messages, no loss, no duplicates",
        start,
    );
}

/// T9: the owner hub-a is stopped; bob's send fails with 503 and B's replica
/// still serves reads; after the restart the same send succeeds.
async fn owner_hub_outage(
    gid: &str,
    a: &Hub,
    alice: &User,
    bob: &User,
    dave: &User,
    groups: &mut Groups,
) {
    let start = Instant::now();
    let before = bob.log(gid).await;
    a.stop();
    let mls = application(bob, &mut groups.bob, b"while the owner is down");
    let (status, body) = bob.post_message(gid, "owner-down", &mls).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(code(&body), "peer_unavailable");
    assert_eq!(bob.log(gid).await, before);
    a.start().await;
    // Retry the same message (same client_id) until A is reachable again.
    let deadline = Instant::now() + CONVERGE;
    let (status, body) = loop {
        let result = bob.post_message(gid, "owner-down", &mls).await;
        if result.0 != StatusCode::SERVICE_UNAVAILABLE || Instant::now() > deadline {
            break result;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["seq"], 60, "{body}");
    for (user, group) in [(alice, &mut groups.alice), (dave, &mut groups.dave)] {
        let text = user.receive(group, gid, 60).await;
        assert_eq!(text.unwrap(), b"while the owner is down");
    }
    ok(
        "owner hub outage (stop/start hub-a): 503 peer_unavailable, then delivered",
        start,
    );
}

/// T10: hub-x is on nobody's allowlist: hub-a refuses its Hello and eve@X
/// cannot claim alice@A. T11 (`psk`): hub-x lacks the pnet key, so its
/// connections fail before any Hello reaches hub-a.
async fn refusal(a: &Hub, x_id: &str, alice: &User, eve: &User, psk: bool) {
    let start = Instant::now();
    let request = json!({ "targets": [{ "user_id": alice.user_id }] });
    let (status, body) = eve
        .call(Method::POST, "/v2/keypackages/claim", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_packages"], json!([]), "{body}");
    let listed = |field: &str| {
        body[field]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["user_id"] == json!(alice.user_id))
    };
    assert!(listed("unavailable") || listed("missing"), "{body}");

    let refused = || {
        a.logs()
            .lines()
            .any(|line| line.contains("Hello refused") && line.contains(x_id))
    };
    if psk {
        // hub-x has been dialing hub-a since startup.
        assert!(!refused(), "a Hello of hub-x reached hub-a despite the PSK");
    } else {
        eventually("hub-a to log the refused Hello of hub-x", || async {
            refused()
        })
        .await;
    }
    // Nothing about eve reached A.
    let (status, body) = alice
        .call(Method::GET, &format!("/v2/users/{}", eve.user_id), None)
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    let (status, body) = a
        .call(
            Method::GET,
            &format!("/v2/users/{}/hosting-record", eve.user_id),
            None,
            None,
        )
        .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    ok(
        if psk {
            "hub-x without the PSK never reaches hub-a; eve@X cannot reach alice@A"
        } else {
            "non-allowlisted hub-x refused; eve@X cannot reach alice@A"
        },
        start,
    );
}

/// T13: frank@B leaves a group owned by hub-a with a self-Remove Proposal
/// (forwarded to A); grace@C commits it by reference through hub-c; frank
/// is removed on every hub.
async fn leave_by_proposal(a: &Hub, b: &Hub, c: &Hub, alice: &User) {
    let start = Instant::now();
    let frank = User::sign_up("frank", b, 6, 61, 1).await;
    let grace = User::sign_up("grace", c, 7, 71, 1).await;
    for user in [&frank, &grace] {
        let path = format!("/v2/users/{}/hosting-record", user.user_id);
        eventually(&format!("{}'s record on hub-a", user.name), || async {
            let (status, body) = a.call(Method::GET, &path, None, None).await;
            status == StatusCode::OK && body["seq"] == 1
        })
        .await;
    }
    let (gid, mut alice_group) = alice.create_group("group").await;
    let kps = vec![alice.claim(&frank).await, alice.claim(&grace).await];
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[&frank, &grace]);
    let (status, result) = alice.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let mut frank_group = frank.join(&gid).await;
    let mut grace_group = grace.join(&gid).await;
    let three = sorted(&[&alice.device_id, &frank.device_id, &grace.device_id]);
    for user in [&frank, &grace] {
        eventually(&format!("{}'s replica roster", user.name), || async {
            user.roster(&gid).await == (StatusCode::OK, three.clone())
        })
        .await;
    }

    // Submits like a client: 503 `peer_unavailable` (e.g. a connection to
    // hub-a still closing after the outage scenario) is retried as is.
    async fn submit(user: &User, gid: &str, body: Value) -> (StatusCode, Value) {
        let deadline = Instant::now() + CONVERGE;
        loop {
            let (status, result) = user.submit_commit(gid, body.clone()).await;
            if status != StatusCode::SERVICE_UNAVAILABLE || Instant::now() > deadline {
                return (status, result);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    // Stores a Proposal, or merges a Commit, from the message `seq`.
    let process = |user: &User, group: &mut MlsGroup, event: &Value| {
        let message = MlsMessageIn::tls_deserialize_exact(unb64(&event["mls_message"])).unwrap();
        let processed = group
            .process_message(&user.provider, message.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ProposalMessage(proposal) => group
                .store_pending_proposal(user.provider.storage(), *proposal)
                .unwrap(),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group.merge_staged_commit(&user.provider, *staged).unwrap()
            }
            _ => panic!("unexpected message"),
        }
    };

    let leave = frank_group
        .leave_group(&frank.provider, &frank.signer)
        .unwrap();
    let (status, result) = submit(&frank, &gid, commit_body("p1", &leave)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 2, "epoch": 1, "duplicate": false }));
    for (user, group) in [(alice, &mut alice_group), (&grace, &mut grace_group)] {
        let event = user.wait_message(&gid, 2).await;
        assert_eq!(event["kind"], "proposal", "{}", user.name);
        process(user, group, &event);
    }
    let (commit, _, _) = grace_group
        .commit_to_pending_proposals(&grace.provider, &grace.signer)
        .unwrap();
    let (status, result) = submit(&grace, &gid, commit_body("c2", &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 3, "epoch": 2, "duplicate": false }));
    grace_group.merge_pending_commit(&grace.provider).unwrap();
    process(alice, &mut alice_group, &alice.wait_message(&gid, 3).await);
    assert_eq!(alice_group.epoch().as_u64(), 2);
    assert_eq!(alice_group.members().count(), 2);

    for user in [alice, &frank, &grace] {
        let removed = || async {
            user.events_of("group.member_removed")
                .await
                .into_iter()
                .filter(|e| e["gid"] == gid)
                .collect::<Vec<_>>()
        };
        eventually(&format!("{}'s member_removed", user.name), || async {
            !removed().await.is_empty()
        })
        .await;
        let removed = removed().await;
        assert_eq!(removed.len(), 1, "{}: {removed:?}", user.name);
        assert_eq!(removed[0]["user_id"], json!(frank.user_id));
        assert_eq!(removed[0]["by_device_id"], json!(grace.device_id));
        assert_eq!(removed[0]["seq"], 3);
    }
    let two = sorted(&[&alice.device_id, &grace.device_id]);
    for user in [alice, &grace] {
        assert_eq!(user.roster(&gid).await, (StatusCode::OK, two.clone()));
    }
    let (status, body) = frank.call(Method::GET, &group_path(&gid), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "not_member");
    ok(
        "frank@B leaves by Proposal, grace@C commits it by reference",
        start,
    );
}

/// `registration.token` -> recorded webhook deliveries at the mock push
/// server, oldest first.
async fn mock_deliveries(mock: &Hub, token: &str) -> Vec<Value> {
    let (status, body) = mock
        .call(
            Method::GET,
            &format!("/deliveries?token={token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["deliveries"].as_array().unwrap().clone()
}

async fn mock_counter(mock: &Hub, name: &str) -> u64 {
    let (status, body) = mock.call(Method::GET, "/stats", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["counters"][name].as_u64().unwrap()
}

/// H6 (docs/push.md §2): henry@B and ivan@B register webhook providers on
/// hub-b and join a group of alice@A. A message to henry is exactly one
/// signed delivery at the mock push server, a Proposal none; ivan's `gone-`
/// token is answered 410 once and hub-b deletes the registration.
async fn webhook_push(a: &Hub, b: &Hub, alice: &User) {
    let start = Instant::now();
    let mock = Hub::from_env("push-mock", "GIM_FED_PUSH_MOCK");
    let hub_b_id = std::env::var("GIM_FED_HUB_B_ID").expect("GIM_FED_HUB_B_ID is not set");
    mock.wait_healthy().await;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let (henry_token, ivan_token) = (format!("t-{nonce:x}"), format!("gone-{nonce:x}"));

    let henry = User::sign_up("henry", b, 8, 81, 1).await;
    let ivan = User::sign_up("ivan", b, 9, 91, 1).await;
    for (user, token) in [(&henry, &henry_token), (&ivan, &ivan_token)] {
        let (status, body) = user
            .call(
                Method::PUT,
                "/v2/push/registration",
                Some(json!({ "provider": "mock-android", "token": token })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let path = format!("/v2/users/{}/hosting-record", user.user_id);
        eventually(&format!("{}'s record on hub-a", user.name), || async {
            let (status, body) = a.call(Method::GET, &path, None, None).await;
            status == StatusCode::OK && body["seq"] == 1
        })
        .await;
    }
    let gone_before = mock_counter(&mock, "gone").await;

    // seq 1: the Welcomes; henry's is delivered, ivan's answered 410.
    let (gid, mut alice_group) = alice.create_group("group").await;
    let kps = vec![alice.claim(&henry).await, alice.claim(&ivan).await];
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let body = with_welcome(commit_body("c1", &commit), &welcome, &[&henry, &ivan]);
    let (status, result) = alice.submit_commit(&gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    eventually("henry's welcome push", || async {
        !mock_deliveries(&mock, &henry_token).await.is_empty()
    })
    .await;
    eventually("ivan's push answered 410", || async {
        mock_counter(&mock, "gone").await > gone_before
    })
    .await;

    // seq 2: a message; seq 3: a Proposal; seq 4: the Commit of it.
    alice.send_text(&mut alice_group, &gid, "push", 2).await;
    let message_seqs = |deliveries: &[Value]| -> Vec<u64> {
        deliveries
            .iter()
            .filter(|d| d["body"]["payload"]["type"] == "message")
            .map(|d| d["body"]["payload"]["seq"].as_u64().unwrap())
            .collect()
    };
    let message = henry.wait_message(&gid, 2).await;
    // Pushes for a device coalesce while queued: let seq 2 go out first.
    eventually("henry's push of seq 2", || async {
        message_seqs(&mock_deliveries(&mock, &henry_token).await).contains(&2)
    })
    .await;
    let (proposal, _) = alice_group
        .propose_self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let (status, result) = alice
        .submit_commit(&gid, commit_body("p1", &proposal))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["seq"], 3, "{result}");
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(&alice.provider, &alice.signer)
        .unwrap();
    let (status, result) = alice.submit_commit(&gid, commit_body("c2", &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["seq"], 4, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    assert_eq!(henry.wait_message(&gid, 3).await["kind"], "proposal");

    eventually("henry's push of seq 4", || async {
        message_seqs(&mock_deliveries(&mock, &henry_token).await).contains(&4)
    })
    .await;
    // Late pushes, if any, would arrive by now.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let deliveries = mock_deliveries(&mock, &henry_token).await;
    assert_eq!(message_seqs(&deliveries), [2, 4], "{deliveries:?}");

    let welcome = &deliveries[0]["body"];
    assert_eq!(welcome["payload"]["type"], "welcome", "{welcome}");
    assert_eq!(welcome["priority"], "high", "{welcome}");
    let pushed = deliveries
        .iter()
        .map(|d| &d["body"])
        .find(|body| body["payload"]["seq"] == 2)
        .unwrap();
    let delivery_id = pushed["delivery_id"].as_str().unwrap();
    assert!(
        delivery_id.len() == 32
            && delivery_id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "{pushed}"
    );
    assert_eq!(pushed["v"], 1, "{pushed}");
    assert_eq!(pushed["hub_id"], json!(hub_b_id), "{pushed}");
    assert_eq!(
        pushed["registration"],
        json!({ "provider": "mock-android", "token": henry_token }),
        "{pushed}"
    );
    assert_eq!(pushed["priority"], "high", "{pushed}");
    assert_eq!(pushed["ttl"], 86400, "{pushed}");
    assert!(pushed["sent_at"].as_u64().unwrap() > 0, "{pushed}");
    let payload = &pushed["payload"];
    assert_eq!(payload["v"], 1, "{pushed}");
    assert_eq!(payload["type"], "message", "{pushed}");
    assert_eq!(payload["gid"], json!(gid), "{pushed}");
    assert_eq!(payload["seq"], 2, "{pushed}");
    assert_eq!(payload["message_id"], message["message_id"], "{pushed}");
    assert_eq!(payload["collapse_id"], message["message_id"], "{pushed}");
    assert_eq!(pushed["collapse_id"], message["message_id"], "{pushed}");

    // ivan's registration is gone: seq 2 and 4 caused no further 410.
    assert_eq!(mock_counter(&mock, "gone").await, gone_before + 1);
    assert!(mock_deliveries(&mock, &ivan_token).await.is_empty());
    ok(
        "webhook push: one signed delivery per message, none for a Proposal, 410 deletes",
        start,
    );
}
