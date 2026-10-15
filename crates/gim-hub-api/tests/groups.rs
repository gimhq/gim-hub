//! Groups and Commits with real openmls clients.

mod mls_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use gim_hub_identity::HubId;
use openmls::prelude::{
    LeafNodeIndex, LeafNodeParameters, MlsMessageOut, OpenMlsProvider,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
};
use serde_json::{json, Value};

use mls_support::{code, encode, group_path, send, Client};

fn commit_body(client_id: &str, commit: &MlsMessageOut) -> Value {
    json!({ "client_id": client_id, "mls_message": encode(commit) })
}

fn member_ids(group: &Value) -> Vec<String> {
    group["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["device_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn create_assigns_hub_id_gid() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let (gid, _) = alice.create_group(&hub).await;

    let hub_id = HubId::from_root_pubkey(&hub.state.hub.signing_key().verifying_key());
    assert_eq!(&hub_id, hub.state.hub.hub_id());
    let (prefix, random) = gid.split_once('/').unwrap();
    assert_eq!(prefix, hub_id.as_str());
    assert_eq!(random.len(), 26);
    assert!(random
        .chars()
        .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));

    let (status, group) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(group["epoch"], 0);
    assert_eq!(group["last_seq"], 0);
    assert_eq!(group["kind"], "group");
    assert_eq!(member_ids(&group), ["da1"]);

    let (status, list) = send(&hub, Method::GET, "/v2/groups", &alice.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["groups"][0]["gid"], gid.as_str());
}

#[tokio::test]
async fn add_duplicate_stale_and_remove() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let bob = Client::new(&hub, "ubob", "db1").await;
    let (gid, mut group) = alice.create_group(&hub).await;
    bob.upload_key_packages(&hub, 1).await;

    // Add Bob with a Welcome.
    let kp = alice.claim(&hub, &bob).await;
    let (commit, welcome, _) = group
        .add_members(&alice.provider, &alice.signer, &[kp])
        .unwrap();
    let mut body = commit_body("c1", &commit);
    body["welcome"] = json!(encode(&welcome));
    body["welcome_recipients"] = json!([{ "user_id": "ubob", "device_id": "db1" }]);
    let (status, result) = alice.submit_commit(&hub, &gid, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 1, "epoch": 1, "duplicate": false }));
    group.merge_pending_commit(&alice.provider).unwrap();

    let (_, info) = send(&hub, Method::GET, &group_path(&gid), &bob.token, None).await;
    assert_eq!(info["epoch"], 1);
    assert_eq!(member_ids(&info), ["da1", "db1"]);

    let added = alice.events_of(&hub, "group.member_added").await;
    assert_eq!(
        added,
        [json!({
            "gid": gid, "user_id": "ubob", "device_ids": ["db1"],
            "by_user_id": "ualice", "by_device_id": "da1", "epoch": 1, "seq": 1,
        })]
    );
    assert_eq!(bob.events_of(&hub, "group.member_added").await, added);
    let welcomes = bob.events_of(&hub, "welcome").await;
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0]["seq"], 1);
    assert_eq!(welcomes[0]["epoch"], 1);
    assert_eq!(welcomes[0]["welcome"], body["welcome"]);
    // The Commit is not echoed to its sender, and new members join from the Welcome.
    assert!(alice.events_of(&hub, "message").await.is_empty());
    assert!(bob.events_of(&hub, "message").await.is_empty());
    let pending: i64 = hub
        .state
        .db
        .read(|conn| {
            conn.query_row(
                "SELECT count(*) FROM pending_welcomes WHERE user_id = 'ubob' AND device_id = 'db1'",
                [],
                |row| row.get(0),
            )
            .map_err(gim_hub_db::DbError::from)
        })
        .await
        .unwrap();
    assert_eq!(pending, 1);

    // Resubmitting the same Commit is idempotent.
    let (status, result) = alice.submit_commit(&hub, &gid, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result, json!({ "seq": 1, "epoch": 1, "duplicate": true }));
    assert_eq!(bob.events_of(&hub, "welcome").await.len(), 1);

    // Two competing Commits for epoch 1: the second one is stale.
    let first = group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    group
        .clear_pending_commit(alice.provider.storage())
        .unwrap();
    let second = group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    let (status, result) = alice
        .submit_commit(&hub, &gid, commit_body("c2", &second))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["epoch"], 2);
    group.merge_pending_commit(&alice.provider).unwrap();
    let (status, result) = alice
        .submit_commit(&hub, &gid, commit_body("c3", &first))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&result), "stale_epoch");
    assert_eq!(result["current_epoch"], 2);
    // Bob, a previous member, received the self-update Commit.
    let messages = bob.events_of(&hub, "message").await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["kind"], "commit");
    assert_eq!(messages[0]["seq"], 2);
    assert_eq!(messages[0]["epoch"], 1);

    // Remove Bob (leaf 1).
    let (commit, _, _) = group
        .remove_members(&alice.provider, &alice.signer, &[LeafNodeIndex::new(1)])
        .unwrap();
    let (status, result) = alice
        .submit_commit(&hub, &gid, commit_body("c4", &commit))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 3, "epoch": 3, "duplicate": false }));
    let removed = bob.events_of(&hub, "group.member_removed").await;
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["user_id"], "ubob");
    assert_eq!(removed[0]["device_ids"], json!(["db1"]));
    assert_eq!(alice.events_of(&hub, "group.member_removed").await, removed);
    assert_eq!(bob.events_of(&hub, "message").await.len(), 2);

    let (status, info) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(member_ids(&info), ["da1"]);
    let (status, body) = send(&hub, Method::GET, &group_path(&gid), &bob.token, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "not_member");
}

#[tokio::test]
async fn removed_leaf_is_reused_by_the_next_add() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let bob = Client::new(&hub, "ubob", "db1").await;
    let carol = Client::new(&hub, "ucarol", "dc1").await;
    let dave = Client::new(&hub, "udave", "dd1").await;
    let (gid, mut group) = alice.create_group(&hub).await;
    for client in [&bob, &carol, &dave] {
        client.upload_key_packages(&hub, 1).await;
    }

    let kps = vec![
        alice.claim(&hub, &bob).await,
        alice.claim(&hub, &carol).await,
    ];
    let (commit, _, _) = group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let (status, _) = alice
        .submit_commit(&hub, &gid, commit_body("c1", &commit))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    group.merge_pending_commit(&alice.provider).unwrap();

    // Remove Bob (leaf 1) and add Dave in one Commit: Dave takes leaf 1.
    let kp = alice.claim(&hub, &dave).await;
    let bundle = group
        .commit_builder()
        .propose_removals([LeafNodeIndex::new(1)])
        .propose_adds([kp])
        .load_psks(alice.provider.storage())
        .unwrap()
        .build(
            alice.provider.rand(),
            alice.provider.crypto(),
            &alice.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice.provider)
        .unwrap();
    let commit = bundle.into_commit();
    let (status, result) = alice
        .submit_commit(&hub, &gid, commit_body("c2", &commit))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    group.merge_pending_commit(&alice.provider).unwrap();

    let dave_leaf = group
        .members()
        .find(|m| m.credential.serialized_content().ends_with(b"udave/dd1"))
        .unwrap()
        .index;
    assert_eq!(dave_leaf, LeafNodeIndex::new(1));
    let leaves: Vec<(String, Option<u32>)> = hub
        .state
        .db
        .read(move |conn| gim_hub_db::groups::members(conn, &gid))
        .await
        .unwrap()
        .into_iter()
        .map(|m| (m.device_id, m.leaf_index))
        .collect();
    assert_eq!(
        leaves,
        [
            ("da1".to_owned(), Some(0)),
            ("dd1".to_owned(), Some(1)),
            ("dc1".to_owned(), Some(2)),
        ]
    );
}

#[tokio::test]
async fn private_message_commit_is_rejected() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let (gid, mut group) = alice
        .create_group_with(&hub, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .await;
    let commit = group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    let (status, body) = alice
        .submit_commit(&hub, &gid, commit_body("c1", &commit))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "validation_failed");
}

#[tokio::test]
async fn commit_for_another_group_is_rejected() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let (_, mut group) = alice.create_group(&hub).await;
    let (other_gid, _) = alice.create_group(&hub).await;
    let commit = group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    let (status, body) = alice
        .submit_commit(&hub, &other_gid, commit_body("c1", &commit))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), "validation_failed");
}

#[tokio::test]
async fn non_member_gets_403() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let mallory = Client::new(&hub, "umallory", "dm1").await;
    let (gid, mut group) = alice.create_group(&hub).await;

    let (status, body) = send(&hub, Method::GET, &group_path(&gid), &mallory.token, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "not_member");

    let commit = group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_commit();
    let (status, body) = mallory
        .submit_commit(&hub, &gid, commit_body("c1", &commit))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "not_member");

    let (_, list) = send(&hub, Method::GET, "/v2/groups", &mallory.token, None).await;
    assert_eq!(list["groups"], json!([]));

    let (status, body) = send(
        &hub,
        Method::GET,
        &group_path("hnope/none"),
        &alice.token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "not_found");
}

#[tokio::test]
async fn welcome_must_target_added_devices() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, "ualice", "da1").await;
    let bob = Client::new(&hub, "ubob", "db1").await;
    let (gid, mut group) = alice.create_group(&hub).await;
    bob.upload_key_packages(&hub, 1).await;
    let kp = alice.claim(&hub, &bob).await;
    let (commit, welcome, _) = group
        .add_members(&alice.provider, &alice.signer, &[kp])
        .unwrap();

    let mut body = commit_body("c1", &commit);
    body["welcome"] = json!(encode(&welcome));
    let (status, _) = alice.submit_commit(&hub, &gid, body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    body["welcome_recipients"] = json!([{ "user_id": "ualice", "device_id": "da1" }]);
    let (status, response) = alice.submit_commit(&hub, &gid, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "validation_failed");
    // Nothing was sequenced.
    let (_, info) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(info["epoch"], 0);
}
