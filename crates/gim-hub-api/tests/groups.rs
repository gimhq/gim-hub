//! Groups and Commits with real openmls clients.

mod mls_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use gim_hub_identity::HubId;
use openmls::prelude::{
    tls_codec::Serialize, CredentialWithKey, KeyPackage, LeafNodeIndex, LeafNodeParameters,
    MlsMessageOut, NewSignerBundle, OpenMlsProvider, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mls_support::{b64, code, encode, gim_credential, group_path, send, signer, Client};

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
    let alice = Client::new(&hub, 1, 11).await;
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
    assert_eq!(member_ids(&group), [alice.device_id.as_str()]);

    let (status, list) = send(&hub, Method::GET, "/v2/groups", &alice.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["groups"][0]["gid"], gid.as_str());
}

#[tokio::test]
async fn add_duplicate_stale_and_remove() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    let (gid, mut group) = alice.create_group(&hub).await;
    bob.upload_key_packages(&hub, 1).await;

    // Add Bob with a Welcome.
    let kp = alice.claim(&hub, &bob).await;
    let (commit, welcome, _) = group
        .add_members(&alice.provider, &alice.signer, &[kp])
        .unwrap();
    let mut body = commit_body("c1", &commit);
    body["welcome"] = json!(encode(&welcome));
    body["welcome_recipients"] = json!([{ "user_id": bob.user_id, "device_id": bob.device_id }]);
    let (status, result) = alice.submit_commit(&hub, &gid, body.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 1, "epoch": 1, "duplicate": false }));
    group.merge_pending_commit(&alice.provider).unwrap();

    let (_, info) = send(&hub, Method::GET, &group_path(&gid), &bob.token, None).await;
    assert_eq!(info["epoch"], 1);
    assert_eq!(
        member_ids(&info),
        [alice.device_id.as_str(), bob.device_id.as_str()]
    );

    let added = alice.events_of(&hub, "group.member_added").await;
    assert_eq!(
        added,
        [json!({
            "gid": gid, "user_id": bob.user_id, "device_ids": [bob.device_id],
            "by_user_id": alice.user_id, "by_device_id": alice.device_id, "epoch": 1, "seq": 1,
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
    let (bob_user, bob_device) = (bob.user_id.clone(), bob.device_id.clone());
    let pending: i64 = hub
        .state
        .db
        .read(move |conn| {
            conn.query_row(
                "SELECT count(*) FROM pending_welcomes WHERE user_id = ?1 AND device_id = ?2",
                [bob_user, bob_device],
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
    assert_eq!(removed[0]["user_id"], bob.user_id.as_str());
    assert_eq!(removed[0]["device_ids"], json!([bob.device_id]));
    assert_eq!(alice.events_of(&hub, "group.member_removed").await, removed);
    assert_eq!(bob.events_of(&hub, "message").await.len(), 2);

    let (status, info) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(member_ids(&info), [alice.device_id.as_str()]);
    let (status, body) = send(&hub, Method::GET, &group_path(&gid), &bob.token, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), "not_member");
}

#[tokio::test]
async fn removed_leaf_is_reused_by_the_next_add() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    let carol = Client::new(&hub, 3, 31).await;
    let dave = Client::new(&hub, 4, 41).await;
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
        .find(|m| m.credential == dave.credential.credential)
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
            (alice.device_id.clone(), Some(0)),
            (dave.device_id.clone(), Some(1)),
            (carol.device_id.clone(), Some(2)),
        ]
    );
}

#[tokio::test]
async fn private_message_commit_is_rejected() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
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
    let alice = Client::new(&hub, 1, 11).await;
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
    let alice = Client::new(&hub, 1, 11).await;
    let mallory = Client::new(&hub, 5, 51).await;
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
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
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

    body["welcome_recipients"] =
        json!([{ "user_id": alice.user_id, "device_id": alice.device_id }]);
    let (status, response) = alice.submit_commit(&hub, &gid, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&response), "validation_failed");
    // Nothing was sequenced.
    let (_, info) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(info["epoch"], 0);
}

#[tokio::test]
async fn welcome_must_be_an_mls_message_carrying_a_welcome() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    let (gid, mut group) = alice.create_group(&hub).await;
    bob.upload_key_packages(&hub, 1).await;
    let kp = alice.claim(&hub, &bob).await;
    let (commit, welcome, _) = group
        .add_members(&alice.provider, &alice.signer, &[kp])
        .unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    let commit_bytes = commit.tls_serialize_detached().unwrap();

    let mut body = commit_body("c1", &commit);
    body["welcome_recipients"] = json!([{ "user_id": bob.user_id, "device_id": bob.device_id }]);
    for bad in [
        // A bare Welcome: the MLSMessage without version and wire_format.
        welcome[4..].to_vec(),
        // MLSMessages of other wire formats: a PublicMessage, a KeyPackage.
        commit_bytes,
        [&welcome[..2], &[0, 5], bob.key_package().as_slice()].concat(),
        // Trailing bytes, garbage.
        [welcome.as_slice(), &[0]].concat(),
        b"welcome".to_vec(),
    ] {
        body["welcome"] = json!(b64(&bad));
        let (status, response) = alice.submit_commit(&hub, &gid, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(code(&response), "validation_failed");
        assert_eq!(
            response["error"]["message"],
            "welcome is not an MLSMessage carrying a Welcome"
        );
    }
    // Nothing was sequenced or delivered.
    let (_, info) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(info["epoch"], 0);
    assert!(bob.events_of(&hub, "welcome").await.is_empty());

    body["welcome"] = json!(b64(&welcome));
    let (status, response) = alice.submit_commit(&hub, &gid, body).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
}

/// Stores `key_package` as a one-time KeyPackage of `owner`, bypassing the
/// upload checks.
async fn plant_key_package(hub: &TestHub, owner: &Client, key_package: &KeyPackage) {
    let bytes = key_package.tls_serialize_detached().unwrap();
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    let (user_id, device_id) = (owner.user_id.clone(), owner.device_id.clone());
    hub.state
        .db
        .write(move |tx| {
            gim_hub_db::keypackages::insert_one_time(tx, &user_id, &device_id, &bytes, &hash, 0)
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn add_must_match_the_claimed_key_package_owner() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    let mallory = Client::new(&hub, 5, 51).await;
    // A user without a DeviceList on this hub.
    let nolist = Client::signed_in(&hub, 6, 61).await;
    let (gid, mut group) = alice.create_group(&hub).await;

    // Mallory's KeyPackage stored as Bob's: the credential names Mallory.
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(mls_support::capabilities(mls_support::GIM_CREDENTIAL))
        .build(
            mls_support::CIPHERSUITE,
            &mallory.provider,
            &mallory.signer,
            mallory.credential.clone(),
        )
        .unwrap();
    plant_key_package(&hub, &bob, kp.key_package()).await;
    // The no-list user's own KeyPackage, stored without the upload check.
    let kp = KeyPackage::builder()
        .leaf_node_capabilities(mls_support::capabilities(mls_support::GIM_CREDENTIAL))
        .build(
            mls_support::CIPHERSUITE,
            &nolist.provider,
            &nolist.signer,
            nolist.credential.clone(),
        )
        .unwrap();
    plant_key_package(&hub, &nolist, kp.key_package()).await;

    for (target, expected) in [
        (&bob, "identity_mismatch"),
        (&nolist, "device_list_unknown"),
    ] {
        let kp = alice.claim(&hub, target).await;
        let (commit, _, _) = group
            .add_members(&alice.provider, &alice.signer, &[kp])
            .unwrap();
        group
            .clear_pending_commit(alice.provider.storage())
            .unwrap();
        let (status, body) = alice
            .submit_commit(&hub, &gid, commit_body("c1", &commit))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(code(&body), "validation_failed");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
    }
    let (_, info) = send(&hub, Method::GET, &group_path(&gid), &alice.token, None).await;
    assert_eq!(info["epoch"], 0);
}

#[tokio::test]
async fn committer_cannot_change_identity() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let _bob = Client::new(&hub, 2, 21).await;
    let (gid, mut group) = alice.create_group(&hub).await;

    // Bob's credential and key, and Alice's credential with another key.
    let bob_signer = signer(21);
    let other_signer = signer(12);
    let cases = [
        (
            &bob_signer,
            CredentialWithKey {
                credential: gim_credential(2, 21),
                signature_key: bob_signer.public().into(),
            },
            "identity_mismatch",
        ),
        (
            &other_signer,
            CredentialWithKey {
                credential: gim_credential(1, 11),
                signature_key: other_signer.public().into(),
            },
            "leaf_key_mismatch",
        ),
    ];
    for (new_signer, credential_with_key, expected) in cases {
        let commit = group
            .self_update_with_new_signer(
                &alice.provider,
                &alice.signer,
                NewSignerBundle {
                    signer: new_signer,
                    credential_with_key,
                },
                LeafNodeParameters::default(),
            )
            .unwrap()
            .into_commit();
        group
            .clear_pending_commit(alice.provider.storage())
            .unwrap();
        let (status, body) = alice
            .submit_commit(&hub, &gid, commit_body("c1", &commit))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
    }

    // A plain self-update keeps the identity.
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
    assert_eq!(status, StatusCode::CREATED, "{body}");
}
