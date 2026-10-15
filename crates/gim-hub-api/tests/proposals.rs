//! MLS Proposals on `POST /v2/groups/{gid}/commits` and Commits that cover
//! them by reference, with real openmls clients on one hub.

mod mls_support;

use axum::http::{Method, StatusCode};
use gim_hub_api::testing::TestHub;
use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    CredentialWithKey, KeyPackage, LeafNodeIndex, LeafNodeParameters, MlsGroup, MlsGroupJoinConfig,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, NewSignerBundle, OpenMlsProvider,
    ProcessedMessageContent, StagedWelcome, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use mls_support::{
    b64, code, device_list, encode, gim_credential, group_path, put_device_list, send, signer,
    unb64, Client,
};

fn body(client_id: &str, message: &MlsMessageOut) -> Value {
    json!({ "client_id": client_id, "mls_message": encode(message) })
}

fn member_ids(group: &Value) -> Vec<String> {
    group["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["device_id"].as_str().unwrap().to_owned())
        .collect()
}

/// Joins the MLS group from a `welcome` event.
fn join(client: &Client, welcome: &Value) -> MlsGroup {
    let message = MlsMessageIn::tls_deserialize_exact(unb64(&welcome["welcome"])).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    StagedWelcome::new_from_welcome(&client.provider, &config, welcome, None)
        .unwrap()
        .into_group(&client.provider)
        .unwrap()
}

/// Processes a `message` event: stores a Proposal as pending, merges a
/// Commit.
fn process(client: &Client, group: &mut MlsGroup, event: &Value) {
    let message = MlsMessageIn::tls_deserialize_exact(unb64(&event["mls_message"])).unwrap();
    let processed = group
        .process_message(
            &client.provider,
            message.try_into_protocol_message().unwrap(),
        )
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(proposal) => group
            .store_pending_proposal(client.provider.storage(), *proposal)
            .unwrap(),
        ProcessedMessageContent::StagedCommitMessage(staged) => group
            .merge_staged_commit(&client.provider, *staged)
            .unwrap(),
        _ => panic!("unexpected message"),
    }
}

/// The `message` event of `client` with `seq`.
async fn message_event(hub: &TestHub, client: &Client, seq: u64) -> Option<Value> {
    client
        .events_of(hub, "message")
        .await
        .into_iter()
        .find(|event| event["seq"] == seq)
}

async fn group_info(hub: &TestHub, client: &Client, gid: &str) -> Value {
    let (status, info) = send(hub, Method::GET, &group_path(gid), &client.token, None).await;
    assert_eq!(status, StatusCode::OK, "{info}");
    info
}

/// The MLS message with its framing epoch replaced (the hub does not verify
/// signatures, so this stands for a Commit created in another epoch).
fn with_epoch(message: &MlsMessageOut, epoch: u64) -> Vec<u8> {
    let mut bytes = message.tls_serialize_detached().unwrap();
    // version u16, wire_format u16, group_id<V> (QUIC varint length), epoch.
    let prefix = 1usize << (bytes[4] >> 6);
    let mut length = usize::from(bytes[4] & 0x3f);
    for byte in &bytes[5..4 + prefix] {
        length = (length << 8) | usize::from(*byte);
    }
    let at = 4 + prefix + length;
    bytes[at..at + 8].copy_from_slice(&epoch.to_be_bytes());
    bytes
}

/// Whether the hub resolves `proposal_ref` for `gid` in `epoch`.
async fn pending(hub: &TestHub, gid: &str, epoch: i64, proposal_ref: &ProposalRef) -> bool {
    let (gid, proposal_ref) = (gid.to_owned(), proposal_ref.as_slice().to_vec());
    hub.state
        .db
        .read(move |conn| gim_hub_db::messages::pending_proposal(conn, &gid, epoch, &proposal_ref))
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn self_remove_proposal_then_commit_by_reference() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    let carol = Client::new(&hub, 3, 31).await;
    let (gid, mut alice_group) = alice.create_group(&hub).await;
    bob.upload_key_packages(&hub, 1).await;
    carol.upload_key_packages(&hub, 1).await;
    let kps = vec![
        alice.claim(&hub, &bob).await,
        alice.claim(&hub, &carol).await,
    ];
    let (commit, welcome, _) = alice_group
        .add_members(&alice.provider, &alice.signer, &kps)
        .unwrap();
    let mut add = body("c1", &commit);
    add["welcome"] = json!(encode(&welcome));
    add["welcome_recipients"] = json!([
        { "user_id": bob.user_id, "device_id": bob.device_id },
        { "user_id": carol.user_id, "device_id": carol.device_id },
    ]);
    let (status, result) = alice.submit_commit(&hub, &gid, add).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let mut bob_group = join(&bob, &bob.events_of(&hub, "welcome").await[0]);
    let mut carol_group = join(&carol, &carol.events_of(&hub, "welcome").await[0]);

    // Carol prepares a Proposal in epoch 1 and keeps it for later.
    let (carol_late, carol_late_ref) = carol_group
        .propose_remove_member(&carol.provider, &carol.signer, LeafNodeIndex::new(0))
        .unwrap();

    // Bob leaves with a self-Remove Proposal.
    let leave = bob_group.leave_group(&bob.provider, &bob.signer).unwrap();
    let (status, result) = bob.submit_commit(&hub, &gid, body("p1", &leave)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 2, "epoch": 1, "duplicate": false }));
    let (status, result) = bob.submit_commit(&hub, &gid, body("p1", &leave)).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result, json!({ "seq": 2, "epoch": 1, "duplicate": true }));

    // Fanned out as a `proposal` message; epoch and roster unchanged.
    for client in [&alice, &carol] {
        let event = message_event(&hub, client, 2).await.unwrap();
        assert_eq!(event["kind"], "proposal");
        assert_eq!(event["epoch"], 1);
        assert_eq!(event["sender_device_id"], bob.device_id.as_str());
    }
    assert!(message_event(&hub, &bob, 2).await.is_none());
    let info = group_info(&hub, &alice, &gid).await;
    assert_eq!(info["epoch"], 1);
    assert_eq!(info["last_seq"], 2);
    assert_eq!(member_ids(&info).len(), 3);
    assert!(alice
        .events_of(&hub, "group.member_removed")
        .await
        .is_empty());
    let (_, log) = send(
        &hub,
        Method::GET,
        &format!("{}/messages?from_seq=2", group_path(&gid)),
        &carol.token,
        None,
    )
    .await;
    assert_eq!(log["messages"][0]["kind"], "proposal");

    // A Commit referencing a Proposal the hub never sequenced (Carol's).
    let bob_leave = message_event(&hub, &carol, 2).await.unwrap();
    process(&carol, &mut carol_group, &bob_leave);
    let (unknown, _, _) = carol_group
        .commit_to_pending_proposals(&carol.provider, &carol.signer)
        .unwrap();
    carol_group
        .clear_pending_commit(carol.provider.storage())
        .unwrap();
    carol_group
        .clear_pending_proposals(carol.provider.storage())
        .unwrap();
    process(&carol, &mut carol_group, &bob_leave);
    let (status, result) = carol.submit_commit(&hub, &gid, body("u1", &unknown)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    assert_eq!(code(&result), "validation_failed");
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown proposal reference"));
    assert!(!pending(&hub, &gid, 1, &carol_late_ref).await);

    // Alice commits Bob's Proposal by reference.
    process(
        &alice,
        &mut alice_group,
        &message_event(&hub, &alice, 2).await.unwrap(),
    );
    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(&alice.provider, &alice.signer)
        .unwrap();
    let (status, result) = alice.submit_commit(&hub, &gid, body("c2", &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result, json!({ "seq": 3, "epoch": 2, "duplicate": false }));
    alice_group.merge_pending_commit(&alice.provider).unwrap();
    let info = group_info(&hub, &alice, &gid).await;
    assert_eq!(info["epoch"], 2);
    assert_eq!(
        member_ids(&info),
        [alice.device_id.as_str(), carol.device_id.as_str()]
    );
    for client in [&alice, &bob, &carol] {
        let removed = client.events_of(&hub, "group.member_removed").await;
        assert_eq!(removed.len(), 1, "{}", client.device_id);
        assert_eq!(removed[0]["user_id"], bob.user_id.as_str());
        assert_eq!(removed[0]["device_ids"], json!([bob.device_id]));
        assert_eq!(removed[0]["by_device_id"], alice.device_id.as_str());
        assert_eq!(removed[0]["epoch"], 2);
    }
    process(
        &carol,
        &mut carol_group,
        &message_event(&hub, &carol, 3).await.unwrap(),
    );
    assert_eq!(carol_group.epoch().as_u64(), 2);

    // Bob's Proposal from epoch 1 can no longer be referenced.
    let (status, result) = alice
        .submit_commit(
            &hub,
            &gid,
            json!({ "client_id": "c3", "mls_message": b64(&with_epoch(&commit, 2)) }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown proposal reference"));

    // A Proposal for the previous epoch is stale.
    let (status, result) = carol
        .submit_commit(&hub, &gid, body("p2", &carol_late))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{result}");
    assert_eq!(code(&result), "stale_epoch");
    assert_eq!(result["current_epoch"], 2);

    // Bob is no longer a member.
    let (update, _) = bob_group
        .propose_self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .unwrap();
    let (status, result) = bob.submit_commit(&hub, &gid, body("p3", &update)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{result}");
    assert_eq!(code(&result), "not_member");
}

#[tokio::test]
async fn proposal_sender_credentials_are_checked() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let _bob = Client::new(&hub, 2, 21).await;
    let (gid, mut group) = alice.create_group(&hub).await;

    // An Update with Bob's identity, and with another key for Alice.
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
        let (update, _) = group
            .propose_self_update_with_new_signer(
                &alice.provider,
                &alice.signer,
                NewSignerBundle {
                    signer: new_signer,
                    credential_with_key,
                },
                LeafNodeParameters::default(),
            )
            .unwrap();
        group
            .clear_pending_proposals(alice.provider.storage())
            .unwrap();
        let (status, result) = alice.submit_commit(&hub, &gid, body("p1", &update)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
        let message = result["error"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
    }

    // A plain Update is accepted; then Alice's device is revoked.
    let (update, _) = group
        .propose_self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let (status, result) = alice.submit_commit(&hub, &gid, body("p1", &update)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let (status, result) =
        put_device_list(&hub, &alice.user_id, &device_list(1, 2, &[12], &[11])).await;
    assert!(status.is_success(), "{result}");
    let (update, _) = group
        .propose_self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let (status, result) = alice.submit_commit(&hub, &gid, body("p2", &update)).await;
    // Revoking the device ends its sessions, as for Commits.
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{result}");
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
async fn add_by_reference_follows_the_key_package_ledger() {
    let hub = TestHub::new();
    let alice = Client::new(&hub, 1, 11).await;
    let bob = Client::new(&hub, 2, 21).await;
    let dave = Client::new(&hub, 4, 41).await;
    let mallory = Client::new(&hub, 5, 51).await;
    let (gid, mut group) = alice.create_group(&hub).await;

    // Mallory's KeyPackage stored as Bob's, and one of Dave's never claimed.
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
    let unclaimed = KeyPackage::builder()
        .leaf_node_capabilities(mls_support::capabilities(mls_support::GIM_CREDENTIAL))
        .build(
            mls_support::CIPHERSUITE,
            &dave.provider,
            &dave.signer,
            dave.credential.clone(),
        )
        .unwrap()
        .key_package()
        .clone();
    let cases = [
        (alice.claim(&hub, &bob).await, "identity_mismatch"),
        (unclaimed, "kp_not_claimed"),
    ];
    for (i, (kp, expected)) in cases.into_iter().enumerate() {
        let (proposal, proposal_ref) = group
            .propose_add_member(&alice.provider, &alice.signer, &kp)
            .unwrap();
        let (status, result) = alice
            .submit_commit(&hub, &gid, body(&format!("p{i}"), &proposal))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{result}");
        assert!(pending(&hub, &gid, 0, &proposal_ref).await);
        let (commit, _, _) = group
            .commit_to_pending_proposals(&alice.provider, &alice.signer)
            .unwrap();
        group
            .clear_pending_commit(alice.provider.storage())
            .unwrap();
        group
            .clear_pending_proposals(alice.provider.storage())
            .unwrap();
        let (status, result) = alice
            .submit_commit(&hub, &gid, body(&format!("c{i}"), &commit))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
        let message = result["error"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
    }

    // Dave's claimed KeyPackage, added by reference with a Welcome.
    dave.upload_key_packages(&hub, 1).await;
    let kp = alice.claim(&hub, &dave).await;
    let (proposal, proposal_ref) = group
        .propose_add_member(&alice.provider, &alice.signer, &kp)
        .unwrap();
    let (status, result) = alice.submit_commit(&hub, &gid, body("p9", &proposal)).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["epoch"], 0);
    assert!(pending(&hub, &gid, 0, &proposal_ref).await);
    let (commit, welcome, _) = group
        .commit_to_pending_proposals(&alice.provider, &alice.signer)
        .unwrap();
    let mut add = body("c9", &commit);
    add["welcome"] = json!(encode(&welcome.unwrap()));
    add["welcome_recipients"] = json!([{ "user_id": dave.user_id, "device_id": dave.device_id }]);
    let (status, result) = alice.submit_commit(&hub, &gid, add).await;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    assert_eq!(result["epoch"], 1);
    group.merge_pending_commit(&alice.provider).unwrap();
    let info = group_info(&hub, &dave, &gid).await;
    assert_eq!(
        member_ids(&info),
        [alice.device_id.as_str(), dave.device_id.as_str()]
    );
    assert_eq!(dave.events_of(&hub, "welcome").await.len(), 1);
    assert!(!pending(&hub, &gid, 0, &proposal_ref).await);

    // A Welcome with a Proposal is rejected.
    let (proposal, _) = group
        .propose_self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    let mut with_welcome = body("p10", &proposal);
    with_welcome["welcome"] = json!(b64(b"welcome"));
    with_welcome["welcome_recipients"] =
        json!([{ "user_id": dave.user_id, "device_id": dave.device_id }]);
    let (status, result) = alice.submit_commit(&hub, &gid, with_welcome).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{result}");
}
