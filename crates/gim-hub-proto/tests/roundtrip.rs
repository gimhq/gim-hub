//! Encode/decode round-trip of every S2S request and response variant.

use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as Res, ClaimKeyPackageRequest, ClaimKeyPackageResponse,
    ClaimedKeyPackage, DeliverRequest, DeliverResponse, DeliverWelcomeRequest,
    DeliverWelcomeResponse, Error, ErrorCode, FetchLogRequest, FetchLogResponse,
    GetDeviceListRequest, GetDeviceListResponse, GetHostingRecordRequest, GetHostingRecordResponse,
    GroupAck, GroupSnapshot, HelloRequest, HelloResponse, HubLocator, Member, MessageKind,
    NotifyDeviceListRequest, NotifyDeviceListResponse, S2sRequest, S2sResponse, SequencedMessage,
    SubmitCommitRequest, SubmitCommitResponse, SubmitMessageRequest, SubmitMessageResponse,
};
use gim_hub_proto::{HUB_RECORD_KEY_PREFIX, KAD_PROTOCOL, S2S_PROTOCOL, USER_RECORD_KEY_PREFIX};
use prost::Message;

const GID: &str =
    "hciqgrcknldyy6lbu2splf5frcdqeftipgfikjxbzeq6x6y55lggapay/abcdefghijklmnopqrstuvwxyz";

fn member(user: &str, device: &str) -> Member {
    Member {
        user_id: user.into(),
        device_id: device.into(),
    }
}

fn sequenced(seq: u64, kind: MessageKind) -> SequencedMessage {
    SequencedMessage {
        gid: GID.into(),
        seq,
        epoch: 3,
        kind: kind as i32,
        sender_user_id: "alice".into(),
        sender_device_id: "alice-d1".into(),
        client_id: format!("c-{seq}"),
        payload: vec![0xde, 0xad, seq as u8],
        message_id: format!("m-{seq}"),
        created_at: 1_792_000_000_000 + seq,
        affected_user_ids: vec!["bob".into()],
        added_members: vec![member("bob", "bob-d1")],
        removed_members: vec![member("carol", "carol-d1")],
    }
}

fn requests() -> Vec<Op> {
    vec![
        Op::SubmitCommit(SubmitCommitRequest {
            gid: GID.into(),
            sender_user_id: "alice".into(),
            sender_device_id: "alice-d1".into(),
            client_id: "c-1".into(),
            mls_message: vec![1, 2, 3],
            welcome: Some(vec![4, 5]),
            welcome_recipient_device_ids: vec!["bob-d1".into(), "bob-d2".into()],
            ratchet_tree: Some(vec![6]),
        }),
        Op::SubmitMessage(SubmitMessageRequest {
            gid: GID.into(),
            sender_user_id: "alice".into(),
            sender_device_id: "alice-d1".into(),
            client_id: "c-2".into(),
            mls_message: vec![7, 8],
        }),
        Op::Deliver(DeliverRequest {
            messages: vec![
                sequenced(1, MessageKind::Commit),
                sequenced(2, MessageKind::Application),
                sequenced(3, MessageKind::Proposal),
                sequenced(4, MessageKind::MemberAdded),
                sequenced(5, MessageKind::MemberRemoved),
            ],
        }),
        Op::DeliverWelcome(DeliverWelcomeRequest {
            gid: GID.into(),
            sender_user_id: "alice".into(),
            recipient_user_id: "bob".into(),
            recipient_device_ids: vec!["bob-d1".into()],
            welcome: vec![9, 9],
            ratchet_tree: None,
            message_id: "w-1".into(),
            group: Some(GroupSnapshot {
                kind: "group".into(),
                created_by_user_id: "alice".into(),
                created_by_device_id: "alice-d1".into(),
                created_at: 1_792_000_000_000,
                epoch: 2,
                seq: 7,
                members: vec![member("alice", "alice-d1"), member("bob", "bob-d1")],
            }),
            sender_device_id: "alice-d1".into(),
        }),
        Op::ClaimKeyPackage(ClaimKeyPackageRequest {
            requester_user_id: "alice".into(),
            target_user_id: "bob".into(),
            device_id: Some("bob-d1".into()),
        }),
        Op::FetchLog(FetchLogRequest {
            gid: GID.into(),
            from_seq: 10,
            limit: 100,
        }),
        Op::GetDeviceList(GetDeviceListRequest {
            user_id: "bob".into(),
        }),
        Op::GetHostingRecord(GetHostingRecordRequest {
            user_id: "bob".into(),
        }),
        Op::Hello(HelloRequest {
            runtime_cert: vec![0x82, 0x41, 0x01, 0x40],
            listen_addrs: vec![vec![4, 127, 0, 0, 1, 6, 0x0f, 0xa1]],
        }),
        Op::NotifyDeviceList(NotifyDeviceListRequest {
            user_id: "bob".into(),
            device_list_cbor: vec![0x82, 0x40, 0x40],
        }),
    ]
}

fn results() -> Vec<Res> {
    vec![
        Res::SubmitCommit(SubmitCommitResponse {
            seq: 11,
            epoch: 4,
            duplicate: true,
            message: Some(sequenced(11, MessageKind::Commit)),
        }),
        Res::SubmitMessage(SubmitMessageResponse {
            seq: 12,
            epoch: 4,
            duplicate: false,
            message: Some(sequenced(12, MessageKind::Application)),
        }),
        Res::Deliver(DeliverResponse {
            acks: vec![GroupAck {
                gid: GID.into(),
                highest_contiguous_seq: 5,
            }],
        }),
        Res::DeliverWelcome(DeliverWelcomeResponse {}),
        Res::ClaimKeyPackage(ClaimKeyPackageResponse {
            key_packages: vec![
                ClaimedKeyPackage {
                    device_id: "bob-d1".into(),
                    key_package: vec![1; 32],
                    last_resort: false,
                },
                ClaimedKeyPackage {
                    device_id: "bob-d2".into(),
                    key_package: vec![2; 32],
                    last_resort: true,
                },
            ],
        }),
        Res::FetchLog(FetchLogResponse {
            messages: vec![sequenced(10, MessageKind::Application)],
            next_seq: 11,
            complete: true,
        }),
        Res::GetDeviceList(GetDeviceListResponse {
            device_list_cbor: vec![0x82, 0x40, 0x40],
        }),
        Res::GetHostingRecord(GetHostingRecordResponse {
            hosting_record_cbor: vec![0x82, 0x41, 0x00, 0x40],
        }),
        Res::Hello(HelloResponse {
            runtime_cert: vec![0x82, 0x41, 0x02, 0x40],
            listen_addrs: vec![],
        }),
        Res::NotifyDeviceList(NotifyDeviceListResponse {}),
    ]
}

fn roundtrip<M: Message + Default + PartialEq + std::fmt::Debug>(msg: &M) {
    let bytes = msg.encode_to_vec();
    let decoded = M::decode(bytes.as_slice()).expect("decode");
    assert_eq!(&decoded, msg);
}

#[test]
fn every_request_variant_roundtrips() {
    let ops = requests();
    assert_eq!(ops.len(), 10);
    for (i, op) in ops.into_iter().enumerate() {
        roundtrip(&S2sRequest {
            request_id: format!("r-{i}"),
            op: Some(op),
        });
    }
}

#[test]
fn every_response_variant_roundtrips() {
    let results = results();
    assert_eq!(results.len(), 10);
    for (i, result) in results.into_iter().enumerate() {
        roundtrip(&S2sResponse {
            request_id: format!("r-{i}"),
            result: Some(result),
            error: None,
        });
    }
}

#[test]
fn every_error_code_roundtrips() {
    let codes = [
        ErrorCode::Unspecified,
        ErrorCode::Unauthorized,
        ErrorCode::NotFound,
        ErrorCode::StaleEpoch,
        ErrorCode::Conflict,
        ErrorCode::Gone,
        ErrorCode::RateLimited,
        ErrorCode::Invalid,
        ErrorCode::Internal,
        ErrorCode::HelloRequired,
    ];
    for code in codes {
        let resp = S2sResponse {
            request_id: "r-err".into(),
            result: None,
            error: Some(Error {
                code: code as i32,
                message: format!("{code:?}"),
                current_epoch: (code == ErrorCode::StaleEpoch).then_some(7),
                client_code: if code == ErrorCode::Unauthorized {
                    "not_member".into()
                } else {
                    String::new()
                },
            }),
        };
        let bytes = resp.encode_to_vec();
        let decoded = S2sResponse::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded, resp);
        assert_eq!(decoded.error.unwrap().code(), code);
    }
}

#[test]
fn optional_fields_absent_roundtrip() {
    roundtrip(&S2sRequest {
        request_id: String::new(),
        op: Some(Op::SubmitCommit(SubmitCommitRequest {
            gid: GID.into(),
            welcome: None,
            ratchet_tree: None,
            ..Default::default()
        })),
    });
    roundtrip(&S2sRequest {
        request_id: String::new(),
        op: Some(Op::ClaimKeyPackage(ClaimKeyPackageRequest {
            target_user_id: "bob".into(),
            device_id: None,
            ..Default::default()
        })),
    });
}

#[test]
fn protocol_ids() {
    assert_eq!(S2S_PROTOCOL, "/gim/s2s/1.0.0");
    assert_eq!(KAD_PROTOCOL, "/gim/kad/1.0.0");
    assert_eq!(USER_RECORD_KEY_PREFIX, "/gim/user/");
    assert_eq!(HUB_RECORD_KEY_PREFIX, "/gim/hub/");
}

#[test]
fn hub_locator_roundtrips() {
    roundtrip(&HubLocator {
        runtime_cert: vec![0x82, 0x41, 0x01, 0x40],
        multiaddrs: vec![vec![4, 127, 0, 0, 1, 6, 0x0f, 0xa1], vec![]],
    });
}

#[test]
fn hello_and_notify_use_field_numbers_40_and_41() {
    // Field 40, wire type 2 (length-delimited): tag varint 0xc2 0x02.
    let hello = S2sRequest {
        request_id: String::new(),
        op: Some(Op::Hello(HelloRequest::default())),
    };
    assert_eq!(hello.encode_to_vec(), [0xc2, 0x02, 0x00]);
    let notify = S2sResponse {
        request_id: String::new(),
        result: Some(Res::NotifyDeviceList(NotifyDeviceListResponse {})),
        error: None,
    };
    assert_eq!(notify.encode_to_vec(), [0xca, 0x02, 0x00]);
    assert_eq!(ErrorCode::HelloRequired as i32, 9);
}
