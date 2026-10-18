//! The user policy on the client API (docs/operations.md, "User policy"):
//! registration (the first DeviceList upload) of a user the policy does not
//! admit is refused in `allow` and `deny` mode; admitted users and later
//! uploads of existing users are unaffected. Sign-in and session cleanup
//! are covered with the admin API (gim-hub-admin tests/actions.rs).

mod identity_support;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use gim_hub_api::{testing::TestHub, user_policy::Mode};
use serde_json::json;

use identity_support::{device_list, put_device_list, user_id};

const NOT_ADMITTED: &str = "user is not admitted on this hub";

#[tokio::test]
async fn registration_is_refused_for_users_not_admitted() {
    for mode in [Mode::Allow, Mode::Deny] {
        let hub = TestHub::new();
        // User 1 is admitted in both modes, user 2 in neither; user 3
        // registered before the policy.
        let (admitted, refused) = (user_id(1), user_id(2));
        let (status, _) = put_device_list(&hub, &user_id(3), &device_list(3, 1, &[30], &[])).await;
        assert_eq!(status, StatusCode::CREATED);
        let listed = match mode {
            Mode::Allow => [admitted.clone()],
            _ => [refused.clone()],
        };
        hub.state
            .user_policy
            .set(mode, BTreeSet::from(listed.clone()));

        let (status, body) = put_device_list(&hub, &refused, &device_list(2, 1, &[20], &[])).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{mode}");
        assert_eq!(
            body,
            json!({ "error": { "code": "user_not_admitted", "message": NOT_ADMITTED } })
        );
        let stored = hub
            .state
            .db
            .read(move |conn| gim_hub_db::users::get_device_list(conn, &refused))
            .await
            .unwrap();
        assert!(stored.is_none(), "nothing stored");

        let (status, body) = put_device_list(&hub, &admitted, &device_list(1, 1, &[10], &[])).await;
        assert_eq!(status, StatusCode::CREATED, "{mode}: {body}");

        // An existing user not admitted can still replace its DeviceList
        // (it cannot sign in).
        if mode == Mode::Allow {
            let (status, body) =
                put_device_list(&hub, &user_id(3), &device_list(3, 2, &[30, 31], &[])).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
    }
}

#[tokio::test]
async fn open_mode_admits_everyone() {
    let hub = TestHub::new();
    hub.state
        .user_policy
        .set(Mode::Open, BTreeSet::from([user_id(2)]));
    let (status, _) = put_device_list(&hub, &user_id(2), &device_list(2, 1, &[20], &[])).await;
    assert_eq!(status, StatusCode::CREATED);
}
