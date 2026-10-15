//! Groups and MLS Commits.

use axum::response::IntoResponse;

use super::not_implemented;
use crate::{
    auth::AuthDevice,
    dto::{
        CommitResult, CreateGroupRequest, Error, Group, GroupList, StaleEpochError,
        SubmitCommitRequest,
    },
};

#[utoipa::path(
    post,
    path = "/v2/groups",
    tag = "groups",
    summary = "Create a group",
    description = "Assigns a new `gid = <owner_peer_id>/<random_128 base32>` (this hub's PeerID) at \
epoch 0 with the calling device as the only member. Further members are added by Commits.",
    request_body = CreateGroupRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 201, description = "Group created", body = Group),
        (status = 400, description = "Validation failed (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn create_group(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/groups",
    tag = "groups",
    summary = "List groups the calling device is a member of",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Groups", body = GroupList),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn list_groups(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    get,
    path = "/v2/groups/{gid}",
    tag = "groups",
    summary = "Get a group",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Group", body = Group),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_group(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}

#[utoipa::path(
    post,
    path = "/v2/groups/{gid}/commits",
    tag = "groups",
    summary = "Submit an MLS Commit",
    description = "`mls_message` is an MLS PublicMessage (Commit or Proposal), so the hub can parse \
it. The hub reads the epoch from the MLS framing (there is no client epoch field) and \
accepts the Commit only for the group's current epoch, advancing it by one. Membership changes \
are derived from the Add/Remove/Update proposals; each added member's gim-core credential \
(type 0xF001) is validated against their DeviceList, members are identified by user ID + device \
ID from their credentials, and `group.member_added` / `group.member_removed` events carry the `user_id`. The \
optional Welcome is delivered as a `welcome` event to `welcome_recipients`.\n\n\
Resubmitting the same Commit (same hash) returns the original result with `duplicate: true` \
and emits nothing. Any other Commit for a past epoch fails with 409 `stale_epoch`.",
    params(("gid" = String, Path, description = "Group ID, percent-encoded (`/` as `%2F`)", example = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA%2Fhf4caruf7nbxzmwh5wvgefz6pa")),
    request_body = SubmitCommitRequest,
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Duplicate of an accepted Commit (`duplicate: true`)", body = CommitResult),
        (status = 201, description = "Commit accepted", body = CommitResult),
        (status = 400, description = "Not a PublicMessage Commit for this group, invalid credential of an added member, or Welcome fields inconsistent (`validation_failed`)", body = Error),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 403, description = "Caller is not a member of the group (`not_member`), or group policy forbids the change (`forbidden`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 409, description = "Commit epoch is not the group epoch (`stale_epoch`)", body = StaleEpochError),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn submit_commit(_auth: AuthDevice) -> impl IntoResponse {
    not_implemented()
}
