//! `DeliverWelcome` (docs/federation.md §5.4, §6.2, §6.6): the owning hub
//! hands a Welcome and the group snapshot to the hub of an added member.
//! `CopyPendingWelcomes` (docs/multihoming.md §4.4): a co-host hands a
//! user's pending Welcomes to a hub newly listed for the user.

use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_response::Result as OpOutput, CopyPendingWelcomesRequest, CopyPendingWelcomesResponse,
    DeliverWelcomeRequest, DeliverWelcomeResponse, ErrorCode,
};

use super::{internal, owner_of, GroupService};
use crate::{
    federation::{error, OpResult},
    hosting::HostingError,
};

/// `DeliverWelcome` on the recipient's hub (§3.7): the caller owns the gid
/// and this hub hosts the recipient.
pub(super) async fn handle(
    service: &GroupService,
    caller: &HubId,
    request: DeliverWelcomeRequest,
) -> OpResult {
    if owner_of(&request.gid) != Some(caller.as_str()) {
        return Err(error(
            ErrorCode::Unauthorized,
            "caller does not own the group",
        ));
    }
    if request.group.is_none() {
        return Err(error(ErrorCode::Invalid, "missing group snapshot"));
    }
    match service
        .hosting
        .require_hosting_record(&request.recipient_user_id)
        .await
    {
        Ok(_) => {}
        Err(HostingError::Db(err)) => return Err(internal(&err)),
        Err(_) => return Err(error(ErrorCode::NotFound, "recipient is not hosted here")),
    }
    service
        .groups
        .deliver_welcome(request)
        .await
        .map_err(|err| internal(&err))?;
    Ok(OpOutput::DeliverWelcome(DeliverWelcomeResponse {}))
}

/// `CopyPendingWelcomes` on the added hub (multihoming.md §9.1): this hub
/// hosts the user and its stored record lists the caller.
pub(super) async fn handle_copy(
    service: &GroupService,
    caller: &HubId,
    request: CopyPendingWelcomesRequest,
) -> OpResult {
    let record = match service
        .hosting
        .require_hosting_record(&request.user_id)
        .await
    {
        Ok(record) => record,
        Err(HostingError::Db(err)) => return Err(internal(&err)),
        Err(_) => return Err(error(ErrorCode::NotFound, "user is not hosted here")),
    };
    if record.entry(caller).is_none() {
        return Err(error(
            ErrorCode::Unauthorized,
            "caller is not listed for the user",
        ));
    }
    service
        .groups
        .copy_pending_welcomes(request)
        .await
        .map_err(|err| internal(&err))?;
    Ok(OpOutput::CopyPendingWelcomes(
        CopyPendingWelcomesResponse {},
    ))
}
