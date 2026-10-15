//! `SubmitCommit` / `SubmitMessage` (docs/federation.md §6.3, §6.5): a
//! member hub forwards its users' Commits and application messages to the
//! owning hub, which sequences them.

use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, Error as S2sError, ErrorCode, S2sRequest,
    SubmitCommitRequest, SubmitCommitResponse, SubmitMessageRequest, SubmitMessageResponse,
};

use super::{caller_listed, GroupService};
use crate::{
    federation::{error, Federation, OpResult},
    transport::SendError,
};

/// Why a submit to the owning hub failed.
#[derive(Debug, Clone, PartialEq)]
pub enum SubmitError {
    /// The owning hub answered with an error.
    Rejected(S2sError),
    /// Local policy forbids the owner, or the owner refused this hub.
    Refused(String),
    /// The owner could not be reached or did not answer in time.
    Unavailable(String),
    /// Federation is disabled.
    Disabled,
}

impl From<SendError> for SubmitError {
    fn from(err: SendError) -> Self {
        match err {
            SendError::Disabled => Self::Disabled,
            SendError::PeerRefused(reason) => Self::Refused(reason),
            other => Self::Unavailable(other.to_string()),
        }
    }
}

/// Sends `SubmitCommit` to the owning hub `owner`.
pub async fn submit_commit(
    federation: &dyn Federation,
    owner: &HubId,
    request: SubmitCommitRequest,
) -> Result<SubmitCommitResponse, SubmitError> {
    match send(federation, owner, Op::SubmitCommit(request)).await? {
        OpOutput::SubmitCommit(response) => Ok(response),
        _ => Err(SubmitError::Unavailable("unexpected response".into())),
    }
}

/// Sends `SubmitMessage` to the owning hub `owner`.
pub async fn submit_message(
    federation: &dyn Federation,
    owner: &HubId,
    request: SubmitMessageRequest,
) -> Result<SubmitMessageResponse, SubmitError> {
    match send(federation, owner, Op::SubmitMessage(request)).await? {
        OpOutput::SubmitMessage(response) => Ok(response),
        _ => Err(SubmitError::Unavailable("unexpected response".into())),
    }
}

async fn send(federation: &dyn Federation, owner: &HubId, op: Op) -> Result<OpOutput, SubmitError> {
    let request = S2sRequest {
        request_id: super::request_id(),
        op: Some(op),
    };
    let response = federation.send(owner, request).await?;
    match (response.result, response.error) {
        (_, Some(err)) => Err(SubmitError::Rejected(err)),
        (Some(output), None) => Ok(output),
        (None, None) => Err(SubmitError::Unavailable("empty response".into())),
    }
}

/// `SubmitCommit` on the owning hub (§3.7): this hub owns the gid and the
/// caller is listed for the sender; roster membership is checked when
/// sequencing.
pub(super) async fn handle_commit(
    service: &GroupService,
    caller: &HubId,
    request: SubmitCommitRequest,
) -> OpResult {
    authorize(service, caller, &request.gid, &request.sender_user_id).await?;
    let response = service.groups.submit_commit(request).await?;
    Ok(OpOutput::SubmitCommit(response))
}

/// `SubmitMessage` on the owning hub, authorized like `SubmitCommit`.
pub(super) async fn handle_message(
    service: &GroupService,
    caller: &HubId,
    request: SubmitMessageRequest,
) -> OpResult {
    authorize(service, caller, &request.gid, &request.sender_user_id).await?;
    let response = service.groups.submit_message(request).await?;
    Ok(OpOutput::SubmitMessage(response))
}

async fn authorize(
    service: &GroupService,
    caller: &HubId,
    gid: &str,
    sender_user_id: &str,
) -> Result<(), S2sError> {
    if !service.owns(gid) {
        return Err(error(ErrorCode::Invalid, "this hub does not own the group"));
    }
    if !caller_listed(&service.hosting, sender_user_id, caller).await? {
        return Err(error(
            ErrorCode::Unauthorized,
            "caller is not listed for the sender",
        ));
    }
    Ok(())
}
