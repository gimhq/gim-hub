//! `FetchLog` (docs/federation.md §6.6, §7.6): a member hub reads a range of
//! a group's log from the owning hub to fill a gap in its replica.

use std::collections::BTreeSet;

use gim_hub_db::{groups, hosting as hosting_store, messages, DbError};
use gim_hub_identity::HubId;
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, ErrorCode, FetchLogRequest,
    FetchLogResponse, S2sRequest,
};

use super::{caller_listed, deliver::sequenced_message, internal, GroupService};
use crate::federation::{error, Federation, OpResult};

/// Most messages in one `FetchLog` page (§9.1 change 6).
pub const MAX_LIMIT: u32 = 256;

/// Sends `FetchLog{gid, from_seq, limit}` to the owning hub `owner`.
pub async fn fetch(
    federation: &dyn Federation,
    owner: &HubId,
    gid: &str,
    from_seq: u64,
    limit: u32,
) -> Result<FetchLogResponse, String> {
    let request = S2sRequest {
        request_id: super::request_id(),
        op: Some(Op::FetchLog(FetchLogRequest {
            gid: gid.to_owned(),
            from_seq,
            limit,
        })),
    };
    let response = federation
        .send(owner, request)
        .await
        .map_err(|err| err.to_string())?;
    match (response.result, response.error) {
        (_, Some(err)) => Err(format!("{:?}: {}", err.code(), err.message)),
        (Some(OpOutput::FetchLog(response)), None) => Ok(response),
        _ => Err("unexpected response".into()),
    }
}

/// `FetchLog` on the owning hub (§3.7): the caller must be listed for a
/// current member, or for a member removed by a Commit at or after
/// `from_seq`. Pages hold at most [`MAX_LIMIT`] messages.
pub(super) async fn handle(
    service: &GroupService,
    caller: &HubId,
    request: FetchLogRequest,
) -> OpResult {
    if !service.owns(&request.gid) {
        return Err(error(
            ErrorCode::Unauthorized,
            "this hub does not own the group",
        ));
    }
    let from_seq = i64::try_from(request.from_seq.max(1))
        .map_err(|_| error(ErrorCode::Invalid, "from_seq out of range"))?;
    let gid = request.gid.clone();
    let caller_id = caller.as_str().to_owned();
    let (exists, users, listed) = service
        .db
        .read(move |conn| {
            if groups::get(conn, &gid)?.is_none() {
                return Ok::<_, DbError>((false, Vec::new(), false));
            }
            let mut users: BTreeSet<String> = groups::member_devices(conn, &gid)?
                .into_iter()
                .map(|(user_id, _)| user_id)
                .collect();
            users.extend(messages::removed_since(conn, &gid, from_seq)?);
            let mut listed = false;
            for user_id in &users {
                if let Some(record) = hosting_store::get(conn, user_id)? {
                    listed |= record.hub_ids.contains(&caller_id);
                }
            }
            Ok((true, users.into_iter().collect(), listed))
        })
        .await
        .map_err(|err| internal(&err))?;
    if !exists {
        return Err(error(ErrorCode::NotFound, "unknown group"));
    }
    if !listed {
        // The cached records do not list the caller: refresh them (§3.7).
        let mut found = false;
        for user_id in &users {
            if caller_listed(&service.hosting, user_id, caller).await? {
                found = true;
                break;
            }
        }
        if !found {
            return Err(error(
                ErrorCode::Unauthorized,
                "caller is not listed for a member of the group",
            ));
        }
    }

    let limit = match request.limit {
        0 => MAX_LIMIT,
        limit => limit.min(MAX_LIMIT),
    };
    let gid = request.gid;
    let response = service
        .db
        .read(move |conn| {
            let last_seq = groups::get(conn, &gid)?.map_or(0, |group| group.last_seq);
            let mut page = Vec::new();
            for stored in messages::list_from(conn, &gid, from_seq, limit)? {
                page.extend(sequenced_message(conn, &gid, stored.seq)?);
            }
            let next_seq = page
                .last()
                .map_or(u64::try_from(from_seq).unwrap_or(1), |message| {
                    message.seq + 1
                });
            Ok::<_, DbError>(FetchLogResponse {
                complete: next_seq > last_seq,
                messages: page,
                next_seq,
            })
        })
        .await
        .map_err(|err| internal(&err))?;
    Ok(OpOutput::FetchLog(response))
}
