//! Cross-hub KeyPackage claims (docs/federation.md §5.2, §6.1): the
//! `ClaimKeyPackage` request a hub sends on behalf of its users, and the op
//! handler serving remote requesters.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use gim_hub_db::DbError;
use gim_hub_identity::{HubId, UserId};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, ClaimKeyPackageRequest,
    ClaimKeyPackageResponse, ClaimedKeyPackage, ErrorCode, S2sRequest,
};

use crate::{
    federation::{error, BoxFuture, Federation, FederationService, OpResult},
    hosting::{Hosting, HostingError, Now, Purpose},
    policy::OpKind,
};

/// Claims per `(caller, requester_user_id, target_user_id)` and minute
/// (§6.8, enforced here because the policy sees no request fields).
pub const CLAIMS_PER_TARGET_PER_MINUTE: u32 = 10;

const MINUTE_MS: i64 = 60_000;
/// Rate-limit windows kept before old ones are swept.
const MAX_WINDOWS: usize = 4096;

/// Local KeyPackage claims, owned by the client API.
pub trait LocalClaims: Send + Sync + 'static {
    /// Claims one KeyPackage per active device of local user
    /// `target_user_id` (or only `device_id`), exactly as for a local
    /// client (including `keypackages.low`). Empty if nothing was claimed.
    fn claim(
        &self,
        target_user_id: String,
        device_id: Option<String>,
    ) -> BoxFuture<'_, Result<Vec<ClaimedKeyPackage>, DbError>>;
}

/// Result of a claim sent to another hub (§6.1 failure mapping).
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimOutcome {
    Claimed(Vec<ClaimedKeyPackage>),
    /// `NOT_FOUND`: unknown user, no active device or no KeyPackage.
    Missing,
    /// The `unavailable` class: transport error, timeout, `INTERNAL`,
    /// `RATE_LIMITED`, `UNAUTHORIZED` (or `HELLO_REQUIRED`). Not retried on
    /// the same hub (claims are not idempotent); routing moves to the next
    /// listed hub (docs/multihoming.md §5.2).
    Unavailable(String),
    /// Any other error (e.g. `INVALID`): routing stops here.
    Rejected(String),
}

/// Sends `ClaimKeyPackage{requester, target, device_id}` to `hub`.
pub async fn claim_remote(
    federation: &dyn Federation,
    hub: &HubId,
    requester_user_id: &str,
    target_user_id: &str,
    device_id: Option<&str>,
) -> ClaimOutcome {
    let request = S2sRequest {
        request_id: super::request_id(),
        op: Some(Op::ClaimKeyPackage(ClaimKeyPackageRequest {
            requester_user_id: requester_user_id.to_owned(),
            target_user_id: target_user_id.to_owned(),
            device_id: device_id.map(str::to_owned),
        })),
    };
    match federation.send(hub, request).await {
        Err(err) => ClaimOutcome::Unavailable(err.to_string()),
        Ok(response) => match (response.result, response.error) {
            (Some(OpOutput::ClaimKeyPackage(response)), _) if response.key_packages.is_empty() => {
                ClaimOutcome::Missing
            }
            (Some(OpOutput::ClaimKeyPackage(response)), _) => {
                ClaimOutcome::Claimed(response.key_packages)
            }
            (_, Some(err)) => {
                let reason = format!("{:?}: {}", err.code(), err.message);
                match err.code() {
                    ErrorCode::NotFound => ClaimOutcome::Missing,
                    ErrorCode::Internal
                    | ErrorCode::RateLimited
                    | ErrorCode::Unauthorized
                    | ErrorCode::HelloRequired => ClaimOutcome::Unavailable(reason),
                    _ => ClaimOutcome::Rejected(reason),
                }
            }
            (_, None) => ClaimOutcome::Unavailable("unexpected response".into()),
        },
    }
}

/// `(caller, requester, target)` of a rate-limit window, which maps to
/// `(window start, claims in window)`.
type WindowKey = (String, String, String);

/// The `ClaimKeyPackage` op handler.
pub struct ClaimService {
    hosting: Hosting,
    local: Arc<dyn LocalClaims>,
    now: Now,
    windows: Mutex<HashMap<WindowKey, (i64, u32)>>,
}

impl ClaimService {
    pub fn new(hosting: Hosting, local: Arc<dyn LocalClaims>, now: Now) -> Arc<Self> {
        Arc::new(Self {
            hosting,
            local,
            now,
            windows: Mutex::default(),
        })
    }

    /// Registers the `ClaimKeyPackage` op handler on `service`.
    pub fn register(self: &Arc<Self>, service: &FederationService) {
        let weak = Arc::downgrade(self);
        service.register(
            OpKind::ClaimKeyPackage,
            Arc::new(
                move |caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                    let weak = weak.clone();
                    Box::pin(async move {
                        let Some(service) = weak.upgrade() else {
                            return Err(error(ErrorCode::Internal, "shutting down"));
                        };
                        service.handle(caller, op).await
                    })
                },
            ),
        );
    }

    /// Serves a claim from `caller` (§3.7): the caller is listed for the
    /// requester, this hub hosts the target, then the per-target rate limit.
    pub async fn handle(&self, caller: HubId, op: Op) -> OpResult {
        let Op::ClaimKeyPackage(request) = op else {
            return Err(error(ErrorCode::Invalid, "unexpected op"));
        };
        let requester = UserId::parse(&request.requester_user_id)
            .map_err(|_| error(ErrorCode::Invalid, "invalid requester_user_id"))?;
        let target = UserId::parse(&request.target_user_id)
            .map_err(|_| error(ErrorCode::Invalid, "invalid target_user_id"))?;
        match self
            .hosting
            .resolve_for(requester.as_str(), Purpose::Authorize(caller.clone()))
            .await
        {
            Ok(record) if record.entry(&caller).is_some() => {}
            Ok(_) | Err(HostingError::NotFound | HostingError::Required) => {
                return Err(error(
                    ErrorCode::Unauthorized,
                    "caller is not listed for the requester",
                ))
            }
            Err(HostingError::Unavailable(reason)) => {
                return Err(error(ErrorCode::Internal, &reason))
            }
            Err(HostingError::Db(err)) => return Err(internal(&err)),
        }
        match self.hosting.require_hosting_record(target.as_str()).await {
            Ok(_) => {}
            Err(HostingError::Db(err)) => return Err(internal(&err)),
            Err(_) => return Err(error(ErrorCode::NotFound, "target is not hosted here")),
        }
        if !self.admit(&caller, &requester, &target) {
            return Err(error(
                ErrorCode::RateLimited,
                "too many claims for this target",
            ));
        }
        let key_packages = self
            .local
            .claim(target.to_string(), request.device_id)
            .await
            .map_err(|err| internal(&err))?;
        if key_packages.is_empty() {
            return Err(error(ErrorCode::NotFound, "no KeyPackage"));
        }
        Ok(OpOutput::ClaimKeyPackage(ClaimKeyPackageResponse {
            key_packages,
        }))
    }

    /// Counts a claim against its fixed one-minute window.
    fn admit(&self, caller: &HubId, requester: &UserId, target: &UserId) -> bool {
        let now = (self.now)();
        let mut windows = self.windows.lock().expect("windows lock");
        if windows.len() >= MAX_WINDOWS {
            windows.retain(|_, (start, _)| now - *start < MINUTE_MS);
        }
        let key = (
            caller.to_string(),
            requester.to_string(),
            target.to_string(),
        );
        let (start, count) = windows.entry(key).or_insert((now, 0));
        if now - *start >= MINUTE_MS {
            (*start, *count) = (now, 0);
        }
        if *count >= CLAIMS_PER_TARGET_PER_MINUTE {
            return false;
        }
        *count += 1;
        true
    }
}

fn internal(err: &DbError) -> gim_hub_proto::s2s::Error {
    tracing::error!(%err, "ClaimKeyPackage failed");
    error(ErrorCode::Internal, "internal error")
}
