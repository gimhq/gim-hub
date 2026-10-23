//! Users and their self-certifying DeviceLists.

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::{HeaderMap, StatusCode, Uri},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_db::{
    events, groups, handles, hosting, remote_identity,
    users::{self, StoredDeviceList},
    Db, DbError, Transaction,
};
use gim_hub_identity::{verify_root_request, HubId, RootRequestHeaders, UserId};
use gim_hub_s2s::{outbox::NewEntry, BoxFuture, DeviceListEvents, FederationService, OutboxSender};

use crate::{
    auth::AuthDevice,
    dto::{DeviceList, Error, Me, PutDeviceListRequest, User},
    error::ApiError,
    notifier::Notifier,
    ratelimit::ClientIp,
    state::{AppState, Clock},
};

const DEVICE_LIST_UPDATED: &str = "device_list.updated";

/// The body of a JSON request; a body that is not acceptable JSON is 400
/// `validation_failed` (413 `payload_too_large` past the body limit).
pub(super) fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    match body {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(ApiError::PayloadTooLarge)
        }
        Err(rejection) => Err(ApiError::ValidationFailed(rejection.body_text())),
    }
}

/// Decodes a standard base64 field, `None` if it is not valid base64.
pub(super) fn decode_base64(value: &str) -> Option<Vec<u8>> {
    STANDARD.decode(value).ok()
}

fn device_list_dto(list: &StoredDeviceList) -> DeviceList {
    DeviceList {
        user_id: list.user_id.clone(),
        device_list: STANDARD.encode(&list.device_list),
    }
}

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Upload a signed DeviceList",
    description = "No authentication: the DeviceList is self-certifying. The hub verifies the root \
key signature and that the list's user ID matches `user_id` (derived from the root key). The first \
upload creates the user on this hub. A later upload with a higher `seq` replaces the stored list; \
re-uploading the identical list (same `seq`, same bytes) is idempotent and returns 200. The first \
upload of a user the hub's user policy (`GIM_HUB_USER_POLICY`) does not admit is refused with 403 \
`user_not_admitted`; later uploads of an existing user are not. Devices revoked by the new list lose their tokens; a `device_list.updated` event is emitted to \
the user's other active devices and to every active device of users sharing a group with them. \
With federation, a replaced list of a hosted user is pushed to the hubs sharing groups with the \
user, which emit `device_list.updated` to their users in those groups.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutDeviceListRequest,
    responses(
        (status = 200, description = "DeviceList replaced, or identical to the stored one", body = DeviceList),
        (status = 201, description = "User created with this DeviceList", body = DeviceList),
        (status = 400, description = "Malformed or invalid DeviceList, or user ID mismatch (`invalid_device_list`)", body = Error),
        (status = 403, description = "First upload (registration) of a user the hub's user policy does not admit: `{\"error\":{\"code\":\"user_not_admitted\",\"message\":\"user is not admitted on this hub\"}}`", body = Error),
        (status = 409, description = "`seq` is lower than the stored DeviceList, or equal with different bytes (`stale_device_list`)", body = Error),
        (status = 413, description = "Payload too large (`payload_too_large`)", body = Error),
    ),
)]
pub async fn put_device_list(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    body: Result<Json<PutDeviceListRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<DeviceList>), ApiError> {
    let body = json_body(body)?;
    let invalid =
        |err: gim_hub_identity::IdentityError| ApiError::InvalidDeviceList(err.to_string());
    let expected = UserId::parse(&user_id).map_err(invalid)?;
    let bytes = decode_base64(&body.device_list)
        .ok_or_else(|| ApiError::InvalidDeviceList("device_list is not valid base64".into()))?;
    let list = gim_hub_identity::DeviceList::verify(&bytes, &expected).map_err(invalid)?;
    let upload = Upload::prepare(&list, state.clock.now_ms())?;
    let response = upload.response.clone();
    let hub_id = state.hub.hub_id().clone();
    let outbox = state.outbox.clone();
    let admitted = state.user_policy.admitted(expected.as_str());
    let applied = state
        .db
        .write(move |tx| {
            // Registration is refused for a user the policy does not admit.
            if !admitted && users::get_device_list(tx, &upload.stored.user_id)?.is_none() {
                return Err(ApiError::UserNotAdmitted);
            }
            upload.apply(tx, Some((&hub_id, outbox.as_ref())))
        })
        .await?;
    let status = match applied {
        Applied::Created => StatusCode::CREATED,
        Applied::Replaced { .. } | Applied::Unchanged => StatusCode::OK,
    };
    applied.wake(&state.notifier, &response.user_id);
    Ok((status, Json(response)))
}

/// A verified DeviceList ready to be stored as a local user's list.
struct Upload {
    stored: StoredDeviceList,
    /// `(device_id, device_sig_pubkey)` of the list's active devices.
    active: Vec<(String, Vec<u8>)>,
    response: DeviceList,
    /// `device_list.updated` event payload.
    payload: String,
}

impl Upload {
    fn prepare(list: &gim_hub_identity::DeviceList, now: i64) -> Result<Self, ApiError> {
        let seq = i64::try_from(list.seq())
            .map_err(|_| ApiError::InvalidDeviceList("seq is out of range".into()))?;
        let stored = StoredDeviceList {
            user_id: list.user_id().to_string(),
            root_pubkey: list.root_pubkey().as_bytes().to_vec(),
            device_list: list.as_bytes().to_vec(),
            seq,
            updated_at: now,
        };
        let active = list
            .certs()
            .iter()
            .map(|cert| {
                (
                    cert.device_id().to_string(),
                    cert.device_sig_pubkey().as_bytes().to_vec(),
                )
            })
            .collect();
        let response = device_list_dto(&stored);
        let payload =
            serde_json::to_string(&response).map_err(|err| ApiError::Internal(err.to_string()))?;
        Ok(Self {
            stored,
            active,
            response,
            payload,
        })
    }

    /// Stores the list with the seq rules. On replacement, notifies the
    /// user's devices and their local group peers and, with `propagate` and
    /// a hosted user, queues `NotifyDeviceList` to the peer hubs (§5.1).
    fn apply(
        self,
        tx: &Transaction<'_>,
        propagate: Option<(&HubId, &dyn OutboxSender)>,
    ) -> Result<Applied, ApiError> {
        let Self {
            stored,
            active,
            payload,
            ..
        } = self;
        // Ordering per the identity spec ("Ordering and updates"); the
        // stored list was verified when it was stored.
        if let Some(current) = users::get_device_list(tx, &stored.user_id)? {
            if stored.seq < current.seq
                || (stored.seq == current.seq && stored.device_list != current.device_list)
            {
                return Err(ApiError::StaleDeviceList);
            }
            if stored.seq == current.seq {
                return Ok(Applied::Unchanged);
            }
        }
        let created = users::put_device_list(tx, &stored)?;
        let revoked = users::set_active_devices(tx, &stored.user_id, &active, stored.updated_at)?;
        if created {
            return Ok(Applied::Created);
        }
        // The user's devices and their group peers, who must re-verify
        // the user's MLS credentials against the new list.
        let mut notify: Vec<(String, String)> = users::active_device_ids(tx, &stored.user_id)?
            .into_iter()
            .map(|device_id| (stored.user_id.clone(), device_id))
            .collect();
        notify.extend(groups::peer_devices(tx, &stored.user_id)?);
        for (user_id, device_id) in &notify {
            events::append(
                tx,
                user_id,
                device_id,
                DEVICE_LIST_UPDATED,
                &payload,
                stored.updated_at,
            )?;
        }
        if let Some((hub_id, outbox)) = propagate {
            queue_device_list(tx, hub_id, outbox, &stored.user_id)?;
        }
        Ok(Applied::Replaced { notify, revoked })
    }
}

/// Queues one `NotifyDeviceList` per peer hub of hosted user `user_id`.
fn queue_device_list(
    tx: &Transaction<'_>,
    hub_id: &HubId,
    outbox: &dyn OutboxSender,
    user_id: &str,
) -> Result<(), DbError> {
    if !hosting::get(tx, user_id)?.is_some_and(|record| record.hosted) {
        return Ok(());
    }
    for peer in remote_identity::device_list_peer_hubs(tx, user_id, hub_id.as_str())? {
        match HubId::parse(&peer) {
            Ok(peer) => outbox.enqueue_in_tx(tx, &peer, NewEntry::DeviceList { user_id })?,
            Err(err) => tracing::warn!(%peer, %err, "skipping an invalid peer hub_id"),
        }
    }
    Ok(())
}

/// What a DeviceList upload did.
enum Applied {
    Created,
    /// `notify`: `(user_id, device_id)` of the devices to notify of the
    /// update; `revoked`: the user's devices deactivated by it, woken so
    /// their open streams re-check the session.
    Replaced {
        notify: Vec<(String, String)>,
        revoked: Vec<String>,
    },
    Unchanged,
}

impl Applied {
    fn wake(&self, notifier: &Notifier, user_id: &str) {
        if let Self::Replaced { notify, revoked } = self {
            for (user_id, device_id) in notify {
                notifier.notify(user_id, device_id);
            }
            for device_id in revoked {
                notifier.notify(user_id, device_id);
            }
        }
    }
}

/// DeviceList effects for [`gim_hub_s2s::DeviceLists`]: events for remote
/// users' list updates and the local upload path for pushed lists.
pub(crate) struct IdentityEvents {
    db: Db,
    clock: Clock,
    notifier: Notifier,
}

impl IdentityEvents {
    pub(crate) fn new(db: Db, clock: Clock, notifier: Notifier) -> Self {
        Self {
            db,
            clock,
            notifier,
        }
    }
}

impl DeviceListEvents for IdentityEvents {
    fn replaced(
        &self,
        tx: &Transaction<'_>,
        user_id: &str,
        device_list: &[u8],
        now: i64,
    ) -> Result<Vec<(String, String)>, DbError> {
        let payload = serde_json::to_string(&DeviceList {
            user_id: user_id.to_owned(),
            device_list: STANDARD.encode(device_list),
        })
        .expect("DeviceList serializes");
        let notify = groups::peer_devices(tx, user_id)?;
        for (peer, device_id) in &notify {
            events::append(tx, peer, device_id, DEVICE_LIST_UPDATED, &payload, now)?;
        }
        Ok(notify)
    }

    fn wake(&self, devices: &[(String, String)]) {
        for (user_id, device_id) in devices {
            self.notifier.notify(user_id, device_id);
        }
    }

    fn apply_local(
        &self,
        list: gim_hub_identity::DeviceList,
    ) -> BoxFuture<'_, Result<(), DbError>> {
        Box::pin(async move {
            let upload = match Upload::prepare(&list, self.clock.now_ms()) {
                Ok(upload) => upload,
                Err(err) => return Err(DbError::Task(err.to_string())),
            };
            let user_id = upload.stored.user_id.clone();
            // Pushed by another hub of the user: that hub propagates it.
            let applied = self
                .db
                .write(move |tx| match upload.apply(tx, None) {
                    Err(ApiError::StaleDeviceList) => Ok(Applied::Unchanged),
                    Err(ApiError::Internal(err)) => Err(DbError::Task(err)),
                    Err(err) => Err(DbError::Task(err.to_string())),
                    Ok(applied) => Ok(applied),
                })
                .await?;
            applied.wake(&self.notifier, &user_id);
            Ok(())
        })
    }
}

/// Registers the `GetDeviceList` and `NotifyDeviceList` op handlers.
pub fn register_device_list_ops(state: &AppState, service: &FederationService) {
    state.device_lists.register(service);
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Get a user's DeviceList",
    description = "No authentication (a bearer token, if sent, is ignored): the DeviceList is \
self-certifying public data, and a device restoring from a recovery code reads it before it can \
sign in. Rate limited per client IP and per `user_id`, shared with `GET /v2/users/{user_id}`. \
For a user of another hub, the hub answers from its cache of remote \
DeviceLists, fetching the list from the user's hub when it is not cached or older than \
`GIM_HUB_DEVICE_LIST_CACHE_HOURS`. A stale cached copy is returned if the user's hub cannot be \
reached.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    responses(
        (status = 200, description = "Current DeviceList", body = DeviceList),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 429, description = "Over the per-client-IP or per-user limit of unauthenticated reads (`rate_limited`); retry after `Retry-After` seconds", body = Error),
        (status = 503, description = "The user's hub is unreachable and no cached copy exists (`peer_unavailable`); retry after `Retry-After` seconds", body = Error),
    ),
)]
pub async fn get_device_list(
    client: ClientIp,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<DeviceList>, ApiError> {
    state
        .public_reads
        .check(client, &user_id, state.clock.now_ms())?;
    let device_list = state.device_lists.device_list_for(&user_id).await?;
    Ok(Json(DeviceList {
        user_id,
        device_list: STANDARD.encode(device_list),
    }))
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}",
    tag = "identity",
    summary = "Get a user",
    description = "No authentication (a bearer token, if sent, is ignored); returns only public \
data: the self-certifying DeviceList and the handle. Rate limited per client IP and per \
`user_id`, shared with `GET /v2/users/{user_id}/device-list`. For a user of another hub, the \
DeviceList comes from the cache of remote \
DeviceLists (fetched from the user's hub when missing or stale) and `handle` is absent.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    responses(
        (status = 200, description = "User", body = User),
        (status = 404, description = "Not found (`not_found`)", body = Error),
        (status = 429, description = "Over the per-client-IP or per-user limit of unauthenticated reads (`rate_limited`); retry after `Retry-After` seconds", body = Error),
        (status = 503, description = "The user's hub is unreachable and no cached copy exists (`peer_unavailable`); retry after `Retry-After` seconds", body = Error),
    ),
)]
pub async fn get_user(
    client: ClientIp,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<User>, ApiError> {
    state
        .public_reads
        .check(client, &user_id, state.clock.now_ms())?;
    let device_list = state.device_lists.device_list_for(&user_id).await?;
    let key = user_id.clone();
    let handle = state
        .db
        .read(move |conn| handles::handle_of(conn, &key))
        .await?;
    Ok(Json(User {
        user_id,
        device_list: STANDARD.encode(device_list),
        handle,
    }))
}

#[utoipa::path(
    delete,
    path = "/v2/users/{user_id}",
    tag = "identity",
    summary = "Delete an account",
    description = "Deletes a local user's account: its DeviceList and devices, handle, recovery \
backup, sessions, KeyPackages, push registration, hosting record, queued events and pending \
Welcomes. Group rosters and messages stay; the client leaves its groups first. Authenticated by \
a request signed with the user's root key (gim-core `docs/identity.md`, \"Root-signed \
requests\"): headers `Gim-Key`, `Gim-Timestamp`, `Gim-Signature`, over the method, this path and \
the (empty) body, within 5 minutes of the hub clock. No bearer token is needed, so an account \
can be deleted after its devices were revoked.",
    params(
        ("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa"),
        ("Gim-Key" = String, Header, description = "Root public key, unpadded base64url"),
        ("Gim-Timestamp" = String, Header, description = "Unix milliseconds, decimal"),
        ("Gim-Signature" = String, Header, description = "Root-key signature, unpadded base64url"),
    ),
    responses(
        (status = 204, description = "Account deleted"),
        (status = 401, description = "Missing, malformed, expired or wrong signature (`invalid_signature`)", body = Error),
        (status = 403, description = "The key is not `user_id`'s root key (`forbidden`)", body = Error),
        (status = 404, description = "No such local user (`not_found`)", body = Error),
    ),
)]
pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::InvalidSignature)
    };
    let path = uri
        .path_and_query()
        .map_or_else(|| uri.path(), |pq| pq.as_str());
    let signer = verify_root_request(
        "DELETE",
        path,
        b"",
        RootRequestHeaders {
            key: header("gim-key")?,
            timestamp: header("gim-timestamp")?,
            signature: header("gim-signature")?,
        },
        u64::try_from(state.clock.now_ms()).unwrap_or_default(),
    )
    .map_err(|_| ApiError::InvalidSignature)?;
    if signer.as_str() != user_id {
        return Err(ApiError::Forbidden(
            "the signing key is not this user's root key".into(),
        ));
    }
    if !state
        .db
        .write(move |tx| users::delete_user(tx, &user_id))
        .await?
    {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/v2/me",
    tag = "identity",
    summary = "Get the calling user and device",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Calling device", body = Me),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_me(auth: AuthDevice, State(state): State<AppState>) -> Result<Json<Me>, ApiError> {
    let user_id = auth.user_id.clone();
    let handle = state
        .db
        .read(move |conn| handles::handle_of(conn, &user_id))
        .await?;
    Ok(Json(Me {
        user_id: auth.user_id,
        device_id: auth.device_id,
        handle,
    }))
}
