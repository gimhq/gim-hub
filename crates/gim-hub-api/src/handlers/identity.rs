//! Users and their self-certifying DeviceLists.

use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use gim_hub_db::{
    events, handles,
    users::{self, StoredDeviceList},
};
use gim_hub_identity::UserId;

use crate::{
    auth::AuthDevice,
    dto::{DeviceList, Error, Me, PutDeviceListRequest, User},
    error::ApiError,
    state::AppState,
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

/// What a DeviceList upload did.
enum Upload {
    Created,
    Replaced { notify: Vec<String> },
    Unchanged,
}

#[utoipa::path(
    put,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Upload a signed DeviceList",
    description = "No authentication: the DeviceList is self-certifying. The hub verifies the root \
key signature and that the list's user ID matches `user_id` (derived from the root key). The first \
upload creates the user on this hub. A later upload with a higher `seq` replaces the stored list; \
re-uploading the identical list (same `seq`, same bytes) is idempotent and returns 200. Devices revoked by the new list lose their tokens; a `device_list.updated` event is emitted.",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    request_body = PutDeviceListRequest,
    responses(
        (status = 200, description = "DeviceList replaced, or identical to the stored one", body = DeviceList),
        (status = 201, description = "User created with this DeviceList", body = DeviceList),
        (status = 400, description = "Malformed or invalid DeviceList, or user ID mismatch (`invalid_device_list`)", body = Error),
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
    let seq = i64::try_from(list.seq())
        .map_err(|_| ApiError::InvalidDeviceList("seq is out of range".into()))?;
    let stored = StoredDeviceList {
        user_id: list.user_id().to_string(),
        root_pubkey: list.root_pubkey().as_bytes().to_vec(),
        device_list: list.as_bytes().to_vec(),
        seq,
        updated_at: state.clock.now_ms(),
    };
    let active: Vec<(String, Vec<u8>)> = list
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

    let upload = state
        .db
        .write(move |tx| {
            // Ordering per the identity spec ("Ordering and updates"); the
            // stored list was verified when it was stored.
            if let Some(current) = users::get_device_list(tx, &stored.user_id)? {
                if stored.seq < current.seq
                    || (stored.seq == current.seq && stored.device_list != current.device_list)
                {
                    return Err(ApiError::StaleDeviceList);
                }
                if stored.seq == current.seq {
                    return Ok(Upload::Unchanged);
                }
            }
            let created = users::put_device_list(tx, &stored)?;
            users::set_active_devices(tx, &stored.user_id, &active, stored.updated_at)?;
            if created {
                return Ok(Upload::Created);
            }
            let notify = users::active_device_ids(tx, &stored.user_id)?;
            for device_id in &notify {
                events::append(
                    tx,
                    &stored.user_id,
                    device_id,
                    DEVICE_LIST_UPDATED,
                    &payload,
                    stored.updated_at,
                )?;
            }
            Ok(Upload::Replaced { notify })
        })
        .await?;

    let status = match upload {
        Upload::Created => StatusCode::CREATED,
        Upload::Replaced { notify } => {
            for device_id in &notify {
                state.notifier.notify(&response.user_id, device_id);
            }
            StatusCode::OK
        }
        Upload::Unchanged => StatusCode::OK,
    };
    Ok((status, Json(response)))
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}/device-list",
    tag = "identity",
    summary = "Get a user's DeviceList",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Current DeviceList", body = DeviceList),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_device_list(
    _auth: AuthDevice,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<DeviceList>, ApiError> {
    let list = state
        .db
        .read(move |conn| users::get_device_list(conn, &user_id))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(device_list_dto(&list)))
}

#[utoipa::path(
    get,
    path = "/v2/users/{user_id}",
    tag = "identity",
    summary = "Get a user",
    params(("user_id" = String, Path, description = "Opaque user ID (format owned by gim-core)", example = "uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa")),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "User", body = User),
        (status = 401, description = "Missing or invalid bearer token (`unauthorized`)", body = Error),
        (status = 404, description = "Not found (`not_found`)", body = Error),
    ),
)]
pub async fn get_user(
    _auth: AuthDevice,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<User>, ApiError> {
    let (list, handle) = state
        .db
        .read(move |conn| {
            let Some(list) = users::get_device_list(conn, &user_id)? else {
                return Ok::<_, ApiError>((None, None));
            };
            Ok((Some(list), handles::handle_of(conn, &user_id)?))
        })
        .await?;
    let list = list.ok_or(ApiError::NotFound)?;
    let DeviceList {
        user_id,
        device_list,
    } = device_list_dto(&list);
    Ok(Json(User {
        user_id,
        device_list,
        handle,
    }))
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
