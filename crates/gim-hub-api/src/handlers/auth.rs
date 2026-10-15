//! Device sign-in by signature challenge.

use axum::{
    extract::{rejection::JsonRejection, State},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use gim_hub_db::{
    auth::{self as db_auth, Challenge},
    users,
};
use gim_hub_identity::{
    auth_response_user_id, verify_auth_response, DeviceId, DeviceList, IdentityError, UserId,
};
use sha2::{Digest, Sha256};

use crate::{
    auth::token_hash,
    dto::{AuthChallenge, AuthChallengeRequest, CreateSessionRequest, Error, Session},
    error::ApiError,
    state::AppState,
};

/// Lifetime of an issued challenge.
pub const CHALLENGE_TTL_MS: i64 = 5 * 60 * 1000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[utoipa::path(
    post,
    path = "/v2/auth/challenge",
    tag = "auth",
    summary = "Request a sign-in challenge",
    description = "Issues a single-use gim-core AuthChallenge (audience = this hub's `hub_id`, \
32-byte random nonce, valid for 5 minutes) for a device listed as active in the user's stored \
DeviceList. The device signs the challenge bytes into an AuthResponse and answers with \
POST /v2/auth/session before `expires_at`.",
    request_body = AuthChallengeRequest,
    responses(
        (status = 200, description = "Challenge issued", body = AuthChallenge),
        (status = 400, description = "Malformed body, user ID or device ID (`validation_failed`)", body = Error),
        (status = 404, description = "No DeviceList stored for the user, or the device is not active in it (`not_found`)", body = Error),
    ),
)]
pub async fn create_auth_challenge(
    State(state): State<AppState>,
    body: Result<Json<AuthChallengeRequest>, JsonRejection>,
) -> Result<Json<AuthChallenge>, ApiError> {
    let request = json_body(body)?;
    let user_id = UserId::parse(&request.user_id).map_err(invalid)?;
    let device_id = DeviceId::parse(&request.device_id).map_err(invalid)?;

    let nonce: [u8; 32] = random_bytes()?;
    let now = state.clock.now_ms();
    let expires_at = now + CHALLENGE_TTL_MS;
    let challenge = gim_hub_identity::AuthChallenge::new(
        state.hub.hub_id(),
        nonce,
        unix_ms(now),
        unix_ms(expires_at),
    )
    .to_bytes();
    let row = Challenge {
        challenge_id: challenge_id(&nonce),
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        challenge: challenge.clone(),
        expires_at,
    };
    state
        .db
        .write(move |tx| {
            if !db_auth::device_is_active(tx, &row.user_id, &row.device_id)? {
                return Err(ApiError::NotFound);
            }
            db_auth::insert_challenge(tx, &row, now)?;
            Ok(())
        })
        .await?;

    Ok(Json(AuthChallenge {
        challenge: STANDARD.encode(&challenge),
        expires_at,
        hub_id: state.hub.hub_id().to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/v2/auth/session",
    tag = "auth",
    summary = "Answer a challenge and obtain a device token",
    description = "Verifies the gim-core AuthResponse against the user's stored DeviceList and \
this hub's `hub_id`, then consumes the challenge: its nonce must have been issued by this hub \
for the same user and device, be unexpired and unused. The device must still be active (not \
revoked). The token is revoked when a later DeviceList revokes the device.",
    request_body = CreateSessionRequest,
    responses(
        (status = 200, description = "Session created", body = Session),
        (status = 400, description = "Malformed body or AuthResponse (`validation_failed`)", body = Error),
        (status = 401, description = "Unknown, used or expired challenge, or one issued by another hub or for another device (`invalid_challenge`); bad signature (`invalid_signature`); device revoked or not in the DeviceList (`device_not_active`)", body = Error),
    ),
)]
pub async fn create_session(
    State(state): State<AppState>,
    body: Result<Json<CreateSessionRequest>, JsonRejection>,
) -> Result<Json<Session>, ApiError> {
    let request = json_body(body)?;
    let response = STANDARD
        .decode(&request.response)
        .map_err(|_| ApiError::ValidationFailed("response is not valid base64".into()))?;
    let user_id = auth_response_user_id(&response).map_err(invalid)?;

    let token = URL_SAFE_NO_PAD.encode(random_bytes::<32>()?);
    let hash = token_hash(&token);
    let now = state.clock.now_ms();
    let expires_at = now + i64::from(state.config.session_ttl_days) * DAY_MS;
    let hub_id = state.hub.hub_id().clone();
    state
        .db
        .write(move |tx| {
            // Without a stored DeviceList no challenge can have been issued.
            let stored =
                users::get_device_list(tx, user_id.as_str())?.ok_or(ApiError::InvalidChallenge)?;
            let list = DeviceList::verify(&stored.device_list, &user_id).map_err(|err| {
                ApiError::Internal(format!("stored DeviceList of {user_id}: {err}"))
            })?;
            let device = verify_auth_response(&response, &hub_id, unix_ms(now), &list)
                .map_err(response_error)?;
            let challenge = db_auth::take_challenge(tx, &challenge_id(&device.nonce), now)?
                .filter(|issued| {
                    issued.user_id == device.user_id.as_str()
                        && issued.device_id == device.device_id.as_str()
                })
                .ok_or(ApiError::InvalidChallenge)?;
            db_auth::create_session(
                tx,
                &hash,
                &db_auth::Session {
                    user_id: challenge.user_id,
                    device_id: challenge.device_id,
                    expires_at,
                },
                now,
            )?;
            Ok::<_, ApiError>(())
        })
        .await?;

    Ok(Json(Session { token, expires_at }))
}

/// The JSON body, or 400 `validation_failed`.
fn json_body<T>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    body.map(|Json(value)| value)
        .map_err(|err| ApiError::ValidationFailed(err.body_text()))
}

fn invalid(err: IdentityError) -> ApiError {
    ApiError::ValidationFailed(err.to_string())
}

fn response_error(err: IdentityError) -> ApiError {
    match err {
        IdentityError::AudienceMismatch | IdentityError::Expired => ApiError::InvalidChallenge,
        IdentityError::Revoked(_) | IdentityError::UnknownDevice(_) => ApiError::DeviceNotActive,
        IdentityError::BadSignature => ApiError::InvalidSignature,
        other => invalid(other),
    }
}

/// Key of an issued challenge: hex SHA-256 of its nonce.
fn challenge_id(nonce: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(nonce))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(bytes)
}

/// Clock milliseconds as the unsigned time of the identity formats.
fn unix_ms(ms: i64) -> u64 {
    u64::try_from(ms).unwrap_or_default()
}
