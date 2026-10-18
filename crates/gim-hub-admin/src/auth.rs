//! Admin authentication: the session cookie, CSRF, the login throttle and
//! trusted-proxy identity (docs/admin.md, "Security model").

use std::net::{IpAddr, SocketAddr};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use gim_hub_api::dto::Error;

use crate::{
    config::constant_time_eq,
    dto::{LoginRequest, LoginResponse, SessionResponse},
    error::AdminError,
    state::{AdminState, Audit, AuthKind, Session, SESSION_TTL_MS},
};

/// Name of the session cookie.
pub const COOKIE_NAME: &str = "gim_admin_session";
/// Header carrying the session's CSRF token on non-GET requests.
pub const CSRF_HEADER: &str = "x-csrf-token";
pub(crate) const LOGIN_PATH: &str = "/admin/api/login";
pub(crate) const SESSION_PATH: &str = "/admin/api/session";
/// Actor of audit entries written before a session exists.
const ANONYMOUS: &str = "anonymous";

/// The caller of an admin API request, set by [`require_session`].
#[derive(Debug, Clone)]
pub struct Caller {
    pub source_ip: IpAddr,
    /// The cookie value and its session; `None` only on POST /login.
    pub session: Option<(String, Session)>,
}

impl Caller {
    /// The session's actor.
    pub fn actor(&self) -> &str {
        self.session
            .as_ref()
            .map_or(ANONYMOUS, |(_, session)| session.actor.as_str())
    }

    /// Writes an audit entry for `action` on `target` with the outcome of
    /// `result`: its error message, or `detail` on success.
    pub(crate) async fn audit<T>(
        &self,
        state: &AdminState,
        action: &'static str,
        target: Option<String>,
        result: &Result<T, AdminError>,
        detail: Option<String>,
    ) {
        state
            .audit(Audit {
                actor: self.actor(),
                action,
                target,
                source_ip: self.source_ip,
                ok: result.is_ok(),
                detail: match result {
                    Ok(_) => detail,
                    Err(err) => Some(err.to_string()),
                },
            })
            .await;
    }
}

/// Middleware of every /admin/api route: resolves the source IP and
/// requires an unexpired session (401 `unauthorized`) and, on every non-GET
/// request, `X-CSRF-Token` equal to the session's token (403
/// `csrf_failed`). POST /admin/api/login is exempt. GET /admin/api/session
/// from a trusted proxy carrying the trusted header creates a session.
pub(crate) async fn require_session(
    State(state): State<AdminState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let headers = request.headers();
    let source_ip = state.source_ip(peer, headers);
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if method == Method::POST && path == LOGIN_PATH {
        request.extensions_mut().insert(Caller {
            source_ip,
            session: None,
        });
        return next.run(request).await;
    }

    let mut session = session_cookie(headers)
        .and_then(|cookie| state.session(&cookie).map(|session| (cookie, session)));
    let mut created = None;
    if session.is_none() && method == Method::GET && path == SESSION_PATH {
        if let Some(actor) = state.header_identity(peer, headers) {
            let (cookie, new) = match state.create_session(actor, AuthKind::Header) {
                Ok(pair) => pair,
                Err(err) => return err.into_response(),
            };
            state
                .audit(Audit {
                    actor: &new.actor,
                    action: "login_ok",
                    target: None,
                    source_ip,
                    ok: true,
                    detail: Some("trusted header".into()),
                })
                .await;
            created = Some(cookie.clone());
            session = Some((cookie, new));
        }
    }
    let Some((cookie, session)) = session else {
        return AdminError::Unauthorized.into_response();
    };
    if !matches!(method, Method::GET | Method::HEAD) {
        let sent = headers
            .get(CSRF_HEADER)
            .map(HeaderValue::as_bytes)
            .unwrap_or_default();
        if !constant_time_eq(sent, session.csrf_token.as_bytes()) {
            return AdminError::CsrfFailed.into_response();
        }
    }
    request.extensions_mut().insert(Caller {
        source_ip,
        session: Some((cookie, session)),
    });
    let mut response = next.run(request).await;
    if let Some(cookie) = created {
        if let Ok(value) =
            HeaderValue::from_str(&set_cookie(&state, &cookie, SESSION_TTL_MS / 1000))
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

/// The `gim_admin_session` cookie value, if sent.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, value)| value.to_owned())
}

fn set_cookie(state: &AdminState, value: &str, max_age: i64) -> String {
    let secure = if state.config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age={max_age}{secure}"
    )
}

/// Milliseconds as the admin API's Unix seconds.
pub(crate) fn seconds(ms: i64) -> i64 {
    ms.div_euclid(1000)
}

#[utoipa::path(
    post,
    path = "/admin/api/login",
    tag = "auth",
    summary = "Log in with the admin token",
    description = "Compares the token with `GIM_HUB_ADMIN_TOKEN` or `GIM_HUB_ADMIN_TOKEN_FILE` in \
constant time and sets the `gim_admin_session` cookie (HttpOnly, SameSite=Strict, Path=/admin, 8 h absolute). At most 5 \
failed logins per source IP and minute. Audited as `login_ok` or `login_failed` (never the token).",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Logged in; `Set-Cookie: gim_admin_session=...`", body = LoginResponse),
        (status = 400, description = "Malformed body (`validation_failed`)", body = Error),
        (status = 401, description = "Wrong token (`unauthorized`)", body = Error),
        (status = 403, description = "Token login is disabled (`forbidden`)", body = Error),
        (status = 429, description = "Too many failed logins from this IP (`rate_limited`)", body = Error),
    ),
)]
pub async fn login(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Response {
    let failed = |detail: &str| Audit {
        actor: ANONYMOUS,
        action: "login_failed",
        target: None,
        source_ip: caller.source_ip,
        ok: false,
        detail: Some(detail.to_owned()),
    };
    if !state.config.token_login() {
        state.audit(failed("token login disabled")).await;
        return AdminError::Forbidden("token login is disabled".into()).into_response();
    }
    if let Err(retry_after) = state.login_allowed(caller.source_ip) {
        state.audit(failed("rate limited")).await;
        return AdminError::RateLimited { retry_after }.into_response();
    }
    let request: LoginRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(err) => return AdminError::BadRequest(err.to_string()).into_response(),
    };
    if !state.config.token_matches(&request.token) {
        state.record_login_failure(caller.source_ip);
        state.audit(failed("wrong token")).await;
        return AdminError::Unauthorized.into_response();
    }
    let (cookie, session) = match state.create_session("token".into(), AuthKind::Token) {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };
    state
        .audit(Audit {
            actor: &session.actor,
            action: "login_ok",
            target: None,
            source_ip: caller.source_ip,
            ok: true,
            detail: None,
        })
        .await;
    (
        [(
            header::SET_COOKIE,
            set_cookie(&state, &cookie, SESSION_TTL_MS / 1000),
        )],
        Json(LoginResponse {
            actor: session.actor,
            csrf_token: session.csrf_token,
            expires_at: seconds(session.expires_at),
        }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/admin/api/logout",
    tag = "auth",
    summary = "End the session",
    description = "Deletes the session and clears the cookie. Audited as `logout`.",
    security(("adminSession" = [])),
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
        (status = 403, description = "Missing or wrong X-CSRF-Token (`csrf_failed`)", body = Error),
    ),
)]
pub async fn logout(
    State(state): State<AdminState>,
    Extension(caller): Extension<Caller>,
) -> Response {
    if let Some((cookie, _)) = &caller.session {
        state.remove_session(cookie);
    }
    caller
        .audit(&state, "logout", None, &Ok::<_, AdminError>(()), None)
        .await;
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, set_cookie(&state, "", 0))],
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/admin/api/session",
    tag = "auth",
    summary = "The current session",
    description = "Returns the session of the cookie. Without one, a request from a \
`GIM_HUB_ADMIN_TRUSTED_PROXIES` peer carrying `GIM_HUB_ADMIN_TRUSTED_HEADER` gets a new session \
(actor `header:<value>`, cookie set, audited as `login_ok`).",
    security(("adminSession" = [])),
    responses(
        (status = 200, description = "The session", body = SessionResponse),
        (status = 401, description = "No session (`unauthorized`)", body = Error),
    ),
)]
pub async fn get_session(
    Extension(caller): Extension<Caller>,
) -> Result<Json<SessionResponse>, AdminError> {
    let (_, session) = caller.session.ok_or(AdminError::Unauthorized)?;
    Ok(Json(SessionResponse {
        actor: session.actor,
        auth: session.auth.as_str().to_owned(),
        csrf_token: session.csrf_token,
        expires_at: seconds(session.expires_at),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_session_cookie() {
        let mut headers = HeaderMap::new();
        assert_eq!(session_cookie(&headers), None);
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("a=1; gim_admin_session=abc"),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("abc"));
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("x=1"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("gim_admin_session=def"),
        );
        assert_eq!(session_cookie(&headers).as_deref(), Some("def"));
    }

    #[test]
    fn seconds_round_down() {
        assert_eq!(seconds(1_999), 1);
        assert_eq!(seconds(0), 0);
    }
}
