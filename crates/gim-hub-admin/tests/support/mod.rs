//! Shared helpers: an admin API over a [`TestHub`], requests with a peer
//! address, and login.
#![allow(dead_code)]

use std::{net::SocketAddr, path::PathBuf};

use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use gim_hub_admin::{AdminConfig, AdminState};
use gim_hub_api::{
    settings::{self, Runtime, Sources, Vars},
    testing::TestHub,
};
use gim_hub_s2s::{FederationConfig, FederationService};
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

/// Default peer address of test requests.
pub const PEER: &str = "127.0.0.1:40000";

pub struct Admin {
    pub hub: TestHub,
    pub state: AdminState,
    /// The admin token.
    pub token: String,
    pub dir: TempDir,
}

pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Response {
    pub fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or_default()
    }
}

/// A session: cookie value and CSRF token.
#[derive(Debug, Clone)]
pub struct Login {
    pub cookie: String,
    pub csrf: String,
}

pub struct Options {
    /// Extra `GIM_HUB_ADMIN_*` variables.
    pub vars: Vec<(&'static str, String)>,
    pub token_file: bool,
    pub federation: Option<(FederationConfig, FederationService)>,
    /// Federation settings without a running service.
    pub federation_config: Option<FederationConfig>,
    pub lode_dir: Option<PathBuf>,
    /// The hub's environment as seen by the stored settings (besides
    /// `GIM_HUB_DATA_DIR`), e.g. env-set keys.
    pub env: Vec<(&'static str, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            vars: Vec::new(),
            token_file: true,
            federation: None,
            federation_config: None,
            lode_dir: None,
            env: Vec::new(),
        }
    }
}

impl Admin {
    pub fn new() -> Self {
        Self::with(TestHub::new(), Options::default())
    }

    pub fn with(hub: TestHub, options: Options) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let token = "t0ken-".repeat(8);
        let mut vars = vec![("GIM_HUB_ADMIN_LISTEN", "127.0.0.1:0".to_owned())];
        if options.token_file {
            let path = dir.path().join("admin.token");
            std::fs::write(&path, format!("{token}\n")).unwrap();
            vars.push(("GIM_HUB_ADMIN_TOKEN_FILE", path.display().to_string()));
        }
        vars.extend(options.vars);
        let config =
            AdminConfig::from_vars(vars.into_iter().map(|(k, v)| (k.to_owned(), v))).unwrap();
        let (federation_config, federation) = match options.federation {
            Some((config, service)) => (config, Some(service)),
            None => (
                options.federation_config.unwrap_or_else(|| {
                    FederationConfig::from_vars(Vec::new(), &hub.state.config.load().data_dir)
                        .unwrap()
                }),
                None,
            ),
        };
        let mut env = Vars::new();
        env.insert(
            "GIM_HUB_DATA_DIR".into(),
            hub.state.config.load().data_dir.display().to_string(),
        );
        env.extend(options.env.into_iter().map(|(k, v)| (k.to_owned(), v)));
        // The test database has no stored settings yet.
        let startup = settings::load(&Sources {
            env: env.clone(),
            ..Sources::default()
        })
        .unwrap()
        .vars;
        let runtime = Runtime::new(hub.state.db.clone(), env, startup, 0);
        settings::install(&runtime, hub.state.clone(), federation.clone(), None);
        let state = AdminState::new(
            hub.state.clone(),
            config,
            federation_config,
            federation,
            runtime,
            options.lode_dir,
        );
        Self {
            hub,
            state,
            token,
            dir,
        }
    }

    pub fn router(&self) -> Router {
        gim_hub_admin::router(self.state.clone())
    }

    /// Sends a request from `peer` with `headers`.
    pub async fn send(
        &self,
        method: Method,
        uri: &str,
        peer: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Response {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let mut request = request.body(body).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        let response = self.router().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        Response {
            status,
            headers,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    /// Sends a request with the session cookie and CSRF token of `login`.
    pub async fn call(
        &self,
        method: Method,
        uri: &str,
        login: &Login,
        body: Option<&Value>,
    ) -> Response {
        let cookie = format!("gim_admin_session={}", login.cookie);
        self.send(
            method,
            uri,
            PEER,
            &[("cookie", &cookie), ("x-csrf-token", &login.csrf)],
            body,
        )
        .await
    }

    pub async fn login_from(&self, peer: &str, token: &str) -> Response {
        self.send(
            Method::POST,
            "/admin/api/login",
            peer,
            &[],
            Some(&serde_json::json!({ "token": token })),
        )
        .await
    }

    /// Logs in with the admin token.
    pub async fn login(&self) -> Login {
        let response = self.login_from(PEER, &self.token).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        Login {
            cookie: session_cookie(&response.headers).unwrap(),
            csrf: response.body["csrf_token"].as_str().unwrap().to_owned(),
        }
    }

    /// The audit log, newest first.
    pub async fn audit(&self, login: &Login) -> Vec<Value> {
        let response = self
            .call(Method::GET, "/admin/api/audit?limit=200", login, None)
            .await;
        assert_eq!(response.status, StatusCode::OK);
        response.body["items"].as_array().unwrap().clone()
    }
}

/// The `gim_admin_session` value of a `Set-Cookie` header.
pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| value.strip_prefix("gim_admin_session="))
        .map(|rest| rest.split(';').next().unwrap_or_default().to_owned())
}
