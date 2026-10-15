//! The federation service: runtime identity, transport, policy admission and
//! op dispatch (docs/federation.md §2, §3.1, §3.7).
//!
//! Inbound requests pass binding (transport) → [`FederationPolicy::admit`]
//! → the handler registered for the op. Ops without a handler answer
//! `INTERNAL` "not implemented"; later subtasks register theirs with
//! [`FederationService::register`].

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use gim_hub_identity::{HubId, SigningKey};
use gim_hub_proto::s2s::{
    s2s_request::Op, s2s_response::Result as OpOutput, Error as S2sError, ErrorCode, S2sRequest,
    S2sResponse,
};
use tokio::task::JoinHandle;

use crate::{
    config::FederationConfig,
    policy::{AllowlistPolicy, Decision, FederationPolicy, OpKind, PolicyError},
    transport::{now_ms, InboundRequest, RuntimeIdentity, SendError, Transport, TransportConfig},
};

/// A boxed, `Send` future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Result of an op handler: the response variant matching the request op,
/// or an S2S error.
pub type OpResult = Result<OpOutput, S2sError>;

/// Handles one inbound op from the bound, admitted hub `caller`.
pub type OpHandler = Arc<dyn Fn(HubId, Op) -> BoxFuture<'static, OpResult> + Send + Sync>;

/// How often the runtime certificate is checked for renewal (§3.1).
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// What the client API needs from federation. Object safe; [`Disabled`]
/// is the implementation when `GIM_HUB_FEDERATION=false`.
pub trait Federation: Send + Sync + 'static {
    fn is_enabled(&self) -> bool;

    /// Sends `request` to `hub_id` (resolving, dialing and binding it as
    /// needed) and returns its response, which may carry an S2S error.
    fn send(
        &self,
        hub_id: &HubId,
        request: S2sRequest,
    ) -> BoxFuture<'_, Result<S2sResponse, SendError>>;
}

/// Federation turned off: every send fails with [`SendError::Disabled`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Disabled;

impl Federation for Disabled {
    fn is_enabled(&self) -> bool {
        false
    }

    fn send(&self, _: &HubId, _: S2sRequest) -> BoxFuture<'_, Result<S2sResponse, SendError>> {
        Box::pin(async { Err(SendError::Disabled) })
    }
}

/// Startup failure of the federation service.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("runtime key or certificate: {0}")]
    Runtime(#[from] std::io::Error),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("transport: {0}")]
    Transport(#[from] SendError),
}

type Handlers = RwLock<HashMap<OpKind, OpHandler>>;

/// The running federation service. Cheap to clone; stops when the last
/// clone is dropped or on [`FederationService::shutdown`].
#[derive(Clone)]
pub struct FederationService {
    inner: Arc<Inner>,
}

struct Inner {
    transport: Transport,
    handlers: Arc<Handlers>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for task in self.tasks.get_mut().expect("tasks lock").drain(..) {
            task.abort();
        }
        self.transport.shutdown();
    }
}

impl std::fmt::Debug for FederationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationService")
            .field("hub_id", self.hub_id())
            .finish_non_exhaustive()
    }
}

impl FederationService {
    /// Starts federation with the closed-federation [`AllowlistPolicy`]
    /// from `config`, reloaded on SIGHUP.
    pub async fn start_with_allowlist(
        config: &FederationConfig,
        hub_root: &SigningKey,
    ) -> Result<Self, StartError> {
        let hub_id = HubId::from_root_pubkey(&hub_root.verifying_key());
        let allowlist = Arc::new(AllowlistPolicy::load(
            &config.allowlist_path,
            &hub_id,
            config.psk,
        )?);
        let service = Self::start(config, hub_root, allowlist.clone()).await?;
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hangup = signal(SignalKind::hangup())?;
            let transport = service.inner.transport.clone();
            let reload = tokio::spawn(async move {
                while hangup.recv().await.is_some() {
                    match allowlist.reload() {
                        Ok(()) => {
                            tracing::info!(hubs = allowlist.hub_ids().len(), "allowlist reloaded");
                            transport.policy_changed();
                        }
                        Err(err) => {
                            tracing::error!(%err, "allowlist reload failed; keeping the previous one")
                        }
                    }
                }
            });
            service.inner.tasks.lock().expect("tasks lock").push(reload);
        }
        Ok(service)
    }

    /// Starts federation with `policy`: loads or creates the runtime key and
    /// certificate, starts the transport and the dispatcher, and renews the
    /// certificate daily when due.
    pub async fn start(
        config: &FederationConfig,
        hub_root: &SigningKey,
        policy: Arc<dyn FederationPolicy>,
    ) -> Result<Self, StartError> {
        let hub_id = HubId::from_root_pubkey(&hub_root.verifying_key());
        let runtime = RuntimeIdentity::load_or_create(
            &config.runtime_key_path(),
            &config.runtime_cert_path(),
            hub_root,
            config.runtime_cert_days,
            now_ms(),
        )?;
        let transport_config = TransportConfig {
            listen: config.listen.clone(),
            external_addrs: config.external_addrs.clone(),
            bootstrap: config.bootstrap.clone(),
            timeout: config.s2s_timeout,
            psk: config.psk,
        };
        let (transport, mut inbound) =
            Transport::start(transport_config, hub_id, &runtime, policy.clone()).await?;
        let handlers = Arc::new(Handlers::default());

        let dispatcher = {
            let handlers = handlers.clone();
            tokio::spawn(async move {
                while let Some(request) = inbound.recv().await {
                    tokio::spawn(handle(request, policy.clone(), handlers.clone()));
                }
            })
        };
        let renewal = {
            let transport = transport.clone();
            let cert_path = config.runtime_cert_path();
            let days = config.runtime_cert_days;
            let hub_root = hub_root.clone();
            let mut runtime = runtime;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(RENEWAL_CHECK_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    match runtime.renew_if_needed(&cert_path, &hub_root, days, now_ms()) {
                        Ok(true) => {
                            tracing::info!(
                                not_after = runtime.not_after(),
                                "runtime certificate renewed"
                            );
                            transport.set_runtime_cert(&runtime).await;
                        }
                        Ok(false) => {}
                        Err(err) => tracing::error!(%err, "runtime certificate renewal failed"),
                    }
                }
            })
        };
        Ok(Self {
            inner: Arc::new(Inner {
                transport,
                handlers,
                tasks: Mutex::new(vec![dispatcher, renewal]),
            }),
        })
    }

    /// Registers the handler of `op`, replacing any previous one. `Hello` is
    /// handled by the transport and never dispatched.
    pub fn register(&self, op: OpKind, handler: OpHandler) {
        self.inner
            .handlers
            .write()
            .expect("handlers lock")
            .insert(op, handler);
    }

    /// The transport: DHT access, record validators, peer events.
    pub fn transport(&self) -> &Transport {
        &self.inner.transport
    }

    pub fn hub_id(&self) -> &HubId {
        self.inner.transport.hub_id()
    }

    /// Stops the transport and background tasks.
    pub fn shutdown(&self) {
        for task in self.inner.tasks.lock().expect("tasks lock").drain(..) {
            task.abort();
        }
        self.inner.transport.shutdown();
    }
}

impl Federation for FederationService {
    fn is_enabled(&self) -> bool {
        true
    }

    fn send(
        &self,
        hub_id: &HubId,
        request: S2sRequest,
    ) -> BoxFuture<'_, Result<S2sResponse, SendError>> {
        let hub_id = hub_id.clone();
        Box::pin(async move { self.inner.transport.request(&hub_id, request).await })
    }
}

async fn handle(
    request: InboundRequest,
    policy: Arc<dyn FederationPolicy>,
    handlers: Arc<Handlers>,
) {
    let InboundRequest {
        caller,
        request,
        responder,
    } = request;
    let response = dispatch(caller, request, policy.as_ref(), &handlers).await;
    responder.respond(response);
}

/// Policy admission, then the registered handler (§3.7).
async fn dispatch(
    caller: HubId,
    request: S2sRequest,
    policy: &dyn FederationPolicy,
    handlers: &Handlers,
) -> S2sResponse {
    let result = match request.op {
        None => Err(error(ErrorCode::Invalid, "missing op")),
        Some(op) => {
            let kind = OpKind::of(&op);
            match policy.admit(&caller, kind) {
                Decision::Allow => {
                    let handler = handlers.read().expect("handlers lock").get(&kind).cloned();
                    match handler {
                        Some(handler) => handler(caller, op).await,
                        None => Err(error(ErrorCode::Internal, "not implemented")),
                    }
                }
                Decision::Deny(reason) => Err(error(ErrorCode::Unauthorized, reason)),
                Decision::RateLimited { retry_after_ms } => Err(error(
                    ErrorCode::RateLimited,
                    &format!("rate limited; retry after {retry_after_ms} ms"),
                )),
            }
        }
    };
    match result {
        Ok(output) => S2sResponse {
            request_id: request.request_id,
            result: Some(output),
            error: None,
        },
        Err(err) => S2sResponse {
            request_id: request.request_id,
            result: None,
            error: Some(err),
        },
    }
}

/// An S2S error with `code` and `message`.
pub fn error(code: ErrorCode, message: &str) -> S2sError {
    S2sError {
        code: code as i32,
        message: message.to_owned(),
        ..S2sError::default()
    }
}

#[cfg(test)]
mod tests {
    use gim_hub_proto::s2s::{GetDeviceListRequest, GetDeviceListResponse, SubmitCommitRequest};

    use super::*;
    use crate::transport::Multiaddr;

    struct Limits;

    impl FederationPolicy for Limits {
        fn psk(&self) -> Option<crate::config::Psk> {
            None
        }
        fn allow_hub(&self, _: &HubId) -> Decision {
            Decision::Allow
        }
        fn admit(&self, _: &HubId, op: OpKind) -> Decision {
            match op {
                OpKind::FetchLog => Decision::Deny("no"),
                OpKind::ClaimKeyPackage => Decision::RateLimited { retry_after_ms: 5 },
                _ => Decision::Allow,
            }
        }
        fn may_contact(&self, _: &HubId) -> bool {
            true
        }
        fn static_addrs(&self, _: &HubId) -> Vec<Multiaddr> {
            Vec::new()
        }
    }

    fn caller() -> HubId {
        HubId::from_root_pubkey(&SigningKey::from_bytes(&[1; 32]).verifying_key())
    }

    fn request(op: Op) -> S2sRequest {
        S2sRequest {
            request_id: "r-1".into(),
            op: Some(op),
        }
    }

    fn code(response: &S2sResponse) -> ErrorCode {
        response.error.as_ref().expect("error").code()
    }

    #[tokio::test]
    async fn dispatch_applies_policy_then_handler() {
        let handlers = Handlers::default();
        handlers.write().unwrap().insert(
            OpKind::GetDeviceList,
            Arc::new(|caller: HubId, op: Op| -> BoxFuture<'static, OpResult> {
                Box::pin(async move {
                    let Op::GetDeviceList(req) = op else {
                        unreachable!()
                    };
                    Ok(OpOutput::GetDeviceList(GetDeviceListResponse {
                        device_list_cbor: format!("{caller}:{}", req.user_id).into_bytes(),
                    }))
                })
            }),
        );

        let response = dispatch(
            caller(),
            request(Op::GetDeviceList(GetDeviceListRequest {
                user_id: "u1".into(),
            })),
            &Limits,
            &handlers,
        )
        .await;
        assert_eq!(response.request_id, "r-1");
        assert_eq!(
            response.result,
            Some(OpOutput::GetDeviceList(GetDeviceListResponse {
                device_list_cbor: format!("{}:u1", caller()).into_bytes(),
            }))
        );

        let not_implemented = dispatch(
            caller(),
            request(Op::SubmitCommit(SubmitCommitRequest::default())),
            &Limits,
            &handlers,
        )
        .await;
        assert_eq!(code(&not_implemented), ErrorCode::Internal);
        assert_eq!(not_implemented.error.unwrap().message, "not implemented");

        let denied = dispatch(
            caller(),
            request(Op::FetchLog(Default::default())),
            &Limits,
            &handlers,
        )
        .await;
        assert_eq!(code(&denied), ErrorCode::Unauthorized);
        let limited = dispatch(
            caller(),
            request(Op::ClaimKeyPackage(Default::default())),
            &Limits,
            &handlers,
        )
        .await;
        assert_eq!(code(&limited), ErrorCode::RateLimited);
        let missing = dispatch(
            caller(),
            S2sRequest {
                request_id: "r-2".into(),
                op: None,
            },
            &Limits,
            &handlers,
        )
        .await;
        assert_eq!(code(&missing), ErrorCode::Invalid);
        assert_eq!(missing.request_id, "r-2");
    }

    #[tokio::test]
    async fn multihoming_ops_are_not_implemented_yet() {
        let handlers = Handlers::default();
        // NotifyHostingRecord has a handler (ops::hosting_record).
        assert!(!crate::ops::MULTIHOMING_OPS.contains(&OpKind::NotifyHostingRecord));
        for op in [
            Op::SeedReplica(Default::default()),
            Op::CopyPendingWelcomes(Default::default()),
        ] {
            assert!(crate::ops::MULTIHOMING_OPS.contains(&OpKind::of(&op)));
            let response = dispatch(caller(), request(op), &Limits, &handlers).await;
            assert_eq!(response.result, None);
            assert_eq!(code(&response), ErrorCode::Internal);
            assert_eq!(response.error.unwrap().message, "not implemented");
        }
    }

    #[tokio::test]
    async fn disabled_federation_refuses_to_send() {
        let federation: Arc<dyn Federation> = Arc::new(Disabled);
        assert!(!federation.is_enabled());
        assert_eq!(
            federation.send(&caller(), S2sRequest::default()).await,
            Err(SendError::Disabled)
        );
    }
}
