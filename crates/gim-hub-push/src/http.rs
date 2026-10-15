//! Minimal HTTP abstraction so providers build requests as plain data
//! (unit-tested without network) and send them through [`HttpClient`].

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::validate::is_public;

const TIMEOUT: Duration = Duration::from_secs(15);

/// A POST request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// The value of header `name`, if set.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A response: status and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Sends POST requests; an `Err` is a transport failure (retryable).
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

/// [`HttpClient`] on reqwest (rustls with ring; HTTP/2 via ALPN).
pub struct ReqwestClient {
    client: reqwest::Client,
}

impl ReqwestClient {
    /// A client for fixed provider hosts (APNs, FCM).
    pub fn new() -> Result<Self, String> {
        Self::build(reqwest::Client::builder())
    }

    /// A client for client-supplied URLs (UnifiedPush endpoints): every
    /// resolved address must be public (no DNS rebinding to internal hosts).
    /// IP-literal URLs are checked at registration.
    pub fn public_only() -> Result<Self, String> {
        Self::build(reqwest::Client::builder().dns_resolver(Arc::new(PublicResolver)))
    }

    /// Redirects are never followed: a 3xx is a failed send.
    fn build(builder: reqwest::ClientBuilder) -> Result<Self, String> {
        let client = builder
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .map_err(|err| err.to_string())?;
        Ok(Self { client })
    }
}

/// Resolves with the system resolver and fails if any answer is not a
/// public address.
struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            check_public(&host, &addrs)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn check_public(host: &str, addrs: &[SocketAddr]) -> Result<(), String> {
    match addrs.iter().find(|addr| !is_public(addr.ip())) {
        _ if addrs.is_empty() => Err(format!("{host} did not resolve")),
        Some(addr) => Err(format!("{host} resolves to non-public {}", addr.ip())),
        None => Ok(()),
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn post(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let mut builder = self.client.post(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        let response = builder
            .body(request.body)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        let status = response.status().as_u16();
        let body = response.bytes().await.map_err(|err| err.to_string())?;
        Ok(HttpResponse {
            status,
            body: body.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_addresses_must_all_be_public() {
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(check_public("h", &[addr("203.0.113.9:0")]).is_ok());
        assert!(check_public("h", &[]).is_err());
        assert!(check_public("h", &[addr("203.0.113.9:0"), addr("10.0.0.1:0")]).is_err());
        assert!(check_public("h", &[addr("[::1]:0")]).is_err());
    }
}
