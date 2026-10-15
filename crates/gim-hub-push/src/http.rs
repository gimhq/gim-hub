//! Minimal HTTP abstraction so providers build requests as plain data
//! (unit-tested without network) and send them through [`HttpClient`].

use std::time::Duration;

use async_trait::async_trait;

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
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(TIMEOUT)
            .build()
            .map_err(|err| err.to_string())?;
        Ok(Self { client })
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
