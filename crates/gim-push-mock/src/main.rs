//! gim-push-mock binary: serves the mock push server (docs/push-mock.md).

use std::{
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    time::Duration,
};

use gim_push_mock::{router, Config, MockState};
use tracing_subscriber::EnvFilter;

const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("healthcheck") => {
            let listen = std::env::var("GIM_PUSH_MOCK_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8090".into())
                .parse()?;
            return Ok(healthcheck(probe_addr(listen))?);
        }
        Some("version" | "--version") => {
            println!(
                "gim-push-mock {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("GIM_HUB_BUILD_REV").unwrap_or("unknown")
            );
            return Ok(());
        }
        Some(other) => {
            return Err(format!(
                "unknown command {other:?}; usage: gim-push-mock [healthcheck|version]"
            )
            .into())
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %config.listen, "gim-push-mock listening");
    axum::serve(listener, router(MockState::new(&config)))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Address the healthcheck connects to: the listen address, with an
/// unspecified IP replaced by loopback.
fn probe_addr(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        ip if !ip.is_unspecified() => ip,
        IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
    };
    SocketAddr::new(ip, listen.port())
}

/// `gim-push-mock healthcheck`: succeeds if `GET /healthz` on `addr` returns
/// 200. Used by the container HEALTHCHECK, so the image needs no HTTP client.
fn healthcheck(addr: SocketAddr) -> io::Result<()> {
    let mut stream = TcpStream::connect_timeout(&addr, HEALTHCHECK_TIMEOUT)?;
    stream.set_read_timeout(Some(HEALTHCHECK_TIMEOUT))?;
    stream.set_write_timeout(Some(HEALTHCHECK_TIMEOUT))?;
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status_line = String::new();
    BufReader::new(stream).read_line(&mut status_line)?;
    if status_line.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "unhealthy: {:?}",
            status_line.trim_end()
        )))
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
