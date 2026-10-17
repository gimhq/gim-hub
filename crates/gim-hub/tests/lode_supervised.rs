//! The binary under a lode-like environment: readiness in `state.json`, the
//! release version from `LODE_ACTIVE_VERSION`, and a graceful SIGTERM stop
//! well within lode's `stop_timeout` (30 s in deploy/lode/lode.toml).

use std::{
    io::{Read, Write},
    net::TcpStream,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::Value;

const STOP_TIMEOUT: Duration = Duration::from_secs(30);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn get_json(port: u16, path: &str) -> Option<Value> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.split_once("\r\n\r\n")?.1).ok()
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn supervised_hub_reports_ready_and_stops_on_sigterm() {
    let tmp = tempfile::tempdir().unwrap();
    let lode_dir = tmp.path().join("lode");
    std::fs::create_dir(&lode_dir).unwrap();
    let state_path = lode_dir.join("state.json");
    std::fs::write(&state_path, r#"{"current":"0.2.1","status":"starting"}"#).unwrap();
    let port = free_port();

    let mut child = Command::new(env!("CARGO_BIN_EXE_gim-hub"))
        .env_clear()
        .env("GIM_HUB_LISTEN", format!("127.0.0.1:{port}"))
        .env("GIM_HUB_DATA_DIR", tmp.path().join("data"))
        .env("LODE_DIR", &lode_dir)
        .env("LODE_INSTANCE", "77-test")
        .env("LODE_ACTIVE_VERSION", "0.2.1")
        .env("LODE_READINESS", "state")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let ready = || {
        std::fs::read(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_some_and(|state| state["ready"] == "77-test")
    };
    wait_until("state.ready", ready);
    let state: Value = serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["current"], "0.2.1");
    assert_eq!(state["status"], "starting");

    let hub = get_json(port, "/v2/hub").expect("GET /v2/hub after readiness");
    assert_eq!(hub["version"], "0.2.1");

    let started = Instant::now();
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let mut status = None;
    wait_until("exit after SIGTERM", || {
        status = child.try_wait().unwrap();
        status.is_some() || started.elapsed() > STOP_TIMEOUT
    });
    let Some(status) = status else {
        child.kill().unwrap();
        panic!("hub still running {STOP_TIMEOUT:?} after SIGTERM");
    };
    assert!(status.success(), "exit status {status}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn unsupervised_hub_leaves_no_state_file() {
    let tmp = tempfile::tempdir().unwrap();
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gim-hub"))
        .env_clear()
        .env("GIM_HUB_LISTEN", format!("127.0.0.1:{port}"))
        .env("GIM_HUB_DATA_DIR", tmp.path().join("data"))
        .current_dir(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut hub = None;
    wait_until("GET /v2/hub", || {
        hub = get_json(port, "/v2/hub");
        hub.is_some()
    });
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(hub.unwrap()["version"], env!("CARGO_PKG_VERSION"));
    let mut names: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["data"]);
}
