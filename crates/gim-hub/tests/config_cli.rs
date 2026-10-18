//! `gim-hub config` against a running hub process: a live setting set by
//! the CLI is applied by the hub within the poll interval (seen through the
//! admin API), and a restart setting applies after a restart.

use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use serde_json::{json, Value};

const TOKEN: &str = "cli-test-admin-token-0123456789abcdef";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One HTTP/1.1 request; returns the status, the raw head and the JSON body.
fn request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Option<(u16, String, Value)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    write!(stream, "{head}\r\n{body}").ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    Some((
        status,
        head.to_owned(),
        serde_json::from_str(body).unwrap_or(Value::Null),
    ))
}

fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
    start.elapsed()
}

struct Hub {
    child: Child,
    port: u16,
    admin: u16,
}

impl Hub {
    fn start(data: &Path) -> Self {
        let (port, admin) = (free_port(), free_port());
        let child = Command::new(env!("CARGO_BIN_EXE_gim-hub"))
            .env_clear()
            .env("GIM_HUB_LISTEN", format!("127.0.0.1:{port}"))
            .env("GIM_HUB_ADMIN_LISTEN", format!("127.0.0.1:{admin}"))
            .env("GIM_HUB_ADMIN_TOKEN", TOKEN)
            .env("GIM_HUB_DATA_DIR", data)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let hub = Self { child, port, admin };
        wait_until("the hub", Duration::from_secs(30), || {
            request(hub.port, "GET", "/healthz", &[], None).is_some()
                && request(hub.admin, "GET", "/admin/api/session", &[], None).is_some()
        });
        hub
    }

    /// Logs in; returns the session cookie and the CSRF token.
    fn login(&self) -> (String, String) {
        let (status, head, body) = request(
            self.admin,
            "POST",
            "/admin/api/login",
            &[],
            Some(&json!({ "token": TOKEN })),
        )
        .unwrap();
        assert_eq!(status, 200, "{body}");
        let cookie = head
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .and_then(|value| value.split(';').next())
            .unwrap()
            .to_owned();
        (cookie, body["csrf_token"].as_str().unwrap().to_owned())
    }

    fn admin_get(&self, cookie: &str, path: &str) -> Value {
        let (status, _, body) =
            request(self.admin, "GET", path, &[("Cookie", cookie)], None).unwrap();
        assert_eq!(status, 200, "{path}: {body}");
        body
    }

    fn stop(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

/// `gim-hub config <args>` with the hub's bootstrap environment.
fn config(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gim-hub"))
        .env_clear()
        .env("GIM_HUB_DATA_DIR", data)
        .arg("config")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_changes_reach_the_running_hub() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let hub = Hub::start(&data);
    let (cookie, _csrf) = hub.login();
    let overview = hub.admin_get(&cookie, "/admin/api/overview");
    assert_eq!(overview["event_retention_days"], 7);

    // A live setting, while the hub runs.
    let out = config(&data, &["set", "GIM_HUB_EVENT_RETENTION_DAYS", "21"]);
    assert!(out.status.success(), "{out:?}");
    let latency = wait_until(
        "the hub to apply the CLI change",
        Duration::from_secs(5),
        || hub.admin_get(&cookie, "/admin/api/overview")["event_retention_days"] == 21,
    );
    assert!(latency < Duration::from_secs(3), "{latency:?}");
    let item = hub.admin_get(&cookie, "/admin/api/settings/GIM_HUB_EVENT_RETENTION_DAYS");
    assert_eq!(
        (&item["value"], &item["source"], &item["updated_by"]),
        (&json!(21), &json!("stored"), &json!("cli"))
    );

    // Invalid: refused, nothing changes.
    let out = config(&data, &["set", "GIM_HUB_EVENT_RETENTION_DAYS", "0"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("must be at least 1"));

    // A restart setting: stored and pending, applied after a restart.
    let out = config(
        &data,
        &["set", "GIM_HUB_PUBLIC_URL", "https://hub.example.eu"],
    );
    assert!(out.status.success(), "{out:?}");
    wait_until("restart_pending", Duration::from_secs(5), || {
        hub.admin_get(&cookie, "/admin/api/settings")["restart_pending"] == true
    });
    let (_, _, info) = request(hub.port, "GET", "/v2/hub", &[], None).unwrap();
    assert_eq!(info["public_url"], Value::Null);
    let audit = hub.admin_get(&cookie, "/admin/api/audit");
    let actors: Vec<_> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "setting_update")
        .map(|e| (e["actor"].clone(), e["result"].clone()))
        .collect();
    // Newest first.
    assert_eq!(
        actors,
        [
            (json!("cli"), json!("ok")),
            (json!("cli"), json!("error")),
            (json!("cli"), json!("ok")),
        ]
    );
    hub.stop();

    let hub = Hub::start(&data);
    let (_, _, info) = request(hub.port, "GET", "/v2/hub", &[], None).unwrap();
    assert_eq!(info["public_url"], "https://hub.example.eu");
    let (cookie, _) = hub.login();
    assert_eq!(
        hub.admin_get(&cookie, "/admin/api/settings")["restart_pending"],
        false
    );
    assert_eq!(
        hub.admin_get(&cookie, "/admin/api/overview")["event_retention_days"],
        21
    );
    hub.stop();
}
