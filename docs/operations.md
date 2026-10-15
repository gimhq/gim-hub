# Operating gim-hub

## Configuration

gim-hub reads its configuration from environment variables at startup. Empty
variables count as unset. An invalid value stops the hub with an error naming
the variable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIM_HUB_LISTEN` | `0.0.0.0:8080` | Socket address of the client API |
| `GIM_HUB_DATA_DIR` | `./data` | Data directory (see below) |
| `GIM_HUB_DATABASE_PATH` | `$GIM_HUB_DATA_DIR/hub.db` | SQLite database file |
| `GIM_HUB_EVENT_RETENTION_DAYS` | `7` | Events older than this are pruned (minimum 1) |
| `GIM_HUB_KEYPACKAGE_LOW_THRESHOLD` | `10` | A device is sent `keypackages.low` when its one-time KeyPackages drop below this |
| `GIM_HUB_MAX_MESSAGE_BYTES` | `262144` | Largest accepted MLS message (minimum 1) |
| `GIM_HUB_MAX_BLOB_BYTES` | `104857600` | Largest accepted blob (minimum 1) |
| `GIM_HUB_LONGPOLL_MAX_WAIT_SECONDS` | `30` | Upper bound for long-poll `wait` |
| `GIM_HUB_SESSION_TTL_DAYS` | `30` | Lifetime of device bearer tokens (minimum 1) |
| `GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN` | `120` | Unauthenticated `GET /v2/users/{user_id}` and `.../device-list` requests per client IP (IPv6: per /64) per minute (minimum 1) |
| `GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN` | `60` | Unauthenticated reads of one `user_id` per minute, across all clients (minimum 1) |
| `GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN` | `20` | Unauthenticated `GET /v2/users/{user_id}/recovery-backup` requests per client IP (IPv6: per /64) per minute, separate from the public reads (minimum 1) |
| `GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN` | `10` | Recovery backup reads of one `user_id` per minute, across all clients (minimum 1) |
| `GIM_HUB_TRUST_FORWARDED_FOR` | `false` | `true` keys the per-IP limit by the left-most `X-Forwarded-For` address; set only behind a reverse proxy that overwrites the header |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` `EnvFilter` syntax, e.g. `gim_hub_api=debug,info`) |

### Federation

Federation is off unless `GIM_HUB_FEDERATION=true`; every other variable in this table is ignored
while it is off. Design: [`federation.md`](federation.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIM_HUB_FEDERATION` | `false` | `true` starts the libp2p host and federation |
| `GIM_HUB_P2P_LISTEN` | `/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4001` | Comma-separated listen multiaddrs (TCP only when a PSK is set) |
| `GIM_HUB_P2P_EXTERNAL_ADDRS` | unset | Comma-separated multiaddrs advertised to peers (default: the actual listen addresses that are not unspecified) |
| `GIM_HUB_P2P_BOOTSTRAP` | unset | Comma-separated bootstrap multiaddrs, `/p2p/<PeerId>` optional |
| `GIM_HUB_FEDERATION_ALLOWLIST` | `$GIM_HUB_DATA_DIR/allowlist` | Allowlist file, reloaded on SIGHUP |
| `GIM_HUB_P2P_PSK_FILE` | unset | libp2p `swarm.key` file; set = private network (pnet), TCP only |
| `GIM_HUB_RUNTIME_CERT_DAYS` | `30` | Runtime certificate lifetime (minimum 2) |
| `GIM_HUB_S2S_TIMEOUT_SECONDS` | `10` | Timeout of one hub-to-hub request (minimum 1) |
| `GIM_HUB_DHT_REPUBLISH_HOURS` | `12` | Republish cadence of hosted users' hosting records (minimum 1) |
| `GIM_HUB_HOSTING_CACHE_SECONDS` | `600` | Freshness of cached remote hosting records |
| `GIM_HUB_DEVICE_LIST_CACHE_HOURS` | `24` | Freshness of cached remote DeviceLists |
| `GIM_HUB_OUTBOX_TTL_HOURS` | `168` | Lifetime of queued outbound hub-to-hub entries (minimum 1) |
| `GIM_HUB_OUTBOX_MAX_ENTRIES_PER_PEER` | `100000` | Outbound backlog cap per peer hub, entries (minimum 1) |
| `GIM_HUB_OUTBOX_MAX_BYTES_PER_PEER` | `1073741824` | Outbound backlog cap per peer hub, bytes (minimum 1) |
| `GIM_HUB_OUTBOX_BACKOFF_MAX_SECONDS` | `300` | Maximum retry backoff per peer hub (minimum 1) |
| `GIM_HUB_UNHOSTED_GRACE_HOURS` | `168` | How long a user who removed this hub from their hosting record keeps read access before their data is purged (minimum 1; [`multihoming.md`](multihoming.md) §7.3) |

The allowlist lists one peer `hub_id` per line, optionally followed by static multiaddrs without
`/p2p/`; `#` starts a comment and the hub's own `hub_id` is ignored:

```
# hub_id                                                  [multiaddr ...]
hciqgtrdldzdkwq3c7fkmzvld7djgm3waetwtedhujnndujzulpgk6vq  /ip4/10.0.0.12/tcp/4001 /ip4/10.0.0.12/udp/4001/quic-v1
```

Allowlist, bootstrap and external addresses may be `/ip4/`, `/ip6/`, `/dns4/` or `/dns6/`
multiaddrs. DNS names are resolved with the system resolver (`/etc/resolv.conf`, `/etc/hosts`) at
dial time, over TCP and QUIC alike (with a PSK, TCP only).

A missing or empty allowlist, an invalid line, or a QUIC address together with
`GIM_HUB_P2P_PSK_FILE` stops startup. On SIGHUP the file is re-read; an invalid file is logged and
the previous allowlist stays in force; hubs no longer listed are disconnected. With federation
enabled the data directory also holds `runtime_key` (32-byte Ed25519 seed of the libp2p host key,
mode 0600) and `runtime_cert` (its certificate, signed by `hub_key` and renewed automatically when
less than a third of its lifetime remains). Deleting both while the hub is stopped rotates the
PeerId; allowlists are unaffected because they name `hub_id`s. `gim-hub hub-id` prints the
`hub_id` (creating `hub_key` if missing), which peers need for their allowlists.

### Federation acceptance test

`scripts/fed-test.sh` is the closed-federation acceptance test (CI job `federation`). It needs
only Docker:

1. builds the hub image from the `Dockerfile` (`GIM_FED_SKIP_BUILD=1` reuses `GIM_FED_IMAGE`);
2. generates fresh hub root keys in the hubs' volumes with `gim-hub hub-id` and writes the
   allowlists into `.tmp/fed-<pid>/` (nothing key-related is committed);
3. starts `deploy/federation/compose.yaml`: `hub-a`, `hub-b`, `hub-c` allowing each other and
   `hub-x`, which is on nobody's allowlist, on an isolated network with fixed IPs
   (`GIM_FED_SUBNET`, default `10.231.64`; change it if that /24 is taken);
4. runs the driver `crates/gim-hub/tests/fed_compose.rs` (`cargo test -p gim-hub --test
   fed_compose -- --ignored`) in a `rust:1.99-bookworm` container attached to that network. The
   driver speaks the client API to every hub with openmls clients and stops and starts hubs
   through the mounted Docker socket. Scenarios: hosting-record resolution, a cross-hub direct
   message, a group across three hubs with add and remove from a non-owning hub, a concurrent
   Commit conflict (one 201, one 409 `stale_epoch`), a member-hub outage (50 messages, no loss,
   no duplicates), an owner-hub outage (503 `peer_unavailable`, then delivery) and the refusal of
   `hub-x`;
5. prints the hub logs on failure and always removes the containers, network and volumes.

All containers, the network and the volumes carry the label `ai-agent=true`. Other variables:
`GIM_FED_PROJECT` (compose project, default `gim-fed`), `GIM_FED_CARGO_HOME` (cargo home of the
driver container) and `GIM_FED_TIMEOUT` (driver timeout in seconds).

### Push

Push design and payload: [`push.md`](push.md). The `log` provider is always available. Each other
provider is inert until configured: registrations for it are accepted and its sends are logged as
skipped. Unreadable or invalid credentials stop startup. Keep credentials out of the image (mount
them, e.g. under `/run/secrets`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIM_HUB_PUSH_MEMBER_EVENTS` | `false` | Also push `group.member_added` / `group.member_removed` (silent) |
| `GIM_HUB_PUSH_MINIMAL` | `false` | `true` sends minimal wake-up payloads `{"v":1,"type":"wake","collapse_id"}` only (no group, sequence or MLS message; see `push.md`) |
| `GIM_HUB_PUSH_QUEUE_CAPACITY` | `10000` | Most devices with a queued push; further pushes are dropped (minimum 1) |
| `GIM_HUB_PUSH_LOG_ENDPOINT` | `false` | Serve the unauthenticated, test-only `GET /v2/debug/push-log`; never enable in production |
| `GIM_HUB_PUSH_APNS_TEAM_ID` | unset | APNs team ID; the four `APNS` variables below enable APNs together |
| `GIM_HUB_PUSH_APNS_KEY_ID` | unset | ID of the APNs auth key |
| `GIM_HUB_PUSH_APNS_KEY_PATH` | unset | Path of the APNs auth key (`.p8`) |
| `GIM_HUB_PUSH_APNS_TOPIC` | unset | Default APNs topic (bundle ID) for registrations without `app_id` |
| `GIM_HUB_PUSH_APNS_SANDBOX` | `false` | Send every APNs push through the sandbox |
| `GIM_HUB_PUSH_FCM_SERVICE_ACCOUNT_PATH` | unset | Service account JSON key; enables FCM |
| `GIM_HUB_PUSH_FCM_PROJECT_ID` | service account's `project_id` | Firebase project ID |
| `GIM_HUB_PUSH_UNIFIEDPUSH` | `false` | `true` delivers to UnifiedPush endpoints |

## Data directory

```
$GIM_HUB_DATA_DIR/
├── hub.db        SQLite database (WAL mode, with hub.db-wal and hub.db-shm)
├── hub_key       32-byte Ed25519 seed of the hub root key, mode 0600
└── blobs/        Encrypted blob contents, one file per blob
```

- `hub.db` is created on first start; schema migrations are embedded in the
  binary and applied automatically (tracked in `PRAGMA user_version`). A hub
  refuses to open a database written by a newer schema version.
- `hub_key` is generated on first start. It is the hub ROOT key and
  determines the hub's `hub_id` (gim-core identity spec): the audience of
  sign-in challenges, the owner prefix of group IDs and the hub named in
  users' hosting records. Replacing it changes `hub_id`, so it must be kept
  secret, backed up with the database and never replaced on a running
  deployment. The `hub_id` is logged at startup.
- Back up `hub.db` with SQLite's online backup (`sqlite3 hub.db ".backup
  out.db"`) or while the hub is stopped; copying the file alone while running
  can miss the WAL.

## Retention

An hourly background task (also run at startup) deletes events older than
`GIM_HUB_EVENT_RETENTION_DAYS` and expired device-link bundles, and purges the
data of users who removed this hub more than `GIM_HUB_UNHOSTED_GRACE_HOURS` ago
(their hosting record is kept as a tombstone). A client whose cursor is older than the
newest pruned event receives 410 `cursor_expired` with the head cursor and
must resync. Pending Welcomes are kept until acknowledged, independently of
event retention.

## Docker

The `Dockerfile` builds a release binary in `rust:1.99-bookworm` and runs it on
`debian:bookworm-slim` as the unprivileged user `gimhub` (uid 10001).

- `GIM_HUB_LISTEN=0.0.0.0:8080` and `GIM_HUB_DATA_DIR=/data` are set in the
  image; port 8080 is exposed and `/data` is a volume. Mount a named volume or
  a host directory writable by uid 10001 there, and back it up as described
  above (it holds `hub_key`).
- Port 4001 (TCP and UDP) is exposed for federation (`GIM_HUB_P2P_LISTEN` default).
- The container `HEALTHCHECK` runs `gim-hub healthcheck`, which sends
  `GET /healthz` to the `GIM_HUB_LISTEN` port (loopback if the address is
  unspecified) and exits non-zero unless it gets 200. No HTTP client is
  installed in the image.
- Other variables from the table above are passed with `-e`.

```bash
docker build -t gim-hub .
docker run -d --name gim-hub -p 8080:8080 -v gim-hub-data:/data \
  -e GIM_HUB_EVENT_RETENTION_DAYS=14 gim-hub
```

`scripts/docker-smoke.sh` builds the image and checks a running container; CI
runs it on every push.

Build notes:

- The builder caches only the cargo registry and git checkouts. `target/` is
  not cached: a BuildKit cache mount is shared by every checkout built on the
  same daemon, and cargo judges freshness by mtime, so a shared `target/` can
  yield a binary built from another checkout's sources. Docker's layer cache
  is keyed on the build context content and stays safe.
- `gim-hub version` prints the package version and the `GIM_HUB_BUILD_REV`
  build argument (`unknown` if unset). `scripts/docker-build.sh IMAGE`, used by
  `docker-smoke.sh` and `fed-test.sh`, passes the checkout's revision (with a
  `-dirty-<hash>` suffix for uncommitted changes to tracked files) and fails
  unless the built image reports exactly that revision.

## Shutdown

The hub stops accepting connections on SIGINT or SIGTERM and finishes
in-flight requests before exiting.
