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
| `GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN` | `120` | Unauthenticated `GET /v2/users/{user_id}`, `.../device-list` and `.../hosting-record` requests per client IP (IPv6: per /64) per minute (minimum 1) |
| `GIM_HUB_PUBLIC_READ_PER_USER_PER_MIN` | `60` | Unauthenticated reads of one `user_id` per minute, across all clients (minimum 1) |
| `GIM_HUB_RECOVERY_READ_PER_IP_PER_MIN` | `20` | Unauthenticated `GET /v2/users/{user_id}/recovery-backup` requests per client IP (IPv6: per /64) per minute, separate from the public reads (minimum 1) |
| `GIM_HUB_RECOVERY_READ_PER_USER_PER_MIN` | `10` | Recovery backup reads of one `user_id` per minute, across all clients (minimum 1) |
| `GIM_HUB_TRUST_FORWARDED_FOR` | `false` | `true` keys the per-IP limit by the left-most `X-Forwarded-For` address; set only behind a reverse proxy that overwrites the header |
| `GIM_HUB_PUBLIC_URL` | unset | Canonical client-API base URL (`scheme://host[:port]`), required when `GIM_HUB_FEDERATION=true`. Normalized at startup; see below |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` `EnvFilter` syntax, e.g. `gim_hub_api=debug,info`) |

`GIM_HUB_PUBLIC_URL` is the URL clients reach this hub's client API at, as listed for it by
clients and other hubs. It is signed into `GET /v2/hub?nonce=` proofs and into sign-in
challenges (AuthChallenge v2), so it must be exactly the URL clients use. It is normalized
before use: the scheme must be `http` or `https` (lowercased), the host (DNS name, IPv4 or
bracketed IPv6) is lowercased, a port equal to the scheme default (80, 443) is dropped and a
single trailing `/` is removed. Userinfo, any other path, a query, a fragment or a result
longer than 65535 bytes is a startup error, as is an unset URL with `GIM_HUB_FEDERATION=true`.
gim-core applies the same rules; the shared cases are in `testdata/identity/public-url.json`. Example:
`HTTPS://Hub.Example.EU:443/` becomes `https://hub.example.eu`. Without federation it is
optional; a hub without it issues version 1 challenges and answers `GET /v2/hub?nonce=` with 400.

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
| `GIM_HUB_PUSH_FAILOVER_SECONDS` | `30` | A co-host hub without a successful ping or hub-to-hub exchange for this long is down; a fallback hub of a multi-homed user pushes only while every hub before it is down (minimum 1; [`multihoming.md`](multihoming.md) §8) |
| `GIM_HUB_FETCH_BLOB_PER_MINUTE` | `600` | Blob chunk requests (`FetchBlob`, up to 4 MiB each) served per peer hub and minute (minimum 1; [`federation.md`](federation.md) §5.6) |

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

1. builds the hub image from the `Dockerfile` and the mock push server image from
   `Dockerfile.push-mock` (`GIM_FED_SKIP_BUILD=1` reuses `GIM_FED_IMAGE` and
   `GIM_FED_PUSH_MOCK_IMAGE`);
2. generates fresh hub root keys in the hubs' volumes with `gim-hub hub-id` and writes the
   allowlists into `.tmp/fed-<pid>/` (nothing key-related is committed);
3. starts `deploy/federation/compose.yaml`: `hub-a`, `hub-b`, `hub-c` allowing each other and
   `hub-x`, which is on nobody's allowlist (each with `GIM_HUB_PUBLIC_URL=http://hub-<n>:8080`,
   the base URL of the driver), on an isolated network with fixed IPs
   (`GIM_FED_SUBNET`, default `10.231.64`; change it if that /24 is taken), and `push-mock`
   ([`push-mock.md`](push-mock.md)), the target of every hub's push webhook with a secret
   generated for the run;
4. runs the driver `crates/gim-hub/tests/fed_compose.rs` (`cargo test -p gim-hub --test
   fed_compose -- --ignored`) in a `rust:1.99-bookworm` container attached to that network. The
   driver speaks the client API to every hub with openmls clients and stops and starts hubs
   through the mounted Docker socket. Scenarios: hub-b's `GET /v2/hub?nonce=` proof (verified
   with its root key and URL; every sign-in also checks that the challenge is v2 for the hub's
   URL), hosting-record resolution, a cross-hub direct
   message, a Commit adding a revoked device of a remote user (400 `revoked_device`), a group
   across three hubs with add and remove from a non-owning hub, a concurrent
   Commit conflict (one 201, one 409 `stale_epoch`), a member-hub outage (50 messages, no loss,
   no duplicates), an owner-hub outage (503 `peer_unavailable`, then delivery), the refusal of
   `hub-x`, a leave by Proposal and webhook push (one signed delivery per message at the mock,
   none for a Proposal, a registration answered 410 deleted);
5. prints the hub logs on failure and always removes the containers, network and volumes.

All containers, the network and the volumes carry the label `ai-agent=true`. Other variables:
`GIM_FED_PROJECT` (compose project, default `gim-fed`), `GIM_FED_CARGO_HOME` (cargo home of the
driver container), `GIM_FED_TIMEOUT` (driver timeout in seconds) and `GIM_FED_RUN_LABEL` (value of
the `ai-agent-run` label also set on every container, network and volume, default the project
name).

`GIM_FED_PSK=1 bash scripts/fed-test.sh` runs the PSK variant (`deploy/federation/compose.psk.yaml`,
not run in CI): hub-a, hub-b and hub-c share a pnet key generated for the run and use TCP only;
hub-x has no key. It first checks that a hub with the key and a QUIC listen address refuses to
start, then runs the same scenarios; hub-x must never get a `Hello` to hub-a.

### Multi-homing

A user is multi-homed when their hosting record lists several hubs
([`multihoming.md`](multihoming.md)). It needs nothing beyond federation
(`GIM_HUB_FEDERATION=true`): every listed hub must allow the others, and the owning hubs of the
user's groups must allow all of them. Two variables apply (table above):

- `GIM_HUB_UNHOSTED_GRACE_HOURS` (default 168): after a user removes this hub, their devices may
  still sign in and read (drain their cursor) for this long; every other write is 403
  `hosting_record_required`. The hourly retention task then purges the user's data and keeps
  the record as a tombstone.
- `GIM_HUB_PUSH_FAILOVER_SECONDS` (default 30): only the user's primary hub pushes; a fallback
  hub starts pushing once every hub before it has been unreachable for this long and stops when
  it sees the primary again. Lower it for faster failover at the cost of double pushes during
  short blips (devices collapse them on `collapse_id`).

Known limits: a group whose owning hub is down cannot sequence (503 `peer_unavailable` through
every hub; owning-hub migration is out of scope); blobs are not replicated: a hub fetches a
remote blob from its origin on first download, so while the origin is down only copies fetched
before are served; an added hub serves no history before its replica seed; pushes for messages
that arrive in the failover window after the primary stops are not sent late; the client must
`PUT` a new record to the added hub before the other hubs, or an owner that only caches the
user's record may seed the added hub too early and the seed is dropped (§4.3).

`GIM_FED_SUITE=mh bash scripts/fed-test.sh` runs the multi-homing acceptance suite
(multihoming.md §11, MH1-MH9; driver `crates/gim-hub/tests/multihoming_compose.rs`; CI job
`federation`) with the same harness: it starts only `hub-a`, `hub-b` and `hub-c` with the
override `deploy/federation/compose.mh.yaml` (`GIM_HUB_UNHOSTED_GRACE_HOURS=1`,
`GIM_HUB_PUSH_FAILOVER_SECONDS=5`, `GIM_HUB_PUSH_LOG_ENDPOINT=true`) and observes pushes through
`GET /v2/debug/push-log`. `GIM_FED_SUITE=all` runs the federation suite and then the
multi-homing suite on a fresh stack with the same image. The run cannot advance the hubs'
clocks, so the purge after the grace period is covered by the in-process test
`crates/gim-hub-api/tests/multihoming_records.rs`, not by the compose suite.

### Push

Push design, webhook contract and payload: [`push.md`](push.md). The hub integrates no push
platform: every push for a registration whose provider is not `log` is POSTed, signed, to the push
server at `GIM_HUB_PUSH_WEBHOOK_URL`, which owns platform delivery and credentials. Without the URL
those pushes are logged as skipped. The `log` provider is always available. A URL without a valid
secret stops startup. Keep the secret out of the image (e.g. inject it from `/run/secrets`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIM_HUB_PUSH_MEMBER_EVENTS` | `false` | Also push `group.member_added` / `group.member_removed` (silent) |
| `GIM_HUB_PUSH_MINIMAL` | `false` | `true` sends minimal wake-up payloads `{"v":1,"type":"wake","collapse_id"}` only (no group, sequence or MLS message; see `push.md`) |
| `GIM_HUB_PUSH_QUEUE_CAPACITY` | `10000` | Most devices with a queued push; further pushes are dropped (minimum 1) |
| `GIM_HUB_PUSH_LOG_ENDPOINT` | `false` | Serve the unauthenticated, test-only `GET /v2/debug/push-log`; never enable in production |
| `GIM_HUB_PUSH_WEBHOOK_URL` | unset | `http` or `https` URL of the push server; every non-`log` push is POSTed there. Unset: those pushes are skipped |
| `GIM_HUB_PUSH_WEBHOOK_SECRET` | unset | HMAC-SHA256 key of `X-Gim-Signature`; required with the URL, at least 32 bytes |
| `GIM_HUB_PUSH_WEBHOOK_TIMEOUT_SECONDS` | `10` | Timeout of one webhook request; a timeout is retried (minimum 1) |

## Data directory

```
$GIM_HUB_DATA_DIR/
├── hub.db        SQLite database (WAL mode, with hub.db-wal and hub.db-shm)
├── hub_key       32-byte Ed25519 seed of the hub root key, mode 0600
├── backups/      Pre-migration database copies, `hub-<from_schema>-<version>.db`
└── blobs/        Encrypted blob contents, one file per blob: uploads and cached
                  copies of other hubs' blobs; `<hub_id>_b_<random>` (legacy
                  uploads: `b_<random>`); `.*.tmp` files are unfinished writes
```

- `hub.db` is created on first start; schema migrations are embedded in the
  binary and applied automatically (tracked in `PRAGMA user_version`).
- Before applying pending migrations to an existing database (schema above 0)
  the hub copies it with SQLite's online backup to
  `backups/hub-<from_schema>-<version>.db`: the schema it is migrating from
  and the release version doing it (see "Running under lode" for the
  version). Only the newest three `hub-*.db` files are kept; older ones are
  deleted after each new backup. A fresh database is not backed up. The
  directory is always under `GIM_HUB_DATA_DIR`, even with a custom
  `GIM_HUB_DATABASE_PATH`.
- A database with a newer schema than the binary knows is refused before
  anything is written to it: the hub exits non-zero with `database schema
  version N is newer than this binary supports (up to M); restore a backup or
  run a newer release`.
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

Blobs have no retention: uploaded blobs and the cached copies of other hubs'
blobs (fetched on first download with federation, `remote_blobs`) are kept
until the data directory is cleaned up by the operator. A cache eviction policy
for the copies is future work; an evicted copy would simply be fetched again
from its origin.

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

`scripts/docker-smoke.sh` builds the image and checks a running container, then
does the same for the mock push server (signed webhook 200, bad signature 401);
CI runs it on every push. `scripts/docker-build.sh IMAGE push-mock` builds
`Dockerfile.push-mock`.

Build notes:

- The builder caches only the cargo registry and git checkouts. `target/` is
  not cached: a BuildKit cache mount is shared by every checkout built on the
  same daemon, and cargo judges freshness by mtime, so a shared `target/` can
  yield a binary built from another checkout's sources. Docker's layer cache
  is keyed on the build context content and stays safe.
- `gim-hub version` prints `gim-hub <version> (<rev>)`: the release version
  (see "Running under lode") and the `GIM_HUB_BUILD_REV` build argument
  (`unknown` if unset). `scripts/docker-build.sh IMAGE`, used by
  `docker-smoke.sh` and `fed-test.sh`, passes the checkout's revision (with a
  `-dirty-<hash>` suffix for uncommitted changes to tracked files) and fails
  unless the built image reports exactly that revision.

## Running under lode

[lode](https://github.com/bkhq/lode) (v0.1.0) can supervise the hub: it
downloads and verifies signed release assets, runs the hub, commits a version
once the hub reports ready and rolls back to the last good version when a new
one fails. The hub implements the lode app contract only when `LODE_DIR` is
set; without it nothing changes.

- **Image and config.** `Dockerfile.lode` is a `debian:bookworm-slim` image
  with the lode binary (and `lode-cli`, the same binary) as `ENTRYPOINT`,
  running as the non-root `gimhub` user, with two volumes: `/srv/lode`
  (`LODE_DIR`: `lode.toml`, `versions/`, `state.json`) and `/data` (the hub
  data). Start from `deploy/lode/lode.toml`: put it at
  `/srv/lode/lode.toml`, replace the placeholder `[trust].trusted_keys` entry
  with the release public key and pick the `[update].asset` of the host
  architecture. `[update].policy = "check"` only records a newer release
  (`lode-cli status`); install it with `lode-cli update`, or set `"auto"`.

  ```bash
  docker build -t gim-hub-lode - < Dockerfile.lode
  docker run -d --name gim-hub --stop-timeout 40 -p 8080:8080 \
    -v gim-hub-lode:/srv/lode -v gim-hub-data:/data gim-hub-lode
  docker exec gim-hub lode-cli status
  ```

- **Environment.** lode injects `LODE_DIR`, `LODE_INSTANCE`,
  `LODE_ACTIVE_VERSION`, `LODE_READINESS`, `LODE_WORKDIR` and `LODE_CONFIG`.
  The `GIM_HUB_*` variables come from the container env or the `lode.toml`
  `[env]` table (defaults; the container env wins). Keep `GIM_HUB_DATA_DIR`
  outside `LODE_DIR`: lode replaces and prunes the version directories, and
  the hub's cwd is the version directory.
- **Readiness** (`[supervise].readiness = "state"`). After the migrations ran,
  the client API listener is bound and federation (if enabled) started, the
  hub sets `state.ready = $LODE_INSTANCE` in `$LODE_DIR/state.json` under
  `state.json.lock`, keeping lode's fields. A failure to write it is logged
  and the hub keeps serving; lode then rolls back after `ready_timeout`
  (60 s in the example). A version that exits within `health_grace` (15 s) is
  rolled back too.
- **Stop.** On SIGTERM the hub stops accepting connections, finishes
  in-flight requests and exits 0, well within `stop_timeout = 30`. Give the
  container a longer stop grace than that (`--stop-timeout 40`,
  `stop_grace_period: 40s`).
- **Version reporting.** `GET /healthz`, `GET /v2/hub` (`version`) and
  `gim-hub version` report `LODE_ACTIVE_VERSION` when supervised (the
  version lode installed, e.g. `0.2.1`), else the package version (`0.2.0`).
  `gim-hub version` adds the build revision: `gim-hub 0.2.1 (<rev>)`. The
  same version names the pre-migration backups.
- **Rollback and the database.** lode rolls back the binary, not the data.
  Only an older release whose schema is not behind the database can run on
  it: an older binary refuses a newer schema and exits non-zero, so lode
  reports the failure instead of serving on a migrated database. To go back
  to a release with an older schema, restore its backup:
  1. Stop the hub (`docker stop gim-hub`), or set `hold = true` in
     `state.json` so lode does not restart it.
  2. Pick the backup made when the newer release migrated the database:
     `backups/hub-<from_schema>-<version>.db` holds schema `<from_schema>`,
     the schema of the release before `<version>`.
  3. Move `hub.db`, `hub.db-wal` and `hub.db-shm` aside, then copy the backup
     to `hub.db` (owned by the hub user).
  4. Pin lode to the older release (`[update].pin`, or
     `lode-cli rollback --version <old>`) and start the hub again.

  Writes made after the backup are lost by a restore; prefer rolling forward
  with a fixed release when possible.
- **Releases.** `.github/workflows/release.yml` runs when a GitHub Release is
  published (tag `v*`) and uploads `gim-hub-linux-x86_64.tar.gz` and
  `gim-hub-linux-aarch64.tar.gz` (the archive root holds `gim-hub`; built on
  Debian bookworm, glibc 2.36). With the `LODE_SIGNING_KEY` secret set, each
  asset is signed with `lode-cli sign --app gim-hub --version <tag without v>`
  (lode-cli from the pinned, checksum-verified bkhq/lode v0.1.0 release) and
  uploaded with its `<asset>.sig`; without it the assets are uploaded
  unsigned, which `require_signature = "enforce"` rejects.
- **Smoke test.** `scripts/lode-smoke.sh` builds the hub and the image, serves
  a signed native manifest from a sibling container and checks a real install
  (with a pre-migration backup), an update, a rollback from a release that
  fails at startup and a graceful `docker stop`.

## Shutdown

The hub stops accepting connections on SIGINT or SIGTERM and finishes
in-flight requests before exiting.
