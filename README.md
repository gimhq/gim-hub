# gim-hub

Rust hub (MLS Delivery Service) for gim: client API (REST + WebSocket), self-certifying identity,
closed federation over libp2p, and multi-homing.

Plan: `docs/plan/20261015-1546-m2-identity-hub-federation.md` in the im-client workspace.
Design basis: cluster-architecture.md (hub model).

## Layout

- `crates/gim-hub-identity`: self-certifying identity types and verification (shared with gim-core).
- `crates/gim-hub-proto`: protobuf types generated from `proto/*.proto`.
- `crates/gim-hub-db`: SQLite storage.
- `crates/gim-hub-api`: client HTTP/WebSocket API v2.
- `crates/gim-hub-s2s`: hub-to-hub federation.
- `crates/gim-hub`: server binary (`GIM_HUB_LISTEN`, default `0.0.0.0:8080`; `GET /healthz`).

## Run

```bash
bash scripts/admin-ui.sh build          # writes admin-ui/dist, embedded by gim-hub-admin
cargo run -p gim-hub                    # listens on 0.0.0.0:8080, data in ./data
```

The admin UI must be built once before anything compiles `gim-hub-admin`: `cargo run -p
gim-hub`, `cargo build`, and `scripts/gen-openapi.sh`. Rebuild it after changing `admin-ui/`.
`scripts/check.sh`, `scripts/fed-test.sh` and the Docker builds build it themselves.

With Docker:

```bash
docker build -t gim-hub .
docker run -d --name gim-hub -p 8080:8080 -v gim-hub-data:/data gim-hub
curl http://127.0.0.1:8080/healthz
```

Configuration, the data directory and backups: `docs/operations.md`. To run
the hub under the [lode](https://github.com/bkhq/lode) supervisor (signed
updates with rollback; `Dockerfile.lode`, `deploy/lode/lode.toml`), see
"Running under lode" there.

## Checks

```bash
bash scripts/check.sh
```

Runs `cargo fmt`, `cargo clippy -D warnings` and `cargo test` (all `--locked`) in a
`rust:1.99-bookworm` container. CI runs the same commands natively.

```bash
bash scripts/docker-smoke.sh
```

Builds the image, starts a container and checks `/healthz`, the `gim-hub healthcheck`
subcommand, the `/data` layout and two unauthenticated `/v2` responses (see the script header for
the network/host variables).
