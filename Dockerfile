# syntax=docker/dockerfile:1

# The admin UI (admin-ui/, docs/admin.md), embedded into the binary by
# crates/gim-hub-admin/build.rs. .dockerignore excludes admin-ui/dist and
# node_modules, so the image always builds the UI from source.
FROM oven/bun:1.4.3 AS ui
WORKDIR /src/admin-ui
COPY admin-ui/package.json admin-ui/bun.lock ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY admin-ui/ ./
RUN bun run build

FROM rust:1.99-bookworm AS builder
WORKDIR /src
COPY . .
COPY --from=ui /src/admin-ui/dist admin-ui/dist
# Embedded in the binary and printed by `gim-hub version`; scripts/docker-build.sh
# passes the checkout's revision and verifies it after the build.
ARG GIM_HUB_BUILD_REV=unknown
# No cache mount for /src/target: the BuildKit cache is shared by every checkout
# built on the daemon and cargo judges freshness by mtime, so artifacts from
# another checkout could be reused. The build always starts from a clean target.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --release --locked -p gim-hub \
    && install -D target/release/gim-hub /out/gim-hub

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin gimhub \
    && mkdir -p /data \
    && chown gimhub:gimhub /data
COPY --from=builder /out/gim-hub /usr/local/bin/gim-hub
ENV GIM_HUB_LISTEN=0.0.0.0:8080 \
    GIM_HUB_DATA_DIR=/data
USER gimhub
# 8080: client API; 4001 tcp/udp: federation (libp2p TCP and QUIC).
EXPOSE 8080 4001/tcp 4001/udp
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["gim-hub", "healthcheck"]
CMD ["gim-hub"]
