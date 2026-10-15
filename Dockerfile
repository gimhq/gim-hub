# syntax=docker/dockerfile:1

FROM rust:1.99-bookworm AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
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
EXPOSE 8080
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["gim-hub", "healthcheck"]
CMD ["gim-hub"]
