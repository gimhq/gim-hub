#!/usr/bin/env bash
# Closed-federation acceptance test (docs/federation.md §11.2): builds the hub
# image, starts deploy/federation/compose.yaml (hub-a, hub-b, hub-c allowing
# each other, hub-x allowed by nobody) with root keys generated for this run,
# and a mock push server (`push-mock`, docs/push-mock.md) receiving every
# hub's push webhook with a secret generated for this run, and runs the
# compose test driver (crates/gim-hub/tests/fed_compose.rs) in a
# rust container attached to the federation network. Hub logs are printed on
# failure; the stack is always torn down.
#
# GIM_FED_SUITE selects the driver: `fed` (default) as above; `mh` runs the
# multi-homing suite (docs/multihoming.md §11,
# crates/gim-hub/tests/multihoming_compose.rs) on hub-a, hub-b and hub-c with
# the override deploy/federation/compose.mh.yaml; `all` runs `fed`, then `mh`
# on a fresh stack with the same image.
#
# With GIM_FED_PSK=1 the override deploy/federation/compose.psk.yaml gives
# hub-a, hub-b and hub-c a generated pnet key and TCP-only addresses (T11);
# hub-x stays without a key. The script first checks that a hub with the key
# and a QUIC listen address refuses to start.
#
# Environment:
#   GIM_FED_IMAGE       hub image tag (default ai-agent/gim-hub:fedtest)
#   GIM_FED_PUSH_MOCK_IMAGE
#                       mock push server image tag
#                       (default ai-agent/gim-push-mock:fedtest)
#   GIM_FED_PROJECT     compose project name (default gim-fed)
#   GIM_FED_SUBNET      /24 prefix of the federation network (default 10.231.64)
#   GIM_FED_CARGO_HOME  cargo home mounted into the driver container
#                       (default /srv/.tmp/cache/cargo)
#   GIM_FED_SKIP_BUILD  1: reuse existing GIM_FED_IMAGE and GIM_FED_PUSH_MOCK_IMAGE
#   GIM_FED_TIMEOUT     driver timeout in seconds (default 420)
#   GIM_FED_PSK         1: run the PSK variant
#   GIM_FED_RUN_LABEL   value of the `ai-agent-run` label on every container,
#                       network and volume of the run (default GIM_FED_PROJECT)
#   GIM_FED_SUITE       fed (default), mh or all
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"

SUITE="${GIM_FED_SUITE:-fed}"
case "$SUITE" in
fed) TEST=fed_compose SERVICES=() ;;
mh) TEST=multihoming_compose SERVICES=(hub-a hub-b hub-c) ;;
all)
    GIM_FED_SUITE=fed bash "$0"
    GIM_FED_SUITE=mh GIM_FED_SKIP_BUILD=1 exec bash "$0"
    ;;
*)
    echo "fed-test: unknown GIM_FED_SUITE '$SUITE' (fed, mh, all)" >&2
    exit 2
    ;;
esac

IMAGE="${GIM_FED_IMAGE:-ai-agent/gim-hub:fedtest}"
MOCK_IMAGE="${GIM_FED_PUSH_MOCK_IMAGE:-ai-agent/gim-push-mock:fedtest}"
PROJECT="${GIM_FED_PROJECT:-gim-fed}"
SUBNET="${GIM_FED_SUBNET:-10.231.64}"
CARGO_CACHE="${GIM_FED_CARGO_HOME:-/srv/.tmp/cache/cargo}"
DRIVER_IMAGE="${CHECK_IMAGE:-rust:1.99-bookworm}"
PSK="${GIM_FED_PSK:-0}"
RUN_LABEL="${GIM_FED_RUN_LABEL:-$PROJECT}"
CONFIG_DIR="$ROOT/.tmp/fed-$$"
DRIVER="ai-agent-$PROJECT-driver-$$"
START=$(date +%s)

# Webhook secret shared by the hubs and push-mock, fresh for every run.
PUSH_SECRET="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
export GIM_FED_IMAGE="$IMAGE" GIM_FED_CONFIG_DIR="$CONFIG_DIR" GIM_FED_SUBNET="$SUBNET" \
    GIM_FED_RUN_LABEL="$RUN_LABEL" GIM_FED_PUSH_MOCK_IMAGE="$MOCK_IMAGE" \
    GIM_FED_PUSH_SECRET="$PUSH_SECRET"
COMPOSE_FILES=(-f deploy/federation/compose.yaml)
if [[ "$PSK" == "1" ]]; then
    COMPOSE_FILES+=(-f deploy/federation/compose.psk.yaml)
fi
if [[ "$SUITE" == "mh" ]]; then
    COMPOSE_FILES+=(-f deploy/federation/compose.mh.yaml)
fi
compose() {
    docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" "$@"
}

log() { echo "fed-test[$SUITE]: $*"; }

status=1
cleanup() {
    if [[ $status -ne 0 ]]; then
        log "FAIL; hub logs follow"
        compose logs --no-color --tail 300 >&2 || true
    fi
    docker rm -f "$DRIVER" >/dev/null 2>&1 || true
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$CONFIG_DIR"
    log "torn down after $(($(date +%s) - START))s"
}
trap cleanup EXIT

if [[ "${GIM_FED_SKIP_BUILD:-}" != "1" ]]; then
    log "building $IMAGE"
    bash scripts/docker-build.sh "$IMAGE"
    log "building $MOCK_IMAGE"
    bash scripts/docker-build.sh "$MOCK_IMAGE" push-mock
fi

# Leftovers of an interrupted run.
compose down -v --remove-orphans >/dev/null 2>&1 || true

# Files must exist before compose bind-mounts them.
mkdir -p "$CONFIG_DIR"
: >"$CONFIG_DIR/allowlist"
: >"$CONFIG_DIR/allowlist-x"
if [[ "$PSK" == "1" ]]; then
    {
        echo "/key/swarm/psk/1.0.0/"
        echo "/base16/"
        od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
        echo
    } >"$CONFIG_DIR/swarm.key"
    chmod 0644 "$CONFIG_DIR/swarm.key"
    log "PSK variant: hub-a, hub-b, hub-c share a generated pnet key, TCP only"
fi
chmod 0755 "$CONFIG_DIR"

# Fresh root keys: `gim-hub hub-id` creates hub_key in the hub's volume and
# prints its hub_id.
declare -A HUB_ID
for hub in a b c x; do
    HUB_ID[$hub]="$(compose run --rm --no-deps -T "hub-$hub" gim-hub hub-id | tr -d '\r\n')"
    log "hub-$hub hub_id ${HUB_ID[$hub]}"
done

addrs() {
    if [[ "$PSK" == "1" ]]; then
        echo "/ip4/$SUBNET.$1/tcp/4001"
    else
        echo "/ip4/$SUBNET.$1/tcp/4001 /ip4/$SUBNET.$1/udp/4001/quic-v1"
    fi
}
{
    echo "# generated by scripts/fed-test.sh"
    echo "${HUB_ID[a]} $(addrs 11)"
    echo "${HUB_ID[b]} $(addrs 12)"
    echo "${HUB_ID[c]} $(addrs 13)"
} >"$CONFIG_DIR/allowlist"
{
    echo "# generated by scripts/fed-test.sh: hub-x tries hub-a, which refuses it"
    echo "${HUB_ID[a]} /ip4/$SUBNET.11/tcp/4001 /ip4/$SUBNET.11/udp/4001/quic-v1"
} >"$CONFIG_DIR/allowlist-x"
chmod 0644 "$CONFIG_DIR"/allowlist*

if [[ "$PSK" == "1" ]]; then
    # A QUIC listen address together with the PSK is a startup error.
    set +e
    out="$(timeout 60 docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" run --rm --no-deps -T \
        -e GIM_HUB_P2P_LISTEN=/ip4/0.0.0.0/udp/4001/quic-v1,/ip4/0.0.0.0/tcp/4001 hub-a gim-hub 2>&1)"
    code=$?
    set -e
    if [[ $code -eq 0 || $code -eq 124 || "$out" != *"QUIC is not available with GIM_HUB_P2P_PSK_FILE"* ]]; then
        log "FAIL: hub-a with a PSK and a QUIC listen address did not refuse to start (exit $code)"
        echo "$out" >&2
        exit 1
    fi
    log "ok   hub with a PSK and a QUIC listen address refuses to start"
fi

log "starting hubs"
compose up -d --wait --wait-timeout 120 "${SERVICES[@]}"

mkdir -p "$CARGO_CACHE"
log "running the driver"
timeout "${GIM_FED_TIMEOUT:-420}" docker run --rm --label ai-agent=true \
    --label ai-agent-run="$RUN_LABEL" --name "$DRIVER" \
    --network "${PROJECT}_fed" \
    -v "$ROOT:$ROOT" -w "$ROOT" \
    -v "$CARGO_CACHE:/cache/cargo" -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR="$ROOT/target" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e GIM_FED_PROJECT="$PROJECT" \
    -e GIM_FED_PSK="$PSK" \
    -e GIM_FED_HUB_A=http://hub-a:8080 \
    -e GIM_FED_HUB_B=http://hub-b:8080 \
    -e GIM_FED_HUB_C=http://hub-c:8080 \
    -e GIM_FED_HUB_X=http://hub-x:8080 \
    -e GIM_FED_HUB_X_ID="${HUB_ID[x]}" \
    -e GIM_FED_HUB_B_ID="${HUB_ID[b]}" \
    -e GIM_FED_PUSH_MOCK=http://push-mock:8090 \
    "$DRIVER_IMAGE" \
    cargo test -p gim-hub --locked --test "$TEST" -- --ignored --nocapture --test-threads 1

status=0
log "PASS in $(($(date +%s) - START))s"
