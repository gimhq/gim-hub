#!/usr/bin/env bash
# Build the gim-hub image, start a container and check it serves the API.
#
# Environment:
#   GIM_HUB_SMOKE_IMAGE    image tag (default ai-agent/gim-hub:smoke)
#   GIM_HUB_SMOKE_NETWORK  docker network to attach the container to (e.g.
#                          traefik); the hub is then reached by container name.
#                          Unset: a random port is published on 127.0.0.1.
#   GIM_HUB_SMOKE_HOST     host that reaches the published port (default
#                          127.0.0.1).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE="${GIM_HUB_SMOKE_IMAGE:-ai-agent/gim-hub:smoke}"
NETWORK="${GIM_HUB_SMOKE_NETWORK:-}"
NAME="ai-agent-gim-hub-smoke-$$"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "smoke: FAIL: $*" >&2
    docker logs "$NAME" >&2 || true
    exit 1
}

echo "smoke: building $IMAGE"
bash scripts/docker-build.sh "$IMAGE"

if [[ -n "$NETWORK" ]]; then
    docker run --rm -d --label ai-agent=true --name "$NAME" --network "$NETWORK" "$IMAGE" >/dev/null
    BASE="http://$NAME:8080"
else
    docker run --rm -d --label ai-agent=true --name "$NAME" -p 127.0.0.1::8080 "$IMAGE" >/dev/null
    PORT="$(docker port "$NAME" 8080/tcp | head -1 | sed 's/.*://')"
    BASE="http://${GIM_HUB_SMOKE_HOST:-127.0.0.1}:$PORT"
fi
echo "smoke: container $NAME at $BASE"

# get PATH -> prints "<status> <body>"
get() {
    curl -sS --max-time 5 -o /tmp/gim-hub-smoke-$$.body -w '%{http_code}' "$BASE$1" || true
    echo " $(cat /tmp/gim-hub-smoke-$$.body 2>/dev/null)"
    rm -f /tmp/gim-hub-smoke-$$.body
}

healthy=""
for _ in $(seq 1 30); do
    if [[ "$(get /healthz)" == "200 "* ]]; then
        healthy=1
        break
    fi
    sleep 1
done
[[ -n "$healthy" ]] || fail "/healthz did not return 200 within 30s"

health="$(get /healthz)"
[[ "$(jq -r .status <<<"${health#* }")" == "ok" ]] || fail "/healthz: $health"
echo "smoke: ok   GET /healthz -> $health"

docker exec "$NAME" gim-hub healthcheck || fail "gim-hub healthcheck exited non-zero"
echo "smoke: ok   gim-hub healthcheck"

uid="$(docker exec "$NAME" id -u)"
[[ "$uid" != "0" ]] || fail "container runs as root"
docker exec "$NAME" test -s /data/hub_key || fail "/data/hub_key missing"
docker exec "$NAME" test -s /data/hub.db || fail "/data/hub.db missing"
echo "smoke: ok   non-root (uid $uid), /data initialised"

rand="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# Unauthenticated, unknown link ID -> 404 not_found.
resp="$(get "/v2/link-bundles/$rand")"
[[ "$resp" == "404 "* && "$(jq -r .error.code <<<"${resp#* }")" == "not_found" ]] \
    || fail "GET /v2/link-bundles/<random>: $resp"
echo "smoke: ok   GET /v2/link-bundles/<random> -> $resp"

# Bearer-protected route without a token -> 401 unauthorized.
resp="$(get "/v2/users/u$rand")"
[[ "$resp" == "401 "* && "$(jq -r .error.code <<<"${resp#* }")" == "unauthorized" ]] \
    || fail "GET /v2/users/<random> without token: $resp"
echo "smoke: ok   GET /v2/users/<random> (no token) -> $resp"

echo "smoke: PASS"
