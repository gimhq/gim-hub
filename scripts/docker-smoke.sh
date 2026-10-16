#!/usr/bin/env bash
# Build the gim-hub image, start a container and check it serves the API;
# then the same for the mock push server (docs/push-mock.md), including one
# signed webhook (200) and one with a bad signature (401).
#
# Environment:
#   GIM_HUB_SMOKE_IMAGE    image tag (default ai-agent/gim-hub:smoke)
#   GIM_HUB_SMOKE_MOCK_IMAGE
#                          mock image tag (default ai-agent/gim-push-mock:smoke)
#   GIM_HUB_SMOKE_RUN_LABEL
#                          value of the `ai-agent-run` label on the containers
#                          (default gim-hub-smoke)
#   GIM_HUB_SMOKE_NETWORK  docker network to attach the container to (e.g.
#                          traefik); the hub is then reached by container name.
#                          Unset: a random port is published on 127.0.0.1.
#   GIM_HUB_SMOKE_HOST     host that reaches the published port (default
#                          127.0.0.1).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE="${GIM_HUB_SMOKE_IMAGE:-ai-agent/gim-hub:smoke}"
NETWORK="${GIM_HUB_SMOKE_NETWORK:-}"
MOCK_IMAGE="${GIM_HUB_SMOKE_MOCK_IMAGE:-ai-agent/gim-push-mock:smoke}"
RUN_LABEL="${GIM_HUB_SMOKE_RUN_LABEL:-gim-hub-smoke}"
NAME="ai-agent-gim-hub-smoke-$$"
MOCK_NAME="ai-agent-gim-push-mock-smoke-$$"
LABELS=(--label ai-agent=true --label ai-agent-run="$RUN_LABEL")

cleanup() {
    docker rm -f "$NAME" "$MOCK_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "smoke: FAIL: $*" >&2
    docker logs "$NAME" >&2 || true
    docker logs "$MOCK_NAME" >&2 || true
    exit 1
}

echo "smoke: building $IMAGE"
bash scripts/docker-build.sh "$IMAGE"

if [[ -n "$NETWORK" ]]; then
    docker run --rm -d "${LABELS[@]}" --name "$NAME" --network "$NETWORK" "$IMAGE" >/dev/null
    BASE="http://$NAME:8080"
else
    docker run --rm -d "${LABELS[@]}" --name "$NAME" -p 127.0.0.1::8080 "$IMAGE" >/dev/null
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

# Public user read, unknown user, no token -> 404 not_found.
resp="$(get "/v2/users/u$rand")"
[[ "$resp" == "404 "* && "$(jq -r .error.code <<<"${resp#* }")" == "not_found" ]] \
    || fail "GET /v2/users/<random> without token: $resp"
echo "smoke: ok   GET /v2/users/<random> (no token) -> $resp"

# Bearer-protected route without a token -> 401 unauthorized.
resp="$(get /v2/me)"
[[ "$resp" == "401 "* && "$(jq -r .error.code <<<"${resp#* }")" == "unauthorized" ]] \
    || fail "GET /v2/me without token: $resp"
echo "smoke: ok   GET /v2/me (no token) -> $resp"

echo "smoke: building $MOCK_IMAGE"
bash scripts/docker-build.sh "$MOCK_IMAGE" push-mock

SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
if [[ -n "$NETWORK" ]]; then
    docker run --rm -d "${LABELS[@]}" --name "$MOCK_NAME" --network "$NETWORK" \
        -e GIM_PUSH_MOCK_SECRET="$SECRET" "$MOCK_IMAGE" >/dev/null
    BASE="http://$MOCK_NAME:8090"
else
    docker run --rm -d "${LABELS[@]}" --name "$MOCK_NAME" -p 127.0.0.1::8090 \
        -e GIM_PUSH_MOCK_SECRET="$SECRET" "$MOCK_IMAGE" >/dev/null
    PORT="$(docker port "$MOCK_NAME" 8090/tcp | head -1 | sed 's/.*://')"
    BASE="http://${GIM_HUB_SMOKE_HOST:-127.0.0.1}:$PORT"
fi
echo "smoke: mock $MOCK_NAME at $BASE"

healthy=""
for _ in $(seq 1 30); do
    if [[ "$(get /healthz)" == "200 "* ]]; then
        healthy=1
        break
    fi
    sleep 1
done
[[ -n "$healthy" ]] || fail "mock /healthz did not return 200 within 30s"
echo "smoke: ok   mock GET /healthz -> $(get /healthz)"

docker exec "$MOCK_NAME" gim-push-mock healthcheck || fail "gim-push-mock healthcheck exited non-zero"
uid="$(docker exec "$MOCK_NAME" id -u)"
[[ "$uid" != "0" ]] || fail "mock container runs as root"
echo "smoke: ok   gim-push-mock healthcheck, non-root (uid $uid)"

# post_push BODY SIGNATURE -> prints the status code
post_push() {
    curl -sS --max-time 5 -o /dev/null -w '%{http_code}' -X POST \
        -H 'content-type: application/json' -H "X-Gim-Delivery: smoke-$rand" \
        -H "X-Gim-Signature: $2" --data-binary "$1" "$BASE/push" || true
}
body="{\"v\":1,\"hub_id\":\"smoke\",\"delivery_id\":\"smoke-$rand\",\"sent_at\":0,\"registration\":{\"provider\":\"mock-android\",\"token\":\"t-$rand\"},\"priority\":\"high\",\"collapse_id\":\"c\",\"ttl\":86400,\"payload\":{\"v\":1,\"type\":\"wake\",\"collapse_id\":\"c\"}}"
t="$(date +%s)"
mac="$(printf '%s.%s' "$t" "$body" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/.*= //')"

code="$(post_push "$body" "t=$t,v1=$(tr 0-9a-f 1-9a-f0 <<<"$mac")")"
[[ "$code" == "401" ]] || fail "POST /push with a bad signature: $code"
echo "smoke: ok   POST /push (bad signature) -> $code"

code="$(post_push "$body" "t=$t,v1=$mac")"
[[ "$code" == "200" ]] || fail "POST /push signed: $code"
resp="$(get "/deliveries?token=t-$rand")"
[[ "$(jq -r '.deliveries | length' <<<"${resp#* }")" == "1" ]] || fail "GET /deliveries: $resp"
echo "smoke: ok   POST /push (signed) -> $code, recorded"

echo "smoke: PASS"
