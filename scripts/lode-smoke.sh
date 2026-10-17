#!/usr/bin/env bash
# End-to-end smoke of gim-hub under lode v0.1.0 (Dockerfile.lode,
# deploy/lode/lode.toml; docs/operations.md "Running under lode").
#
# Builds the hub release binary in rust:1.99-bookworm and the Dockerfile.lode
# image, then runs the real lode fetch + verify + install path against a
# native manifest served over http by a sibling container on a per-run
# network, signed with a throwaway key generated here (never printed):
#
#   a. install 0.2.0 over a seeded schema-(N-1) database -> ready, pre-migration
#      backup taken, data written
#   b. publish 0.2.1 (same binary) -> update -> ready on 0.2.1, data kept
#   c. publish a broken 0.2.2 (exits 3 at startup) -> update -> lode rolls
#      back to 0.2.1, data kept
#   d. docker stop -t 30 -> clean exit, time printed
#
# Requires docker, jq and sqlite3. Every container, network and image carries
# --label ai-agent=true --label ai-agent-run=<run>; cleanup removes only those.
#
# Environment:
#   LODE_SMOKE_RUN   run id (default lode-smoke-<pid>)
#   LODE_SMOKE_KEEP  set to 1 to keep containers and the work dir on exit
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"

RUN="${LODE_SMOKE_RUN:-lode-smoke-$$}"
LABELS=(--label ai-agent=true --label "ai-agent-run=$RUN")
WORK="$ROOT/.tmp/$RUN"
NET="ai-agent-$RUN"
FILES="ai-agent-$RUN-files"
LODE="ai-agent-$RUN-lode"
IMAGE="ai-agent/gim-hub-lode:$RUN"
ASSET="gim-hub-linux-x86_64.tar.gz"
BUSYBOX="busybox:1.37"
STATE="$WORK/lode/state.json"

for tool in docker jq sqlite3; do
    command -v "$tool" >/dev/null || { echo "lode-smoke: $tool is required" >&2; exit 2; }
done

cleanup() {
    local code=$?
    if [[ "${LODE_SMOKE_KEEP:-}" == "1" ]]; then
        echo "lode-smoke: kept run $RUN ($WORK)"
        return
    fi
    docker ps -aq --filter "label=ai-agent-run=$RUN" | xargs -r docker rm -f >/dev/null
    docker network ls -q --filter "label=ai-agent-run=$RUN" | xargs -r docker network rm >/dev/null
    docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
    if [[ -d "$WORK" ]] && ! rm -rf "$WORK" 2>/dev/null; then
        # Files written by the image's non-root user.
        docker run --rm "${LABELS[@]}" --user 0 -v "$WORK:$WORK" "$BUSYBOX" rm -rf "$WORK/lode" "$WORK/data" "$WORK/files" "$WORK/keys"
        rm -rf "$WORK"
    fi
    exit "$code"
}
trap cleanup EXIT

pass() { echo "lode-smoke: PASS $*"; }
fail() {
    echo "lode-smoke: FAIL $*" >&2
    if docker inspect "$LODE" >/dev/null 2>&1; then
        docker logs --tail 80 "$LODE" >&2 || true
    fi
    [[ -f "$STATE" ]] && jq . "$STATE" >&2
    exit 1
}

# wait_for SECONDS DESCRIPTION COMMAND...: retries COMMAND every second.
wait_for() {
    local seconds="$1" what="$2"
    shift 2
    for _ in $(seq 1 "$seconds"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "$what (not within ${seconds}s)"
}

state() { jq -r "$1" "$STATE" 2>/dev/null; }
lode_cli() { docker exec "$LODE" lode-cli "$@"; }
hub_get() { docker run --rm "${LABELS[@]}" --network "$NET" "$BUSYBOX" wget -qO- -T 5 "http://$LODE:8080$1"; }
hub_version() { hub_get /v2/hub | jq -r .version; }
hub_id() { hub_get /v2/hub | jq -r .hub_id; }
meta() { sqlite3 "$WORK/data/hub.db" "SELECT value FROM meta WHERE key = '$1'"; }

serving() {
    local version="$1"
    [[ "$(state .status)" == running && "$(state .current)" == "$version" ]] || return 1
    [[ "$(state '.ready // empty')" != "" ]] || return 1
    [[ "$(hub_version)" == "$version" ]]
}

# publish VERSION DIR: packages DIR/gim-hub as the VERSION asset and signs it
# into the manifest, which points the stable channel at VERSION.
publish() {
    local version="$1" dir="$2"
    mkdir -p "$WORK/files/$version"
    tar -C "$dir" -czf "$WORK/files/$version/$ASSET" gim-hub
    chmod -R a+rX "$WORK/files"
    docker run --rm "${LABELS[@]}" -v "$WORK:$WORK" --user 0 --entrypoint lode-cli "$IMAGE" \
        manifest "$WORK/files/$version/$ASSET" --app gim-hub --version "$version" \
        --channel stable --url "http://$FILES:8000/$version/$ASSET" \
        --key "$WORK/keys/smoke.key" --into "$WORK/files/manifest.json" >/dev/null
    chmod a+r "$WORK/files/manifest.json"
}

mkdir -p "$WORK"/{keys,files,lode,data,bin/good,bin/broken}
chmod 777 "$WORK/lode" "$WORK/data"

# --- build -------------------------------------------------------------------
rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
mkdir -p /srv/.tmp/cache/cargo
echo "lode-smoke: building gim-hub (release, rust:1.99-bookworm)"
docker run --rm "${LABELS[@]}" --name "ai-agent-$RUN-build" \
    -v "$ROOT:$ROOT" -w "$ROOT" \
    -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR="$ROOT/target" -e GIM_HUB_BUILD_REV="$rev" \
    rust:1.99-bookworm cargo build --release --locked -q -p gim-hub
cp target/release/gim-hub "$WORK/bin/good/gim-hub"
printf '#!/bin/sh\necho "gim-hub: deliberately broken release" >&2\nexit 3\n' >"$WORK/bin/broken/gim-hub"
chmod 755 "$WORK/bin/good/gim-hub" "$WORK/bin/broken/gim-hub"
pass "build gim-hub ($("$WORK/bin/good/gim-hub" version))"

echo "lode-smoke: building $IMAGE"
docker build -q --label ai-agent=true --label "ai-agent-run=$RUN" -t "$IMAGE" - <Dockerfile.lode >/dev/null
[[ "$(docker run --rm "${LABELS[@]}" --entrypoint id "$IMAGE" -u)" != 0 ]] || fail "image runs as root"
docker run --rm "${LABELS[@]}" --entrypoint lode-cli "$IMAGE" --help >/dev/null || fail "lode-cli missing"
pass "build Dockerfile.lode (non-root, lode + lode-cli)"

# --- source: throwaway key, manifest server, lode.toml ------------------------
docker run --rm "${LABELS[@]}" -v "$WORK:$WORK" --user 0 --entrypoint lode-cli "$IMAGE" \
    keygen --out "$WORK/keys/smoke" >/dev/null
trusted="$(tr ' ' ':' <"$WORK/keys/smoke.pub")"
docker network create "${LABELS[@]}" "$NET" >/dev/null
docker run -d "${LABELS[@]}" --name "$FILES" --network "$NET" \
    -v "$WORK/files:/srv:ro" "$BUSYBOX" httpd -f -p 8000 -h /srv >/dev/null

# The shipped example, pointed at the local manifest and the throwaway key.
sed -e "s|^github .*|manifest = \"http://$FILES:8000/manifest.json\"|" \
    -e "s|^trusted_keys .*|trusted_keys = [\"$trusted\"]|" \
    deploy/lode/lode.toml >"$WORK/lode/lode.toml"
printf '\n[http]\nallow_insecure = true   # the local http manifest server\n' >>"$WORK/lode/lode.toml"
grep -q "^manifest = " "$WORK/lode/lode.toml" && grep -q '^require_signature = "enforce"' "$WORK/lode/lode.toml" ||
    fail "lode.toml rewrite"

# An existing install one schema step behind, with a row of data.
schema="$(grep -c 'include_str!("../migrations/' crates/gim-hub-db/src/migrate.rs)"
from=$((schema - 1))
for sql in $(ls crates/gim-hub-db/migrations/*.sql | head -n "$from"); do
    sqlite3 "$WORK/data/hub.db" <"$sql"
done
sqlite3 "$WORK/data/hub.db" "PRAGMA user_version = $from; INSERT INTO meta (key, value) VALUES ('smoke-seed', '$RUN');"
chmod 666 "$WORK/data/hub.db"

# --- a. install 0.2.0 ---------------------------------------------------------
publish 0.2.0 "$WORK/bin/good"
docker run -d "${LABELS[@]}" --name "$LODE" --network "$NET" \
    -v "$WORK/lode:/srv/lode" -v "$WORK/data:/data" "$IMAGE" >/dev/null
wait_for 90 "a: 0.2.0 running and ready" serving 0.2.0
[[ -f "$WORK/data/backups/hub-$from-0.2.0.db" ]] || fail "a: backup hub-$from-0.2.0.db missing: $(ls "$WORK/data/backups" 2>&1)"
[[ "$(sqlite3 "$WORK/data/backups/hub-$from-0.2.0.db" 'PRAGMA user_version')" == "$from" ]] || fail "a: backup schema"
[[ "$(sqlite3 "$WORK/data/hub.db" 'PRAGMA user_version')" == "$schema" ]] || fail "a: schema not migrated"
[[ ! -e "$WORK/lode/versions/0.2.0/hub.db" ]] || fail "a: data written into LODE_DIR"
sqlite3 "$WORK/data/hub.db" "INSERT INTO meta (key, value) VALUES ('smoke-0.2.0', '$RUN');"
HUB_ID="$(hub_id)"
pass "a: install 0.2.0 (signed, fetched + verified) -> status=$(state .status) current=$(state .current) ready=$(state .ready) version=$(hub_version); backup backups/hub-$from-0.2.0.db; data written"

# --- b. update to 0.2.1 -------------------------------------------------------
publish 0.2.1 "$WORK/bin/good"
lode_cli update --version 0.2.1 >/dev/null
wait_for 90 "b: 0.2.1 running and ready" serving 0.2.1
wait_for 30 "b: 0.2.1 committed as last_good" test "$(state .last_good)" == 0.2.1
[[ "$(hub_id)" == "$HUB_ID" ]] || fail "b: hub identity changed"
[[ "$(meta smoke-seed)" == "$RUN" && "$(meta smoke-0.2.0)" == "$RUN" ]] || fail "b: data lost"
[[ "$(ls "$WORK/data/backups")" == "hub-$from-0.2.0.db" ]] || fail "b: unexpected backups: $(ls "$WORK/data/backups")"
pass "b: update 0.2.0 -> 0.2.1 -> current=$(state .current) last_good=$(state .last_good) version=$(hub_version); data kept; no backup (schema current)"

# --- c. broken 0.2.2 rolls back -----------------------------------------------
publish 0.2.2 "$WORK/bin/broken"
lode_cli update --version 0.2.2 >/dev/null || true
rolled_back() {
    [[ "$(state '[.history[]? | select(.version == "0.2.2" and .result == "bad")] | length')" -ge 1 ]] &&
        serving 0.2.1
}
wait_for 120 "c: rollback from 0.2.2 to 0.2.1" rolled_back
[[ "$(state .last_good)" == 0.2.1 ]] || fail "c: last_good $(state .last_good)"
[[ "$(hub_id)" == "$HUB_ID" ]] || fail "c: hub identity changed"
[[ "$(meta smoke-seed)" == "$RUN" && "$(meta smoke-0.2.0)" == "$RUN" ]] || fail "c: data lost"
[[ "$(ls "$WORK/data/backups")" == "hub-$from-0.2.0.db" ]] || fail "c: unexpected backups: $(ls "$WORK/data/backups")"
pass "c: broken 0.2.2 -> rolled back: current=$(state .current) last_good=$(state .last_good) version=$(hub_version); data kept; backups: $(ls "$WORK/data/backups")"

# --- d. graceful stop ---------------------------------------------------------
start=$(date +%s%N)
docker stop -t 30 "$LODE" >/dev/null
elapsed_ms=$((($(date +%s%N) - start) / 1000000))
code="$(docker inspect -f '{{.State.ExitCode}}' "$LODE")"
docker logs "$LODE" 2>&1 | grep -q "gim-hub stopped" || fail "d: hub did not log a graceful stop"
[[ "$code" == 0 ]] || fail "d: lode exited $code"
((elapsed_ms < 30000)) || fail "d: stop took ${elapsed_ms}ms"
pass "d: docker stop -t 30 -> exit $code in ${elapsed_ms}ms (hub logged 'gim-hub stopped')"

echo "lode-smoke: all steps passed (run $RUN)"
