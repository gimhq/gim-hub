#!/usr/bin/env bash
# Browser E2E of the admin UI (docs/admin.md, "Browser E2E").
#
# Builds the admin UI and the hub release binary (which embeds it), seeds a
# hub data dir, starts the hub with the admin listener, federation and a fake
# lode state.json, and drives the UI with Playwright (admin-ui/e2e/) in the
# pinned mcr.microsoft.com/playwright image:
#
#   1. login with the token
#   2. search the seeded user and open the detail
#   3. revoke the device's sessions (UI, API and database)
#   4. add a second fake hub to the allowlist (source stored; API and the table)
#   5. lode "check now" (state.json check_nonce bumped, lode's fields intact)
#   6. audit entries for the revoke, allowlist_update and lode_check
#   7. GET <client listener>/admin/ is 404
#   8. edit the live setting GIM_HUB_EVENT_RETENTION_DAYS on the Settings page
#      (GET item source stored, overview retention, settings table, audit)
#   9. GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN set in the hub's env is read-only in
#      the UI and PUT answers 409
#
# The user, device and session are seeded with sqlite3 into a database built
# from the migrations: a real sign-in needs a signed DeviceList made by the
# Rust identity helpers, while the admin API only reads these rows.
#
# Requires docker, jq, sqlite3 and base32. Every container and network carries
# --label ai-agent=true --label ai-agent-run=<run>; cleanup removes only those.
#
# Environment:
#   ADMIN_E2E_RUN    run id (default admin-e2e-<pid>)
#   ADMIN_E2E_KEEP   set to 1 to keep containers and the work dir on exit
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"

RUN="${ADMIN_E2E_RUN:-admin-e2e-$$}"
LABELS=(--label ai-agent=true --label "ai-agent-run=$RUN")
WORK="$ROOT/.tmp/$RUN"
NET="ai-agent-$RUN"
HUB="ai-agent-$RUN-hub"
# Keep in sync with @playwright/test in admin-ui/package.json.
PLAYWRIGHT_IMAGE="mcr.microsoft.com/playwright:v1.63.0-noble"
RUNTIME_IMAGE="debian:bookworm-slim"
BUSYBOX="busybox:1.37"
STATE="$WORK/lode/state.json"
DB="$WORK/data/hub.db"
# Step 8 edits RETENTION_KEY (default 7) to RETENTION_DAYS; step 9 checks ENV_KEY.
RETENTION_KEY=GIM_HUB_EVENT_RETENTION_DAYS
RETENTION_DAYS=30
ENV_KEY=GIM_HUB_PUBLIC_READ_PER_IP_PER_MIN
ENV_VALUE=77

for tool in docker jq sqlite3 base32; do
    command -v "$tool" >/dev/null || { echo "admin-e2e: $tool is required" >&2; exit 2; }
done
want_pw="$(jq -r '.devDependencies["@playwright/test"]' admin-ui/package.json)"
[[ "$PLAYWRIGHT_IMAGE" == *":v$want_pw-"* ]] ||
    { echo "admin-e2e: $PLAYWRIGHT_IMAGE does not match @playwright/test $want_pw" >&2; exit 2; }

cleanup() {
    local code=$?
    if [[ "${ADMIN_E2E_KEEP:-}" == "1" ]]; then
        echo "admin-e2e: kept run $RUN ($WORK)"
        return
    fi
    docker ps -aq --filter "label=ai-agent-run=$RUN" | xargs -r docker rm -f >/dev/null
    docker network ls -q --filter "label=ai-agent-run=$RUN" | xargs -r docker network rm >/dev/null
    rm -rf "$WORK"
    exit "$code"
}
trap cleanup EXIT

pass() { echo "admin-e2e: ok   $*"; }
fail() {
    echo "admin-e2e: FAIL $*" >&2
    docker logs --tail 80 "$HUB" >&2 2>&1 || true
    exit 1
}

# id PREFIX BYTES: PREFIX || base32(BYTES) in the hub's id encoding.
id() { base32 -w0 | tr -d '=' | tr 'A-Z' 'a-z' | sed "s/^/$1/"; }
# multihash_id PREFIX: a random SHA-256 multihash id (user or hub ID).
multihash_id() { { printf '\x12\x20'; head -c 32 /dev/urandom; } | id "$1"; }
hub_get() { docker run --rm "${LABELS[@]}" --network "$NET" "$BUSYBOX" wget -qO- -T 5 "http://$HUB:$1$2"; }

mkdir -p "$WORK"/{bin,data,lode,results}

# --- build -------------------------------------------------------------------
echo "admin-e2e: building the admin UI"
bash scripts/admin-ui.sh build >/dev/null
rev="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
mkdir -p /srv/.tmp/cache/cargo
echo "admin-e2e: building gim-hub (release, rust:1.99-bookworm)"
docker run --rm "${LABELS[@]}" --name "ai-agent-$RUN-build" \
    -v "$ROOT:$ROOT" -w "$ROOT" \
    -v /srv/.tmp/cache/cargo:/cache/cargo -e CARGO_HOME=/cache/cargo \
    -e CARGO_TARGET_DIR="$ROOT/target" -e GIM_HUB_BUILD_REV="$rev" \
    rust:1.99-bookworm cargo build --release --locked -q -p gim-hub
cp target/release/gim-hub "$WORK/bin/gim-hub"
pass "build: $("$WORK/bin/gim-hub" version), admin UI embedded"

# --- seed --------------------------------------------------------------------
schema="$(grep -c 'include_str!("../migrations/' crates/gim-hub-db/src/migrate.rs)"
for sql in crates/gim-hub-db/migrations/*.sql; do
    sqlite3 "$DB" <"$sql"
done
USER_ID="$(multihash_id u)"
DEVICE_ID="$(head -c 16 /dev/urandom | id d)"
HANDLE="e2e$(od -An -tx1 -N3 /dev/urandom | tr -d ' \n')"
SESSION_HASH="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SESSION_REF="$(printf '%s' "$SESSION_HASH" | cut -c1-16)"
now_ms="$(($(date +%s) * 1000))"
sqlite3 "$DB" <<SQL
PRAGMA user_version = $schema;
INSERT INTO users (user_id, root_pubkey, device_list, device_list_seq, created_at, updated_at)
    VALUES ('$USER_ID', zeroblob(32), x'00', 1, $now_ms, $now_ms);
INSERT INTO devices (user_id, device_id, sig_pubkey, active, updated_at, created_at)
    VALUES ('$USER_ID', '$DEVICE_ID', zeroblob(32), 1, $now_ms, $now_ms);
INSERT INTO handles (handle, user_id, created_at) VALUES ('$HANDLE', '$USER_ID', $now_ms);
INSERT INTO sessions (token_hash, user_id, device_id, created_at, expires_at)
    VALUES (x'$SESSION_HASH', '$USER_ID', '$DEVICE_ID', $now_ms, $((now_ms + 86400000)));
SQL

od -An -tx1 -N32 /dev/urandom | tr -d ' \n' >"$WORK/admin.token"
TOKEN="$(cat "$WORK/admin.token")"
HUB_ONE="$(multihash_id h)"
HUB_TWO="$(multihash_id h)"
# The stored allowlist (docs/operations.md, "Stored settings"): no
# GIM_HUB_FEDERATION_ALLOWLIST file, so the admin API edits the table.
sqlite3 "$DB" "INSERT INTO federation_allowlist (hub_id, addrs) VALUES ('$HUB_ONE', '[\"/dns4/hub-one.example.eu/tcp/4001\"]');"

cat >"$STATE" <<'JSON'
{
  "status": "running",
  "current": "0.3.0",
  "available": "0.3.1",
  "last_good": "0.3.0",
  "channel": "stable",
  "last_check": "2026-10-17T08:00:00Z",
  "history": [
    {"version": "0.2.0", "at": "2026-10-01T08:00:00Z", "result": "good"},
    {"version": "0.3.0", "at": "2026-10-16T08:00:00Z", "result": "good"}
  ],
  "config_generation": 1,
  "checked_nonce": 0,
  "check_nonce": 0,
  "restart_nonce": 0
}
JSON
cp "$STATE" "$WORK/state.orig.json"
pass "seed: user $USER_ID (@$HANDLE), device $DEVICE_ID, session $SESSION_REF; allowlist with $HUB_ONE; state.json current 0.3.0, available 0.3.1"

# --- hub ---------------------------------------------------------------------
docker network create "${LABELS[@]}" "$NET" >/dev/null
docker run -d "${LABELS[@]}" --name "$HUB" --network "$NET" \
    -v "$WORK:$WORK" -w "$WORK" \
    -e GIM_HUB_LISTEN=0.0.0.0:8080 \
    -e GIM_HUB_DATA_DIR="$WORK/data" \
    -e GIM_HUB_ADMIN_LISTEN=0.0.0.0:8081 \
    -e GIM_HUB_ADMIN_TOKEN_FILE="$WORK/admin.token" \
    -e GIM_HUB_FEDERATION=true \
    -e GIM_HUB_PUBLIC_URL=https://hub-e2e.example.eu \
    -e "$ENV_KEY=$ENV_VALUE" \
    -e LODE_DIR="$WORK/lode" \
    -e LODE_INSTANCE="$RUN" \
    -e LODE_ACTIVE_VERSION=0.3.0 \
    "$RUNTIME_IMAGE" "$WORK/bin/gim-hub" >/dev/null
for _ in $(seq 1 60); do
    hub_get 8080 /healthz >/dev/null 2>&1 && hub_get 8081 /admin/ >/dev/null 2>&1 && break
    sleep 1
done
hub_get 8081 /admin/ | grep -q '<div id="root"' || fail "hub: admin listener does not serve the UI"
[[ "$(jq -r .ready "$STATE")" == "$RUN" ]] || fail "hub: readiness not reported to the fake lode"
pass "hub: $HUB serves the client API on :8080 and the admin UI on :8081"

# --- browser -----------------------------------------------------------------
echo "admin-e2e: running Playwright ($PLAYWRIGHT_IMAGE)"
docker run --rm "${LABELS[@]}" --name "ai-agent-$RUN-playwright" --network "$NET" --ipc=host \
    -v "$ROOT/admin-ui:$ROOT/admin-ui" -w "$ROOT/admin-ui" \
    -v "$WORK/results:$WORK/results" -e E2E_OUTPUT_DIR="$WORK/results" \
    -e E2E_ADMIN_URL="http://$HUB:8081" \
    -e E2E_CLIENT_URL="http://$HUB:8080" \
    -e E2E_TOKEN="$TOKEN" \
    -e E2E_USER_ID="$USER_ID" \
    -e E2E_HANDLE="$HANDLE" \
    -e E2E_DEVICE_ID="$DEVICE_ID" \
    -e E2E_SESSION_REF="$SESSION_REF" \
    -e E2E_NEW_HUB="$HUB_TWO" \
    -e E2E_RETENTION_KEY="$RETENTION_KEY" \
    -e E2E_RETENTION_DAYS="$RETENTION_DAYS" \
    -e E2E_ENV_KEY="$ENV_KEY" \
    -e E2E_ENV_VALUE="$ENV_VALUE" \
    "$PLAYWRIGHT_IMAGE" \
    node node_modules/@playwright/test/cli.js test -c e2e/playwright.config.ts ||
    fail "browser steps (traces in $WORK/results with ADMIN_E2E_KEEP=1)"

# --- on disk -----------------------------------------------------------------
left="$(sqlite3 "$DB" "SELECT count(*) FROM sessions WHERE user_id = '$USER_ID'")"
[[ "$left" == 0 ]] || fail "3: $left sessions left in the database"
pass "3. database: no session left for $USER_ID"

stored="$(sqlite3 "$DB" "SELECT hub_id FROM federation_allowlist ORDER BY hub_id")"
grep -qx "$HUB_ONE" <<<"$stored" && grep -qx "$HUB_TWO" <<<"$stored" ||
    fail "4: federation_allowlist table: $stored"
pass "4. federation_allowlist table lists $HUB_ONE and $HUB_TWO"

[[ "$(jq .check_nonce "$STATE")" == 1 ]] || fail "5: check_nonce $(jq .check_nonce "$STATE")"
lode_fields='{status, current, available, last_good, channel, last_check, history, config_generation, checked_nonce, restart_nonce}'
[[ "$(jq -S "$lode_fields" "$STATE")" == "$(jq -S "$lode_fields" "$WORK/state.orig.json")" ]] ||
    fail "5: lode's fields changed: $(jq -c . "$STATE")"
pass "5. state.json: check_nonce 0 -> 1, lode's fields intact"

audit="$(sqlite3 "$DB" "SELECT action FROM admin_audit WHERE actor = 'token' AND result = 'ok' ORDER BY id")"
for action in device_sessions_revoke allowlist_update lode_check setting_update; do
    grep -qx "$action" <<<"$audit" || fail "6: no '$action' in admin_audit: $audit"
done
pass "6. admin_audit: $(tr '\n' ' ' <<<"$audit")"

row="$(sqlite3 -separator ' ' "$DB" "SELECT value, updated_by FROM settings WHERE key = '$RETENTION_KEY'")"
[[ "$(tr -d '"' <<<"$row")" == "$RETENTION_DAYS token" ]] || fail "8: settings row for $RETENTION_KEY: '$row'"
pass "8. settings table: $RETENTION_KEY = $row"

row="$(sqlite3 "$DB" "SELECT count(*) FROM settings WHERE key = '$ENV_KEY'")"
[[ "$row" == 0 ]] || fail "9: $ENV_KEY was stored despite the env"
pass "9. settings table: no stored $ENV_KEY (env value $ENV_VALUE)"

echo "admin-e2e: all steps passed (run $RUN)"
