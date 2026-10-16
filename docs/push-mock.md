# Mock push server

`gim-push-mock` (crate `crates/gim-push-mock`) is the receiving side of the hub's push webhook for
tests and development. It verifies the webhook signature, records each push in memory and lets
tests, a Mac-side iOS Simulator helper and an Android debug app read them back. It is a test tool,
not production software: state lives in memory only (a ring of the last 10 000 deliveries) and is
lost on restart.

## 1. Running

| Variable | Default | Meaning |
|---|---|---|
| `GIM_PUSH_MOCK_LISTEN` | `0.0.0.0:8090` | Listen address |
| `GIM_PUSH_MOCK_SECRET` | (required) | Shared secret; the hub's `GIM_HUB_PUSH_WEBHOOK_SECRET` |
| `GIM_PUSH_MOCK_MAX_SKEW_SECONDS` | `300` | Accepted distance of the signature timestamp from now |

Point the hub at it with `GIM_HUB_PUSH_WEBHOOK_URL=http://<mock>:8090/push` and the same secret.

Image: `bash scripts/docker-build.sh IMAGE push-mock` builds `Dockerfile.push-mock` (non-root,
`gim-push-mock healthcheck` as the container healthcheck). `deploy/federation/compose.yaml` runs it
as the `push-mock` service; `scripts/docker-smoke.sh` builds and checks it.

## 2. Endpoints

### `POST /push`

The webhook target. In order:

1. `X-Gim-Signature: t=<unix seconds>,v1=<64 lowercase hex>` must be well formed, `t` within the
   allowed skew, and `v1` equal to HMAC-SHA256(secret, `"<t>." + raw body`) (constant-time
   compare). Otherwise **401**.
2. The body must be JSON with `v` = 1, a non-empty `delivery_id` equal to the `X-Gim-Delivery`
   header, and string `registration.provider` and `registration.token`. Otherwise **400**.
3. A `delivery_id` already recorded is answered **200** `{"status":"duplicate"}` and not recorded
   again.
4. Token prefix hooks: `gone-` -> **410**, `fail-` -> **500**, `bad-` -> **400**. These pushes are
   counted but not recorded, so every retry gets the same answer.
5. Otherwise the push is recorded as `{seq, received_at, delivery_id, body}` and answered **200**
   `{"status":"ok","seq":<seq>}`. `seq` increases monotonically (also across `POST /reset`);
   `received_at` is in unix milliseconds; `body` is the request body as received.

### `GET /deliveries?token=&provider=&since=&wait=`

Recorded deliveries with `seq > since` (default 0) whose `registration.token` / `.provider` equal
the given filters (empty or absent: any), oldest first:

```json
{"deliveries": [{"seq": 3, "received_at": 1760000000000, "delivery_id": "...", "body": {...}}],
 "next": 3}
```

`next` is the value to pass as `since` on the next call (the newest recorded `seq`, or `since` if
larger). With `wait` > 0 (seconds, at most 30) the request long-polls until at least one delivery
matches or the wait is over (then `deliveries` is empty).

### `GET /stats`, `POST /reset`, `GET /healthz`

`GET /stats` returns `{"deliveries", "last_seq", "counters"}` with the counters `delivered`,
`duplicates`, `gone`, `failed`, `bad`, `unauthorized` (401) and `invalid` (400 on a signed
request). `POST /reset` (204) clears the deliveries and the counters. `GET /healthz` returns
`{"status":"ok","version"}`.

## 3. Device hooks

### iOS Simulator: provider `mock-ios-sim`

A device registers `{"provider":"mock-ios-sim","token":"<any>","app_id":"<bundle id>"}`. Each of
its deliveries additionally carries

```json
"simctl": {"bundle_id": "<app_id>",
           "payload": {"aps": {"alert": {"title": "gim", "body": "New message"}, "mutable-content": 1},
                       "gim": <the webhook payload>}}
```

The mock never runs `xcrun`. A helper on the Mac running the Simulator polls the mock and hands
each payload to `simctl` (needs `curl` and `jq`):

```bash
MOCK=http://localhost:8090   # where the Mac reaches the mock
DEVICE=booted                # or a simulator UDID
since=0
while true; do
    resp="$(curl -fsS "$MOCK/deliveries?provider=mock-ios-sim&since=$since&wait=30")" || { sleep 2; continue; }
    since="$(jq -r .next <<<"$resp")"
    jq -c '.deliveries[].simctl' <<<"$resp" | while read -r simctl; do
        file="$(mktemp -t gim-push).json"
        jq '.payload' <<<"$simctl" >"$file"
        xcrun simctl push "$DEVICE" "$(jq -r .bundle_id <<<"$simctl")" "$file"
        rm -f "$file"
    done
done
```

### Android debug app: provider `mock-android`

The debug build registers `{"provider":"mock-android","token":"<its own random token>"}` and
long-polls its own deliveries, keeping `next`:

```
GET /deliveries?token=<token>&since=<next>&wait=30
```

Each returned `body.payload` is handed to the app's push handler as if it came from FCM. Start
with `since=0`, or with `next` from a first call without `wait` to skip deliveries made before the
app started.

## 4. Test hooks summary

| Token prefix | Answer | Hub behaviour (webhook contract) |
|---|---|---|
| `gone-` | 410 | deletes the registration |
| `fail-` | 500 | retries with backoff |
| `bad-` | 400 | drops the push, keeps the registration |
| other | 200 | delivered |
