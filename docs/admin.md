# Admin API

The hub's admin API (and the admin UI, served from the same listener) manages
users, sessions, federation and the lode supervisor. It is off by default and
listens only on its own socket, `GIM_HUB_ADMIN_LISTEN`; the client API
listener (`GIM_HUB_LISTEN`) never serves an `/admin` path.

The contract is [`admin-openapi.json`](../admin-openapi.json) at the
repository root, generated from the code with `scripts/gen-openapi.sh` (which
also regenerates the client `openapi.json`); a test fails when the committed
file is out of date.

Messages are end-to-end encrypted and the admin API shows metadata only: it
never returns group membership, group IDs, the peers of a user or message
metadata. Groups appear only as an aggregate count.

## Enabling

1. Create a token file readable only by the hub user:

   ```sh
   openssl rand -hex 32 > /data/admin.token
   chmod 600 /data/admin.token
   ```

   The token is trimmed and must be at least 32 characters. The hub reads the
   file at startup and keeps only its SHA-256; a changed token needs a restart.
2. Set the variables and restart the hub:

   ```sh
   GIM_HUB_ADMIN_LISTEN=127.0.0.1:8081
   GIM_HUB_ADMIN_TOKEN_FILE=/data/admin.token
   ```

3. Open `https://<proxy>/admin/` and log in with the token.

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIM_HUB_ADMIN_LISTEN` | unset | Admin socket address. Unset: no listener, and the other variables are ignored |
| `GIM_HUB_ADMIN_TOKEN_FILE` | unset | Admin token file. Unset: token login is disabled (POST /admin/api/login answers 403 `forbidden`) |
| `GIM_HUB_ADMIN_TRUSTED_HEADER` | unset | Identity header set by a trusted reverse proxy, e.g. `X-Forwarded-User` |
| `GIM_HUB_ADMIN_TRUSTED_PROXIES` | unset | Comma-separated CIDRs (or single addresses) of trusted proxies; required with the header |
| `GIM_HUB_ADMIN_COOKIE_SECURE` | `false` | Set `Secure` on the session cookie |

With `GIM_HUB_ADMIN_LISTEN` set the hub refuses to start without a token file
or a trusted header, with a trusted header but no trusted proxies, or with an
unreadable or too short token file.

Bind the listener to loopback (or a private network only the proxy can reach)
and terminate TLS in a reverse proxy. `GIM_HUB_ADMIN_COOKIE_SECURE` defaults to
`false` because the hub itself speaks plain HTTP on that socket; set it to
`true` whenever browsers reach the UI over HTTPS (the normal case behind a TLS
proxy) so the cookie is never sent in clear.

### Behind traefik with OIDC

With a proxy that authenticates admins itself (here a traefik middleware named
`oidc`, e.g. an OIDC/forward-auth plugin that sets `X-Forwarded-User` to the
signed-in identity), the hub can trust that header instead of, or in addition
to, the token:

```sh
GIM_HUB_ADMIN_LISTEN=0.0.0.0:8081          # reachable only on the proxy network
GIM_HUB_ADMIN_TRUSTED_HEADER=X-Forwarded-User
GIM_HUB_ADMIN_TRUSTED_PROXIES=172.18.0.0/16 # the traefik network
GIM_HUB_ADMIN_COOKIE_SECURE=true
# GIM_HUB_ADMIN_TOKEN_FILE unset: token login disabled
```

traefik dynamic configuration (file provider):
[`deploy/lode/traefik-admin.yml`](../deploy/lode/traefik-admin.yml). It
routes the admin host to port 8081 through a `strip-identity` middleware
(drops any client-supplied `X-Forwarded-User`) and `oidc`. The commented
admin variables in [`deploy/lode/lode.toml`](../deploy/lode/lode.toml) show
the same setup under lode.

The admin port is not published; only traefik reaches it. The proxy must
overwrite or remove a client-supplied identity header, since the hub cannot
tell it apart from one the proxy set. A request carrying the header from a
peer outside `GIM_HUB_ADMIN_TRUSTED_PROXIES` is treated as unauthenticated.

## Security model

- **Session cookie.** `gim_admin_session`: 256 random bits, `HttpOnly`,
  `SameSite=Strict`, `Path=/admin`, `Max-Age=28800` (8 hours, absolute; no
  sliding renewal), `Secure` with `GIM_HUB_ADMIN_COOKIE_SECURE=true`. Sessions
  live in memory only: a restart logs every admin out.
- **Session required.** Every `/admin/api/*` route except POST
  /admin/api/login answers 401 `unauthorized` without an unexpired session.
- **CSRF.** Every non-GET request must send `X-CSRF-Token` equal to the
  session's `csrf_token` (returned by login and GET /admin/api/session);
  otherwise 403 `csrf_failed`.
- **Token login.** The token is compared in constant time over SHA-256
  digests. At most 5 failed logins per source IP and minute; the next attempt,
  right token or not, answers 429 `rate_limited` with `Retry-After`.
- **Trusted proxy.** A request from a `GIM_HUB_ADMIN_TRUSTED_PROXIES` peer
  carrying `GIM_HUB_ADMIN_TRUSTED_HEADER` gets a session on GET
  /admin/api/session (actor `header:<value>`); mutations still need the cookie
  and the CSRF token.
- **Source IP.** The TCP peer, or the left-most `X-Forwarded-For` address when
  the peer is a trusted proxy. It keys the login throttle and is recorded in
  the audit log.
- **Audit.** Every login, logout and mutation is recorded in the database
  (`admin_audit`) with time, actor, action, target, source IP, result and a
  detail (the error message on failure). Tokens are never recorded.
- **Redaction.** GET /admin/api/config never shows secrets (the webhook
  secret, the PSK, any `*_SECRET`, `*_TOKEN` or `*_KEY` value) or file
  contents; it shows file paths.

## Conventions

JSON bodies; errors use the hub's envelope `{"error":{"code","message"}}`.
Codes: `unauthorized` (401), `csrf_failed` (403), `forbidden` (403),
`not_found` (404), `validation_failed` (400 malformed request, 422 invalid
allowlist), `conflict` (409), `rate_limited` (429), `unavailable` (503, e.g.
not supervised by lode), `internal` (500).

Timestamps are integer seconds since the Unix epoch. lode's fields
(`last_check`, `history[].at`) are passed through from `state.json` verbatim
(RFC 3339 strings). Pages use an opaque `cursor`: pass the previous page's
`next_cursor`, which is `null` on the last page.

## Endpoints

Actor values in the audit log: `token`, `header:<identity>`, or `anonymous`
for failed logins.

| Method and path | Result | Audit action (target) |
| --- | --- | --- |
| `POST /admin/api/login` `{"token"}` | 200 `{actor, csrf_token, expires_at}` + cookie; 401 wrong token; 403 token login disabled; 429 throttled | `login_ok` / `login_failed` |
| `POST /admin/api/logout` | 204, cookie cleared | `logout` |
| `GET /admin/api/session` | 200 `{actor, auth: "token"\|"header", csrf_token, expires_at}`; creates a trusted-header session | `login_ok` (trusted header) |
| `GET /admin/api/overview` | version, revision, `hub_id`, `public_url`, `started_at`, `uptime_seconds`, storage (database file + WAL bytes, blob directory bytes), counts (users, active devices, groups, blobs), push dispatcher counters, `event_retention_days` | |
| `GET /admin/api/users?q=&limit=&cursor=` | Users by user ID; `q` is a case-insensitive substring of the user ID or handle; `limit` 1-100 (default 50) | |
| `GET /admin/api/users/{user_id}` | The user, `hosting_hubs` (from the stored hosting record) and devices with their unexpired sessions | |
| `POST /admin/api/users/{user_id}/suspend` `{"reason"?}` | 204; 409 if already suspended | `user_suspend` (user ID; detail: reason) |
| `POST /admin/api/users/{user_id}/unsuspend` | 204; 409 if not suspended | `user_unsuspend` (user ID) |
| `DELETE /admin/api/users/{user_id}/devices/{device_id}/sessions` | 200 `{revoked}`; 404 unknown device | `device_sessions_revoke` (`<user_id>/<device_id>`) |
| `POST /admin/api/handles/{handle}/release` | 204; 404 unknown handle. The user keeps existing without a handle | `handle_release` (handle; detail: owner) |
| `GET /admin/api/federation` | `enabled`, `peer_id`, `listen_addrs`, `external_addrs`, peers | |
| `GET /admin/api/federation/allowlist` | `{path, text, entries}`; 404 with federation off | |
| `PUT /admin/api/federation/allowlist` `{"text"}` | 200 (same body as GET); 422 invalid; 404 with federation off | `allowlist_update` (file path) |
| `GET /admin/api/lode` | `{"supervised":false}`, or lode's `status`, `current`, `available`, `last_good`, `last_check`, `last_error`, `history` | |
| `POST /admin/api/lode/check` | 202 (bumps `check_nonce`) | `lode_check` |
| `POST /admin/api/lode/update` `{"version"}` | 202 (sets `target`: a version or `latest`) | `lode_update` (version) |
| `POST /admin/api/lode/restart` | 202 (bumps `restart_nonce`) | `lode_restart` |
| `POST /admin/api/lode/rollback` `{"version"?}` | 202 (sets `target` to the version, else `last_good`); 409 with neither | `lode_rollback` (version) |
| `GET /admin/api/config` | `{items: [{key, value, redacted}]}`: every `GIM_HUB_*` setting with defaults applied | |
| `GET /admin/api/audit?limit=&cursor=` | Audit entries newest first; `limit` 1-200 (default 50) | |

A failed mutation is audited too, with result `error`. The lode endpoints
answer 503 `unavailable` unless the hub runs under lode (`LODE_DIR`).

`GET /` on the admin listener redirects (302) to `/admin/`, the admin UI.

### Users

- `last_seen` is the latest sign-in among the current (unexpired) sessions of
  the user or device; `null` without one. The hub does not record request
  times.
- `device_count` counts active devices; `devices` lists every stored device,
  `active` meaning listed (not revoked) in the current DeviceList.
- `session_ref` is the first 16 hex characters of the SHA-256 of the session
  token (the digest the hub stores); it identifies a session in the UI and is
  never the token.
- Suspending sets `suspended_at`, deletes every session and pending sign-in
  challenge of the user and makes POST /v2/auth/challenge and
  POST /v2/auth/session answer 403 `user_suspended` (see
  [`api-v2.md`](api-v2.md)) until the suspension is lifted. Suspension is
  local to this hub.

### Federation

- `peers` lists the allowlisted hubs and any hub with outbox entries or
  delivery state. `connected` is true while the hub is bound (a verified,
  admitted connection); `outbox_backlog` counts queued S2S outbox entries;
  `last_error` is set while deliveries keep failing (`N consecutive delivery
  failures`); `last_seen` is the last connection.
- The allowlist PUT validates the text with the allowlist loader's rules (one
  `hub_id [multiaddr ...]` per line, `#` comments, no `/p2p/`, no QUIC with a
  PSK, at least one other hub); an invalid text answers 422 with the parser's
  message and leaves the file unchanged. A valid text is written atomically
  (temporary file and rename, keeping the file's permissions) to
  `GIM_HUB_FEDERATION_ALLOWLIST` and applied at once, exactly like SIGHUP:
  newly listed hubs are admitted and bound hubs no longer listed are
  disconnected.

### lode

The lode panel reads `$LODE_DIR/state.json` and writes its requests through
the vendored lode SDK: a read-modify-write under `state.json.lock` that keeps
every field lode owns. lode acts on a request about a second later; reload
GET /admin/api/lode to see the outcome (`available` / `check_error` after a
check, `current` after an update). A restart stops this hub gracefully, so the
UI loses its connection briefly; sessions do not survive it.

## Embedding the UI

The SPA (`admin-ui/`, see its README) is built to `admin-ui/dist` by
`scripts/admin-ui.sh build` and embedded at compile time:
`crates/gim-hub-admin/build.rs` generates one `include_bytes!` per file, and
compilation fails with "run scripts/admin-ui.sh build first" when
`admin-ui/dist/index.html` is missing, so a binary never ships an empty UI.
Every build path builds the UI first: `scripts/check.sh`, CI, the Dockerfile
(an `oven/bun:1.4.3` stage), `release.yml`, `scripts/lode-smoke.sh` and
`scripts/fed-test.sh`.

`gim_hub_admin::router` serves, besides `/admin/api/*` and `GET /`:

- `GET /admin/` and every other `/admin/` path: the file under `dist` if it
  exists, else `index.html` (client-side routes such as
  `/admin/users/<user_id>`). `GET /admin` redirects to `/admin/`.
- `/admin/assets/*` (hashed names): `Cache-Control: public,
  max-age=31536000, immutable`; everything else, `index.html` included:
  `no-cache`.
- `/admin/api` paths are never the UI: unknown ones answer 401 without a
  session and 404 with one.

## Browser E2E

`bash scripts/admin-e2e.sh` (not part of `scripts/check.sh`; it needs a
browser image) builds the binary with the embedded UI, starts it with the
admin listener, federation (one allowlisted fake hub) and a fake lode
`state.json`, seeds a user with a device and a session, and drives the UI
with Playwright (`admin-ui/e2e/`, in the pinned
`mcr.microsoft.com/playwright` image): login, user search and detail,
session revoke, allowlist edit, lode "check now", the audit log, and no
`/admin/` on the client listener. Every container and network carries
`ai-agent=true` and a per-run `ai-agent-run` label and is removed on exit.
