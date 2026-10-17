# gim-hub admin UI

React 19 + Vite SPA for the hub admin listener (`GIM_HUB_ADMIN_LISTEN`), built to
the `pma-web` baseline: TanStack Router (file-based, `src/app/routes/`), TanStack
Query, shadcn/ui (base-nova, Base UI primitives), Tailwind v4, react-i18next
(English and Chinese).

The app is served under `/admin/` (Vite `base`, router `basepath`) and talks only to
same-origin `/admin/api/*`. Requests send the session cookie; every non-GET request
also sends `X-CSRF-Token` with the token from `POST /login` or `GET /session`.

## Gates

All tooling runs in the pinned `oven/bun:1.4.3` container:

```bash
bash scripts/admin-ui.sh install   # bun install --frozen-lockfile
bash scripts/admin-ui.sh check     # install, lint, typecheck, test (coverage >= 80%), build
bash scripts/admin-ui.sh build     # install, build -> admin-ui/dist
```

`bash scripts/check.sh` runs `scripts/admin-ui.sh check` before the cargo checks.

Dependencies are pinned to exact versions; `bun.lock` is committed. After adding or
renaming a route, rebuild (or run the tests) so `src/app/routeTree.gen.ts` is
regenerated, and commit it.

## Layout

```text
src/main.tsx                 entry: query client, router, providers
src/app/                     providers, router factory, i18n, locales, routes/
src/features/<area>/         api.ts (query/mutation hooks) and pages
src/shared/lib/http.ts       fetch wrapper: error envelope, CSRF header, 401/403 hooks
src/shared/components/ui/    shadcn primitives (generated, owned code)
src/test/                    MSW mock of the admin API contract, render helper
```

## Behaviour

- `GET /session` decides the entry: a session (token or trusted proxy header)
  skips the login form.
- A 401 from any call clears the cached session and redirects to `/login`.
- A 403 `csrf_failed` shows the error and refetches the session (new CSRF token).
- Errors render the envelope `error.message`.
- The lode entry is hidden in the navigation when `GET /lode` reports
  `supervised: false`.

## Deviations from the pma-web defaults

- Locales are bundled (`src/app/locales/*.json`) instead of loaded from
  `public/locales/`: the hub embeds the SPA and only `/admin/assets/` is
  guaranteed to be served as static files.
- `typescript` is aliased to `@typescript/typescript6` (TS 6 API for
  typescript-eslint, which does not support TS 7), and TS 7 is installed as
  `@typescript/native`, which provides the `tsc` used by `bun run typecheck`.
- Tests run on the Bun runtime (no Node in the bun image). jsdom does not start
  there and MSW's network interceptors do not hook fetch, so tests use happy-dom
  and `src/test/server.ts` replaces the global `fetch` with a function that
  resolves requests against the MSW handlers via `getResponse`.

## Development

`bun run dev` starts Vite through nsl. The admin API is not proxied by Vite; for
manual testing, route `/admin/api` to a hub admin listener at the nsl layer. None
of the gates need a dev server.
