// MSW mock of the H10 admin API contract.
//
// The tests run on the Bun runtime, where MSW's network interceptors do not
// hook fetch. Instead `mockFetch` replaces the global fetch and resolves each
// request against the MSW handlers with `getResponse`.
import type { RequestHandler } from 'msw'
import { getResponse, http, HttpResponse } from 'msw'

const API = '/admin/api'
export const CSRF = 'csrf-test-token'
export const TOKEN = 'a'.repeat(40)

export interface MockState {
  loggedIn: boolean
  // Records the X-CSRF-Token header of every mutation, keyed by "METHOD path".
  mutations: { key: string, csrf: string | null, body: unknown }[]
  lodeSupervised: boolean
}

export const state: MockState = { loggedIn: false, mutations: [], lodeSupervised: true }

export function resetMockState() {
  state.loggedIn = false
  state.mutations = []
  state.lodeSupervised = true
}

export function envelope(status: number, code: string, message: string) {
  return HttpResponse.json({ error: { code, message } }, { status })
}

const session = () => ({ actor: 'token', auth: 'token', csrf_token: CSRF, expires_at: 2_000_000_000 })

async function record(request: Request, path: string) {
  const text = await request.text()
  state.mutations.push({
    key: `${request.method} ${path}`,
    csrf: request.headers.get('X-CSRF-Token'),
    body: text ? JSON.parse(text) : undefined,
  })
}

// Wraps a mutation handler with the session and CSRF checks of the contract.
function mutation(method: 'post' | 'put' | 'delete', path: string, respond: (request: Request) => Response | Promise<Response>) {
  return http[method](`${API}${path}`, async ({ request }) => {
    const url = new URL(request.url)
    await record(request.clone(), url.pathname.slice(API.length))
    if (!state.loggedIn)
      return envelope(401, 'unauthorized', 'no session')
    if (request.headers.get('X-CSRF-Token') !== CSRF)
      return envelope(403, 'csrf_failed', 'CSRF token mismatch')
    return respond(request)
  })
}

function authed(path: string, body: () => unknown) {
  return http.get(`${API}${path}`, () =>
    state.loggedIn ? HttpResponse.json(body() as never) : envelope(401, 'unauthorized', 'no session'))
}

export const users = [
  { user_id: 'u-alice', handle: 'alice', suspended: false, created_at: 1_760_000_000, device_count: 2, last_seen: 1_760_600_000 },
  { user_id: 'u-bob', handle: null, suspended: true, created_at: 1_760_000_100, device_count: 1, last_seen: null },
]

export const aliceDetail = {
  user_id: 'u-alice',
  handle: 'alice',
  suspended: false,
  suspended_at: null,
  created_at: 1_760_000_000,
  hosting_hubs: ['hub-athens'],
  devices: [
    {
      device_id: 'd-phone',
      created_at: 1_760_000_000,
      last_seen: 1_760_600_000,
      active: true,
      sessions: [{ session_ref: '0123456789abcdef', created_at: 1_760_500_000, expires_at: 1_761_000_000 }],
    },
  ],
}

export const lodeState = {
  supervised: true,
  status: 'running',
  current: '0.9.0',
  available: '0.10.0',
  last_good: '0.8.2',
  last_check: '2026-10-17T08:00:00Z',
  last_error: null,
  history: [{ version: '0.9.0', at: '2026-10-16T10:00:00Z', result: 'good' }],
}

export const allowlistText = 'hub-split /dns4/split.example/tcp/4001\n'

export const handlers = [
  http.post(`${API}/login`, async ({ request }) => {
    const { token } = await request.json() as { token: string }
    if (token !== TOKEN)
      return envelope(401, 'unauthorized', 'invalid admin token')
    state.loggedIn = true
    return HttpResponse.json({ actor: 'token', csrf_token: CSRF, expires_at: 2_000_000_000 })
  }),
  http.get(`${API}/session`, () =>
    state.loggedIn ? HttpResponse.json(session()) : envelope(401, 'unauthorized', 'no session')),
  http.post(`${API}/logout`, () => {
    state.loggedIn = false
    return new HttpResponse(null, { status: 204 })
  }),
  authed('/overview', () => ({
    version: '0.9.0',
    revision: 'abc1234',
    hub_id: 'hub-athens',
    public_url: 'https://hub.athens.example',
    started_at: 1_760_000_000,
    uptime_seconds: 93_784,
    storage: { db_bytes: 5_242_880, blob_bytes: 1024 },
    counts: { users: 2, devices: 3, groups: 4, blobs: 5 },
    push: { enqueued: 10, coalesced: 1, upgraded: 0, dropped: 0, sent: 9, skipped: 0, invalid_token: 0, retried: 2, failed: 1 },
    event_retention_days: 30,
  })),
  http.get(`${API}/users`, ({ request }) => {
    if (!state.loggedIn)
      return envelope(401, 'unauthorized', 'no session')
    const q = new URL(request.url).searchParams.get('q') ?? ''
    const items = users.filter(u => u.user_id.includes(q) || (u.handle ?? '').includes(q))
    return HttpResponse.json({ items, next_cursor: null })
  }),
  authed('/users/u-alice', () => aliceDetail),
  mutation('delete', '/users/u-alice/devices/d-phone/sessions', () => HttpResponse.json({ revoked: 1 })),
  mutation('post', '/users/u-alice/suspend', () => new HttpResponse(null, { status: 204 })),
  mutation('post', '/handles/alice/release', () => new HttpResponse(null, { status: 204 })),
  authed('/federation', () => ({
    enabled: true,
    peer_id: '12D3KooWAthens',
    listen_addrs: ['/ip4/0.0.0.0/tcp/4001'],
    external_addrs: [],
    peers: [{ hub_id: 'hub-split', connected: true, outbox_backlog: 0, last_error: null, last_seen: 1_760_600_000 }],
  })),
  authed('/federation/allowlist', () => ({
    path: '/etc/gim-hub/allowlist',
    text: allowlistText,
    entries: [{ hub_id: 'hub-split', addrs: ['/dns4/split.example/tcp/4001'] }],
  })),
  mutation('put', '/federation/allowlist', async (request) => {
    const { text } = await request.json() as { text: string }
    if (text.includes('!'))
      return envelope(422, 'validation_failed', 'line 2: invalid hub id "!"')
    return HttpResponse.json({ path: '/etc/gim-hub/allowlist', text, entries: [] })
  }),
  authed('/lode', () => (state.lodeSupervised ? lodeState : { supervised: false })),
  mutation('post', '/lode/check', () => new HttpResponse(null, { status: 202 })),
  mutation('post', '/lode/update', () => new HttpResponse(null, { status: 202 })),
  mutation('post', '/lode/restart', () => new HttpResponse(null, { status: 202 })),
  mutation('post', '/lode/rollback', () => new HttpResponse(null, { status: 202 })),
  authed('/config', () => ({
    items: [
      { key: 'GIM_HUB_LISTEN', value: '0.0.0.0:8080', redacted: false },
      { key: 'GIM_HUB_PUSH_WEBHOOK_SECRET', value: null, redacted: true },
      { key: 'GIM_HUB_PUBLIC_URL', value: null, redacted: false },
    ],
  })),
  http.get(`${API}/audit`, ({ request }) => {
    if (!state.loggedIn)
      return envelope(401, 'unauthorized', 'no session')
    const cursor = new URL(request.url).searchParams.get('cursor')
    const entry = (id: number, action: string) => ({
      id,
      at: 1_760_600_000 + id,
      actor: 'token',
      action,
      target: 'u-alice',
      source_ip: '127.0.0.1',
      result: 'ok',
      detail: null,
    })
    return cursor
      ? HttpResponse.json({ items: [entry(1, 'login_ok')], next_cursor: null })
      : HttpResponse.json({ items: [entry(2, 'user_suspend')], next_cursor: 'c1' })
  }),
]

let overrides: RequestHandler[] = []

// Same surface as setupServer() for the parts the tests use.
export const server = {
  use: (...next: RequestHandler[]) => {
    overrides = [...next, ...overrides]
  },
  resetHandlers: () => {
    overrides = []
  },
}

export async function mockFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : String(input), window.location.href)
  const request = new Request(url, init)
  const response = await getResponse([...overrides, ...handlers], request)
  if (!response)
    throw new Error(`Unhandled request: ${request.method} ${url.pathname}`)
  return response
}
