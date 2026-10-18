// MSW mock of the H10 admin API contract, with the H14 settings endpoints.
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
  settings: MockSetting[]
  allowlistReadOnly: boolean
  policyEntries: MockPolicyEntry[]
}

interface MockPolicyEntry {
  user_id: string
  handle: string | null
  added_at: number
  added_by: string
  note: string | null
}

type MockSetting = Record<string, unknown> & {
  key: string
  type: string
  enum: string[] | null
  default: unknown
  value: unknown
  is_set: boolean
  source: string
  read_only: boolean
  apply: string
  restart_pending: boolean
  updated_at: number | null
  updated_by: string | null
}

function setting(key: string, group: string, type: string, description: string, fields: Partial<MockSetting> = {}): MockSetting {
  const base: MockSetting = {
    key,
    group,
    type,
    enum: null,
    description,
    default: null,
    value: null,
    is_set: false,
    source: 'default',
    read_only: false,
    apply: 'live',
    restart_pending: false,
    updated_at: null,
    updated_by: null,
  }
  return { ...base, value: fields.default ?? null, ...fields }
}

export const SECRET = 'webhook-secret-value'

export function initialSettings(): MockSetting[] {
  return [
    setting('GIM_HUB_PUBLIC_URL', 'general', 'url', 'Public base URL of the hub', {
      apply: 'restart',
      value: 'https://hub.athens.example',
      is_set: true,
      source: 'stored',
      updated_at: 1_760_600_000,
      updated_by: 'token',
    }),
    setting('GIM_HUB_FEDERATION', 'federation', 'bool', 'Enable federation', { default: false, apply: 'restart' }),
    setting('GIM_HUB_P2P_BOOTSTRAP', 'federation', 'list', 'Bootstrap peers', { default: [], apply: 'restart' }),
    setting('GIM_HUB_PUSH_TOPIC', 'push', 'string', 'Push topic', { default: 'gim' }),
    setting('GIM_HUB_PUSH_WEBHOOK_SECRET', 'push', 'secret', 'Push webhook secret'),
    setting('GIM_HUB_RATE_LIMIT_PER_MINUTE', 'limits', 'integer', 'Requests per minute', {
      default: 60,
      value: 120,
      is_set: true,
      source: 'env',
      read_only: true,
    }),
    setting('GIM_HUB_PUSH_RETRY_SECONDS', 'limits', 'duration_seconds', 'Push retry interval', { default: 30 }),
    setting('GIM_HUB_EVENT_RETENTION_DAYS', 'storage', 'integer', 'Events older than this are pruned (days)', {
      default: 7,
      value: 30,
      is_set: true,
      source: 'stored',
      updated_at: 1_760_600_000,
      updated_by: 'cli',
    }),
    setting('GIM_HUB_USER_POLICY', 'users', 'enum', 'Who may use this hub', { enum: ['open', 'allow', 'deny'], default: 'open' }),
  ]
}

export const state: MockState = { loggedIn: false, mutations: [], lodeSupervised: true, settings: initialSettings(), allowlistReadOnly: false, policyEntries: [] }

export function resetMockState() {
  state.loggedIn = false
  state.mutations = []
  state.lodeSupervised = true
  state.settings = initialSettings()
  state.allowlistReadOnly = false
  state.policyEntries = []
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

function allowlistSource() {
  return state.allowlistReadOnly
    ? { source: 'file', read_only: true, path: '/etc/gim-hub/allowlist' }
    : { source: 'stored', read_only: false, path: '/var/lib/gim-hub/hub.db#federation_allowlist' }
}

// The env parser's checks, reduced to what the tests need.
function validate(item: MockSetting, value: unknown): string | null {
  switch (item.type) {
    case 'integer':
    case 'duration_seconds':
      return Number.isInteger(value) && (value as number) >= 0 ? null : `invalid ${item.key}: expected a non-negative integer`
    case 'bool':
      return typeof value === 'boolean' ? null : `invalid ${item.key}: expected a boolean`
    case 'list':
      return Array.isArray(value) && value.every(v => typeof v === 'string') ? null : `invalid ${item.key}: expected a list`
    case 'enum':
      return item.enum?.includes(value as string) ? null : `invalid ${item.key}: expected one of ${item.enum?.join(', ')}`
    case 'url':
      return typeof value === 'string' && /^https?:\/\//.test(value) ? null : `invalid ${item.key}: expected an http(s) URL`
    default:
      return typeof value === 'string' ? null : `invalid ${item.key}: expected a string`
  }
}

function settingResponse(item: MockSetting) {
  return item.type === 'secret' ? { ...item, value: null } : item
}

function updateSetting(key: string, next: (item: MockSetting) => Response | MockSetting) {
  const item = state.settings.find(s => s.key === key)
  if (!item)
    return envelope(404, 'not_found', `unknown setting ${key}`)
  if (item.source === 'env')
    return envelope(409, 'conflict', 'set by environment')
  const result = next(item)
  if (result instanceof Response)
    return result
  result.restart_pending = result.apply === 'restart'
  state.settings = state.settings.map(s => (s.key === key ? result : s))
  return HttpResponse.json(settingResponse(result) as never)
}

// The user policy view: the mode is the GIM_HUB_USER_POLICY setting.
function userPolicy() {
  const item = state.settings.find(s => s.key === 'GIM_HUB_USER_POLICY')!
  const mode = item.value as string
  const listed = new Set(state.policyEntries.map(e => e.user_id))
  const notAdmitted = mode === 'open' ? 0 : users.filter(u => (mode === 'allow') !== listed.has(u.user_id)).length
  return { mode, mode_source: item.source, not_admitted_users: notAdmitted, entries: state.policyEntries }
}

function policyEntry(userId: string, note: string | null = null): MockPolicyEntry {
  const handle = users.find(u => u.user_id === userId)?.handle ?? null
  return { user_id: userId, handle, added_at: 1_760_700_000, added_by: 'token', note }
}

const validUserId = (raw: string) => /^u-[a-z]+$/.test(raw)

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
    event_retention_days: state.settings.find(s => s.key === 'GIM_HUB_EVENT_RETENTION_DAYS')?.value,
    user_policy: state.settings.find(s => s.key === 'GIM_HUB_USER_POLICY')?.value,
  })),
  http.get(`${API}/users`, ({ request }) => {
    if (!state.loggedIn)
      return envelope(401, 'unauthorized', 'no session')
    const q = new URL(request.url).searchParams.get('q') ?? ''
    const items = users.filter(u => u.user_id.includes(q) || (u.handle ?? '').includes(q))
    return HttpResponse.json({ items, next_cursor: null })
  }),
  authed('/users/policy', userPolicy),
  mutation('put', '/users/policy', async (request) => {
    const { text } = await request.json() as { text: string }
    const ids: string[] = []
    for (const [index, raw] of text.split('\n').entries()) {
      const line = raw.split('#')[0].trim()
      if (!line)
        continue
      if (!validUserId(line))
        return envelope(422, 'validation_failed', `line ${index + 1}: invalid user ID "${line}"`)
      if (!ids.includes(line))
        ids.push(line)
    }
    state.policyEntries = ids.map(id => state.policyEntries.find(e => e.user_id === id) ?? policyEntry(id))
    return HttpResponse.json(userPolicy())
  }),
  mutation('post', '/users/policy/entries', async (request) => {
    const body = await request.json() as { user_id?: string, handle?: string, note?: string }
    let userId = body.user_id
    if (body.handle !== undefined) {
      userId = users.find(u => u.handle === body.handle!.replace(/^@/, '').toLowerCase())?.user_id
      if (!userId)
        return envelope(404, 'not_found', 'not found')
    }
    else if (!userId || !validUserId(userId)) {
      return envelope(422, 'validation_failed', `invalid user ID "${userId ?? ''}"`)
    }
    if (state.policyEntries.some(e => e.user_id === userId))
      return envelope(409, 'conflict', 'the user is already listed')
    state.policyEntries = [...state.policyEntries, policyEntry(userId, body.note?.trim() || null)]
    return HttpResponse.json(userPolicy())
  }),
  mutation('delete', '/users/policy/entries/:id', (request) => {
    const id = decodeURIComponent(new URL(request.url).pathname.split('/').pop()!)
    if (!state.policyEntries.some(e => e.user_id === id))
      return envelope(404, 'not_found', 'not found')
    state.policyEntries = state.policyEntries.filter(e => e.user_id !== id)
    return HttpResponse.json(userPolicy())
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
    ...allowlistSource(),
    text: allowlistText,
    entries: [{ hub_id: 'hub-split', addrs: ['/dns4/split.example/tcp/4001'] }],
  })),
  mutation('put', '/federation/allowlist', async (request) => {
    if (state.allowlistReadOnly)
      return envelope(409, 'conflict', 'managed by the allowlist file')
    const { text } = await request.json() as { text: string }
    if (text.includes('!'))
      return envelope(422, 'validation_failed', 'line 2: invalid hub id "!"')
    return HttpResponse.json({ ...allowlistSource(), text, entries: [] })
  }),
  authed('/settings', () => ({
    items: state.settings.map(settingResponse),
    restart_pending: state.settings.some(s => s.restart_pending),
  })),
  mutation('put', '/settings/:key', async (request) => {
    const key = decodeURIComponent(new URL(request.url).pathname.split('/').pop()!)
    const { value } = await request.json() as { value: unknown }
    return updateSetting(key, (item) => {
      const error = validate(item, value)
      if (error)
        return envelope(422, 'validation_failed', error)
      return { ...item, value, is_set: true, source: 'stored', updated_at: 1_760_700_000, updated_by: 'token' }
    })
  }),
  mutation('delete', '/settings/:key', (request) => {
    const key = decodeURIComponent(new URL(request.url).pathname.split('/').pop()!)
    const federation = state.settings.find(s => s.key === 'GIM_HUB_FEDERATION')?.value === true
    if (key === 'GIM_HUB_PUBLIC_URL' && federation)
      return envelope(422, 'validation_failed', 'GIM_HUB_PUBLIC_URL is required when GIM_HUB_FEDERATION is enabled')
    return updateSetting(key, item => ({
      ...item,
      value: item.default,
      is_set: false,
      source: 'default',
      updated_at: 1_760_700_000,
      updated_by: 'token',
    }))
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
      { key: 'GIM_HUB_ADMIN_TOKEN', value: null, redacted: true },
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
