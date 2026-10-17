// Same-origin transport for the hub admin API. Every call sends the session
// cookie; every non-GET call also sends the session's CSRF token.

export const API_BASE = '/admin/api'

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

export interface HttpHooks {
  getCsrfToken: () => string | null | undefined
  onUnauthorized: () => void
  onCsrfFailed: () => void
}

let hooks: HttpHooks = {
  getCsrfToken: () => null,
  onUnauthorized: () => {},
  onCsrfFailed: () => {},
}

export function configureHttp(next: HttpHooks) {
  hooks = next
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
  query?: Record<string, string | number | null | undefined>
  // Skip the global 401 handler (used by the session probe and login).
  allowUnauthorized?: boolean
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (options.body !== undefined)
    headers['Content-Type'] = 'application/json'
  if (method !== 'GET') {
    const token = hooks.getCsrfToken()
    if (token)
      headers['X-CSRF-Token'] = token
  }

  let url = `${API_BASE}${path}`
  if (options.query) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(options.query)) {
      if (value !== undefined && value !== null && value !== '')
        params.set(key, String(value))
    }
    const qs = params.toString()
    if (qs)
      url += `?${qs}`
  }

  const response = await fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  })

  if (!response.ok) {
    const error = await toApiError(response)
    if (error.status === 401 && !options.allowUnauthorized)
      hooks.onUnauthorized()
    if (error.status === 403 && error.code === 'csrf_failed')
      hooks.onCsrfFailed()
    throw error
  }

  if (response.status === 204)
    return undefined as T
  const text = await response.text()
  return (text ? JSON.parse(text) : undefined) as T
}

async function toApiError(response: Response): Promise<ApiError> {
  try {
    const body = await response.json() as { error?: { code?: string, message?: string } }
    if (body?.error?.code)
      return new ApiError(response.status, body.error.code, body.error.message ?? body.error.code)
  }
  catch {}
  return new ApiError(response.status, 'http_error', `HTTP ${response.status}`)
}
