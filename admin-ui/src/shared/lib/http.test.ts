import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import { ApiError, configureHttp, request } from './http'

describe('request', () => {
  it('drops empty query parameters and sends the CSRF token only on mutations', async () => {
    const seen: { url: string, csrf: string | null }[] = []
    server.use(http.all('/admin/api/probe', ({ request: req }) => {
      seen.push({ url: req.url, csrf: req.headers.get('X-CSRF-Token') })
      return HttpResponse.json({ ok: true })
    }))
    configureHttp({ getCsrfToken: () => 't1', onUnauthorized: () => {}, onCsrfFailed: () => {} })
    await request('/probe', { query: { q: '', limit: 5, cursor: null } })
    await request('/probe', { method: 'POST' })
    expect(new URL(seen[0]!.url).search).toBe('?limit=5')
    expect(seen.map(s => s.csrf)).toEqual([null, 't1'])
  })

  it('maps a response without an envelope to a generic error', async () => {
    server.use(http.get('/admin/api/broken', () => new HttpResponse('oops', { status: 502 })))
    const error = await request('/broken').catch(e => e as ApiError)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 502, code: 'http_error' })
  })
})
