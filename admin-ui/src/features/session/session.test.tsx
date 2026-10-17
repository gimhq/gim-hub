import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { envelope, server, state, TOKEN } from '@/test/server'

describe('login', () => {
  it('shows the token form without a session and renders the error envelope on failure', async () => {
    const user = userEvent.setup()
    renderApp('/')
    const input = await screen.findByLabelText('Admin token')
    await user.type(input, 'wrong-token')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('invalid admin token')
    expect(state.loggedIn).toBe(false)
  })

  it('signs in with the token and opens the overview', async () => {
    const user = userEvent.setup()
    renderApp('/login')
    await user.type(await screen.findByLabelText('Admin token'), TOKEN)
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument()
    expect(await screen.findByText('hub-athens')).toBeInTheDocument()
  })

  it('skips the login form when the session already exists (proxy header mode)', async () => {
    state.loggedIn = true
    server.use(http.get('/admin/api/session', () =>
      HttpResponse.json({ actor: 'header:alice@example', auth: 'header', csrf_token: 'x', expires_at: 2_000_000_000 })))
    renderApp('/login')
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument()
    expect(screen.getByText('header:alice@example')).toBeInTheDocument()
    expect(screen.queryByLabelText('Admin token')).not.toBeInTheDocument()
  })

  it('redirects to the login form when any call answers 401', async () => {
    state.loggedIn = true
    server.use(http.get('/admin/api/overview', () => envelope(401, 'unauthorized', 'session expired')))
    const { router } = renderApp('/')
    expect(await screen.findByLabelText('Admin token')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/login')
  })

  it('signs out', async () => {
    state.loggedIn = true
    const user = userEvent.setup()
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByLabelText('Admin token')).toBeInTheDocument()
    expect(state.loggedIn).toBe(false)
  })

  it('shows csrf_failed errors and refetches the session', async () => {
    state.loggedIn = true
    let sessionCalls = 0
    server.use(
      http.get('/admin/api/session', () => {
        sessionCalls++
        return HttpResponse.json({ actor: 'token', auth: 'token', csrf_token: 'stale', expires_at: 2_000_000_000 })
      }),
    )
    const user = userEvent.setup()
    renderApp('/lode')
    await user.click(await screen.findByRole('button', { name: 'Check now' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('CSRF token mismatch')
    await waitFor(() => expect(sessionCalls).toBe(2))
  })
})
