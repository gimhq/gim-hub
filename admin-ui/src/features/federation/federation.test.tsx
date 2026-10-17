import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { allowlistText, CSRF, envelope, server, state } from '@/test/server'

beforeEach(() => {
  state.loggedIn = true
})

describe('federation', () => {
  it('shows the own peer and the peer table', async () => {
    renderApp('/federation')
    expect(await screen.findByText('12D3KooWAthens')).toBeInTheDocument()
    expect(screen.getByText('hub-split')).toBeInTheDocument()
    expect(screen.getByText('Connected')).toBeInTheDocument()
  })

  it('shows the 422 parser message inline, then saves a valid allowlist', async () => {
    const user = userEvent.setup()
    renderApp('/federation')
    const editor = await screen.findByLabelText('Allowlist file')
    expect(editor).toHaveValue(allowlistText)

    await user.type(editor, '!')
    await user.click(screen.getByRole('button', { name: 'Save and apply' }))
    const error = await screen.findByText('line 2: invalid hub id "!"')
    expect(error).toHaveAttribute('id', 'allowlist-error')
    expect(editor).toHaveAttribute('aria-invalid', 'true')

    await user.clear(editor)
    await user.type(editor, 'hub-zadar /dns4/zadar.example/tcp/4001')
    await user.click(screen.getByRole('button', { name: 'Save and apply' }))
    expect(await screen.findByText('Allowlist saved and applied.')).toBeInTheDocument()
    expect(state.mutations.at(-1)).toEqual({
      key: 'PUT /federation/allowlist',
      csrf: CSRF,
      body: { text: 'hub-zadar /dns4/zadar.example/tcp/4001' },
    })
  })

  it('shows a disabled notice when federation is off', async () => {
    server.use(
      http.get('/admin/api/federation', () =>
        HttpResponse.json({ enabled: false, peer_id: null, listen_addrs: [], external_addrs: [], peers: [] })),
      http.get('/admin/api/federation/allowlist', () => envelope(404, 'not_found', 'federation is off')),
    )
    renderApp('/federation')
    expect(await screen.findByText('Federation is disabled on this hub.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Allowlist file')).not.toBeInTheDocument()
  })
})
