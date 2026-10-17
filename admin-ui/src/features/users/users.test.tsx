import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { aliceDetail, CSRF, envelope, server, state } from '@/test/server'

beforeEach(() => {
  state.loggedIn = true
})

describe('users', () => {
  it('searches users by handle or id', async () => {
    const user = userEvent.setup()
    const { router } = renderApp('/users')
    expect(await screen.findByText('u-alice')).toBeInTheDocument()
    expect(screen.getByText('u-bob')).toBeInTheDocument()

    await user.type(screen.getByLabelText('Search users'), 'bob')
    await user.click(screen.getByRole('button', { name: 'Search' }))
    await screen.findByText('u-bob')
    expect(screen.queryByText('u-alice')).not.toBeInTheDocument()
    expect(router.state.location.search).toEqual({ q: 'bob' })
    expect(screen.getByText('Suspended')).toBeInTheDocument()
  })

  it('shows an empty state', async () => {
    const user = userEvent.setup()
    renderApp('/users')
    await user.type(await screen.findByLabelText('Search users'), 'nobody')
    await user.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByText('No users found.')).toBeInTheDocument()
  })

  it('opens the user detail with devices and sessions', async () => {
    const user = userEvent.setup()
    renderApp('/users')
    await user.click(await screen.findByRole('link', { name: 'u-alice' }))
    expect(await screen.findByText('d-phone')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'User u-alice' })).toBeInTheDocument()
    expect(screen.getByText('0123456789abcdef')).toBeInTheDocument()
    expect(screen.getByText('hub-athens')).toBeInTheDocument()
  })

  it('revokes a device\'s sessions after confirmation, sending the CSRF token', async () => {
    const user = userEvent.setup()
    renderApp('/users/u-alice')
    await user.click(await screen.findByRole('button', { name: 'Revoke sessions' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(state.mutations).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: 'Revoke sessions' }))
    expect(await screen.findByText('Revoked 1 session.')).toBeInTheDocument()
    expect(state.mutations).toEqual([
      { key: 'DELETE /users/u-alice/devices/d-phone/sessions', csrf: CSRF, body: undefined },
    ])
  })

  it('cancelling the confirmation sends nothing', async () => {
    const user = userEvent.setup()
    renderApp('/users/u-alice')
    await user.click(await screen.findByRole('button', { name: 'Release handle' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Cancel' }))
    expect(state.mutations).toHaveLength(0)
  })

  it('suspends with a reason', async () => {
    const user = userEvent.setup()
    renderApp('/users/u-alice')
    await user.click(await screen.findByRole('button', { name: 'Suspend' }))
    const dialog = await screen.findByRole('alertdialog')
    await user.type(within(dialog).getByLabelText('Reason (optional)'), 'spam')
    await user.click(within(dialog).getByRole('button', { name: 'Suspend' }))
    await vi.waitFor(() => expect(state.mutations).toEqual([
      { key: 'POST /users/u-alice/suspend', csrf: CSRF, body: { reason: 'spam' } },
    ]))
  })

  it('keeps the dialog open with the envelope message on conflict', async () => {
    server.use(http.post('/admin/api/users/u-alice/unsuspend', () => envelope(409, 'conflict', 'user is not suspended')))
    server.use(http.get('/admin/api/users/u-alice', () =>
      HttpResponse.json({ ...aliceDetail, suspended: true, suspended_at: 1_760_700_000 })))
    const user = userEvent.setup()
    renderApp('/users/u-alice')
    await user.click(await screen.findByRole('button', { name: 'Unsuspend' }))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Unsuspend' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('user is not suspended')
  })

  it('releases the handle', async () => {
    const user = userEvent.setup()
    renderApp('/users/u-alice')
    await user.click(await screen.findByRole('button', { name: 'Release handle' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Release handle' }))
    await vi.waitFor(() => expect(state.mutations.map(m => m.key)).toEqual(['POST /handles/alice/release']))
  })

  it('renders a not-found envelope for an unknown user', async () => {
    server.use(http.get('/admin/api/users/u-ghost', () => envelope(404, 'not_found', 'unknown user')))
    renderApp('/users/u-ghost')
    expect(await screen.findByRole('alert')).toHaveTextContent('unknown user')
  })
})
