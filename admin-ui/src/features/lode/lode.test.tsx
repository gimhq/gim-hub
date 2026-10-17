import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { CSRF, state } from '@/test/server'

beforeEach(() => {
  state.loggedIn = true
})

describe('lode', () => {
  it('hides the nav entry when lode does not supervise the hub', async () => {
    state.lodeSupervised = false
    renderApp('/')
    const nav = await screen.findByRole('navigation')
    await within(nav).findByRole('link', { name: 'Users' })
    // Let the lode query settle before asserting absence.
    await screen.findByText('hub-athens')
    expect(within(nav).queryByRole('link', { name: 'lode' })).not.toBeInTheDocument()
  })

  it('shows the nav entry and the panel when supervised', async () => {
    const user = userEvent.setup()
    renderApp('/')
    await user.click(await screen.findByRole('link', { name: 'lode' }))
    expect(await screen.findByText('0.10.0')).toBeInTheDocument()
    expect(screen.getByText('0.8.2')).toBeInTheDocument()
    expect(screen.getByText('running')).toBeInTheDocument()
    expect(screen.getByText('good')).toBeInTheDocument()
  })

  it('checks now with the CSRF token', async () => {
    const user = userEvent.setup()
    renderApp('/lode')
    await user.click(await screen.findByRole('button', { name: 'Check now' }))
    expect(await screen.findByText('Update check requested.')).toBeInTheDocument()
    expect(state.mutations).toEqual([{ key: 'POST /lode/check', csrf: CSRF, body: undefined }])
  })

  it('updates to the available version after confirmation', async () => {
    const user = userEvent.setup()
    renderApp('/lode')
    await user.click(await screen.findByRole('button', { name: 'Update to available' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Update to available' }))
    expect(await screen.findByText('Update requested.')).toBeInTheDocument()
    expect(state.mutations).toEqual([{ key: 'POST /lode/update', csrf: CSRF, body: { version: '0.10.0' } }])
  })

  it('restarts and rolls back after confirmation', async () => {
    const user = userEvent.setup()
    renderApp('/lode')
    await user.click(await screen.findByRole('button', { name: 'Restart' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Restart' }))
    expect(await screen.findByText('Restart requested.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Roll back' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Roll back' }))
    expect(await screen.findByText('Rollback requested.')).toBeInTheDocument()
    expect(state.mutations.map(m => [m.key, m.csrf])).toEqual([
      ['POST /lode/restart', CSRF],
      ['POST /lode/rollback', CSRF],
    ])
  })

  it('shows a notice on the lode page when not supervised', async () => {
    state.lodeSupervised = false
    renderApp('/lode')
    expect(await screen.findByText('This hub is not running under the lode supervisor.')).toBeInTheDocument()
  })
})
