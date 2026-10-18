import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { CSRF, state } from '@/test/server'
import { addTarget, listText } from './api'

function setMode(mode: string, source = 'stored') {
  state.settings = state.settings.map(s =>
    s.key === 'GIM_HUB_USER_POLICY' ? { ...s, value: mode, source, read_only: source === 'env' } : s)
}

beforeEach(() => {
  state.loggedIn = true
})

describe('user policy', () => {
  it('changes the mode through the settings API', async () => {
    const user = userEvent.setup()
    renderApp('/user-policy')
    expect(await screen.findByText('Every user is admitted; the list is kept but not enforced.')).toBeInTheDocument()
    expect(screen.getByText('The list is empty.')).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: 'New mode' }))
    await user.click(await screen.findByRole('option', { name: 'deny list' }))
    await user.click(screen.getByRole('button', { name: 'Apply mode' }))
    expect(await screen.findByText('Every user except those on the list is admitted.')).toBeInTheDocument()
    expect(state.mutations.at(-1)).toEqual({ key: 'PUT /settings/GIM_HUB_USER_POLICY', csrf: CSRF, body: { value: 'deny' } })
  })

  it('links to the settings when the environment sets the mode', async () => {
    setMode('deny', 'env')
    renderApp('/user-policy')
    expect(await screen.findByText(/^Set by the GIM_HUB_USER_POLICY environment variable/)).toBeInTheDocument()
    expect(screen.getByText('environment')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open settings' })).toHaveAttribute('href', '/admin/settings')
    expect(screen.queryByRole('combobox', { name: 'New mode' })).not.toBeInTheDocument()
  })

  it('warns that allow mode with an empty list admits nobody', async () => {
    setMode('allow')
    renderApp('/user-policy')
    expect(await screen.findByText('No user is admitted')).toBeInTheDocument()
    expect(screen.queryByText(/users of this hub are not admitted/)).not.toBeInTheDocument()
  })

  it('adds by handle, warns about locked-out users and removes with a confirmation', async () => {
    setMode('deny')
    const user = userEvent.setup()
    renderApp('/user-policy')
    await user.type(await screen.findByLabelText('Handle or user ID'), '@alice')
    await user.type(screen.getByLabelText('Note'), 'spam')
    await user.click(screen.getByRole('button', { name: 'Add' }))

    const row = (await screen.findByRole('cell', { name: 'u-alice' })).closest('tr')!
    expect(within(row).getByText('@alice')).toBeInTheDocument()
    expect(within(row).getByText('spam')).toBeInTheDocument()
    expect(state.mutations.at(-1)).toEqual({ key: 'POST /users/policy/entries', csrf: CSRF, body: { handle: 'alice', note: 'spam' } })
    expect(screen.getByText('1 user of this hub is not admitted')).toBeInTheDocument()
    expect(screen.getByLabelText('User IDs')).toHaveValue('u-alice\n')

    await user.click(within(row).getByRole('button', { name: 'Remove' }))
    const dialog = within(await screen.findByRole('alertdialog'))
    expect(dialog.getByText('@alice is removed from the user list. The change applies at once.')).toBeInTheDocument()
    await user.click(dialog.getByRole('button', { name: 'Remove' }))
    expect(await screen.findByText('The list is empty.')).toBeInTheDocument()
    expect(state.mutations.at(-1)?.key).toBe('DELETE /users/policy/entries/u-alice')
  })

  it('shows an add error inline', async () => {
    const user = userEvent.setup()
    renderApp('/user-policy')
    await user.type(await screen.findByLabelText('Handle or user ID'), '@nobody')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('not found')
    expect(screen.getByLabelText('Handle or user ID')).toHaveAttribute('aria-invalid', 'true')
  })

  it('shows the 422 line error inline, then replaces the list', async () => {
    const user = userEvent.setup()
    renderApp('/user-policy')
    const editor = await screen.findByLabelText('User IDs')
    await user.type(editor, 'u-bob # suspended{enter}not valid')
    await user.click(screen.getByRole('button', { name: 'Replace list' }))
    const error = await screen.findByText('line 2: invalid user ID "not valid"')
    expect(error).toHaveAttribute('id', 'user-policy-text-error')
    expect(editor).toHaveAttribute('aria-invalid', 'true')

    await user.clear(editor)
    await user.type(editor, 'u-bob # suspended')
    await user.click(screen.getByRole('button', { name: 'Replace list' }))
    expect(await screen.findByRole('cell', { name: 'u-bob' })).toBeInTheDocument()
    expect(state.mutations.at(-1)).toEqual({ key: 'PUT /users/policy', csrf: CSRF, body: { text: 'u-bob # suspended' } })
  })

  it('tells handles from user IDs and renders the list as text', () => {
    expect(addTarget(' @Alice ', '')).toEqual({ handle: 'Alice' })
    expect(addTarget('bob_1', ' note ')).toEqual({ handle: 'bob_1', note: 'note' })
    const id = 'uciqgytfj5l477ei2pprxmxv2dgxqygyfkj4b6ho7onbwmqrwamhwaaa'
    expect(addTarget(id, '')).toEqual({ user_id: id })
    expect(listText([])).toBe('')
  })
})
