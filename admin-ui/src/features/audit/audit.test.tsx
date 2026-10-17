import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { state } from '@/test/server'

describe('audit log', () => {
  it('pages through entries with the cursor', async () => {
    state.loggedIn = true
    const user = userEvent.setup()
    renderApp('/audit')
    expect(await screen.findByText('user_suspend')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText('login_ok')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument()
  })
})
