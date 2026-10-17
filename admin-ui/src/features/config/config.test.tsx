import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { state } from '@/test/server'

describe('configuration', () => {
  it('marks redacted and unset values', async () => {
    state.loggedIn = true
    renderApp('/config')
    expect(await screen.findByText('0.0.0.0:8080')).toBeInTheDocument()
    expect(screen.getByText('GIM_HUB_PUSH_WEBHOOK_SECRET').nextSibling).toHaveTextContent('redacted')
    expect(screen.getByText('GIM_HUB_PUBLIC_URL').nextSibling).toHaveTextContent('unset')
  })
})
