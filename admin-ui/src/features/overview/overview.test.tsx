import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { state } from '@/test/server'

describe('overview', () => {
  it('renders version, uptime, storage, counts, push counters and retention', async () => {
    state.loggedIn = true
    renderApp('/')
    expect(await screen.findByText('0.9.0 (abc1234)')).toBeInTheDocument()
    expect(screen.getByText('1 d 2 h 3 min')).toBeInTheDocument()
    expect(screen.getByText('5 MiB')).toBeInTheDocument()
    expect(screen.getByText('1 KiB')).toBeInTheDocument()
    expect(screen.getByText('30 days')).toBeInTheDocument()
    expect(screen.getByText('Invalid token')).toBeInTheDocument()
    expect(screen.getByText('Coalesced').nextSibling).toHaveTextContent('1')
  })
})
