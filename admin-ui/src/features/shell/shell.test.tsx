import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { state } from '@/test/server'

describe('shell', () => {
  it('switches the language to Chinese and back, and persists the choice', async () => {
    state.loggedIn = true
    const user = userEvent.setup()
    renderApp('/')
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Switch language to 中文' }))
    expect(await screen.findByRole('heading', { name: '概览' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: '用户' })).toBeInTheDocument()
    expect(localStorage.getItem('gim-admin-lang')).toBe('zh-CN')
    expect(document.documentElement.lang).toBe('zh-CN')

    await user.click(screen.getByRole('button', { name: '切换语言为 English' }))
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument()
  })

  it('offers the language switch on the login page', async () => {
    const user = userEvent.setup()
    renderApp('/login')
    await user.click(await screen.findByRole('button', { name: 'Switch language to 中文' }))
    expect(await screen.findByLabelText('管理员令牌')).toBeInTheDocument()
  })

  it('cycles the theme and persists it', async () => {
    state.loggedIn = true
    const user = userEvent.setup()
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: 'Theme: system' }))
    expect(localStorage.getItem('gim-admin-theme')).toBe('light')
    expect(document.documentElement).not.toHaveClass('dark')
    await user.click(screen.getByRole('button', { name: 'Theme: light' }))
    expect(localStorage.getItem('gim-admin-theme')).toBe('dark')
    expect(document.documentElement).toHaveClass('dark')
  })
})
