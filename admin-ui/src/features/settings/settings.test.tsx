import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { CSRF, SECRET, state } from '@/test/server'

beforeEach(() => {
  state.loggedIn = true
})

async function row(key: string) {
  return within(await screen.findByRole('listitem', { name: key }))
}

function lastMutation() {
  return state.mutations.at(-1)
}

describe('settings', () => {
  it('is reachable from the navigation', async () => {
    const user = userEvent.setup()
    renderApp('/')
    await user.click(await screen.findByRole('link', { name: 'Settings' }))
    expect(await screen.findByRole('heading', { name: 'Settings' })).toBeInTheDocument()
  })

  it('renders the items grouped by group', async () => {
    renderApp('/settings')
    await screen.findByText('GIM_HUB_PUBLIC_URL')
    const titles = ['General', 'Federation', 'Push', 'Limits', 'Storage', 'Users']
    for (const title of titles)
      expect(screen.getByText(title, { selector: '[data-slot=card-title]' })).toBeInTheDocument()

    const federation = screen.getByText('Federation', { selector: '[data-slot=card-title]' }).closest('[data-slot=card]') as HTMLElement
    expect(within(federation).getAllByRole('listitem').map(li => li.getAttribute('aria-label')))
      .toEqual(['GIM_HUB_FEDERATION_ENABLED', 'GIM_HUB_P2P_BOOTSTRAP'])
  })

  it('shows the value, the source and apply badges and the last update', async () => {
    renderApp('/settings')
    const retention = await row('GIM_HUB_EVENT_RETENTION_DAYS')
    expect(retention.getByText('Events older than this are pruned (days)')).toBeInTheDocument()
    expect(retention.getByText('stored')).toBeInTheDocument()
    expect(retention.getByText('live')).toBeInTheDocument()
    expect(retention.getByText('30')).toBeInTheDocument()
    expect(retention.getByText('7')).toBeInTheDocument()
    expect(retention.getByText(/by cli$/)).toBeInTheDocument()

    const url = await row('GIM_HUB_PUBLIC_URL')
    expect(url.getByText('restart required')).toBeInTheDocument()

    const mode = await row('GIM_HUB_USER_LIST_MODE')
    expect(mode.getByText('default')).toBeInTheDocument()
    expect(mode.getByRole('button', { name: 'Reset to default' })).toBeDisabled()

    const retry = await row('GIM_HUB_PUSH_RETRY_SECONDS')
    expect(retry.getAllByText('30 seconds')).toHaveLength(2)
  })

  it('shows environment rows read-only', async () => {
    renderApp('/settings')
    const limit = await row('GIM_HUB_RATE_LIMIT_PER_MINUTE')
    expect(limit.getByText('environment')).toBeInTheDocument()
    expect(limit.getByText(/^Set by environment/)).toBeInTheDocument()
    expect(limit.getByText('120')).toBeInTheDocument()
    expect(limit.queryByRole('button')).not.toBeInTheDocument()
    expect(limit.queryByRole('textbox')).not.toBeInTheDocument()
  })

  it('saves an integer as a JSON number', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const retention = await row('GIM_HUB_EVENT_RETENTION_DAYS')
    await user.click(retention.getByRole('button', { name: 'Edit' }))
    const input = retention.getByLabelText('New value for GIM_HUB_EVENT_RETENTION_DAYS')
    expect(input).toHaveValue(30)
    await user.clear(input)
    await user.type(input, '14')
    await user.click(retention.getByRole('button', { name: 'Save' }))
    expect(await retention.findByText('Saved.')).toBeInTheDocument()
    expect(await retention.findByText('14')).toBeInTheDocument()
    expect(lastMutation()).toEqual({ key: 'PUT /settings/GIM_HUB_EVENT_RETENTION_DAYS', csrf: CSRF, body: { value: 14 } })
  })

  it('shows a 422 message inline and keeps the editor open', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const retention = await row('GIM_HUB_EVENT_RETENTION_DAYS')
    await user.click(retention.getByRole('button', { name: 'Edit' }))
    const input = retention.getByLabelText('New value for GIM_HUB_EVENT_RETENTION_DAYS')
    await user.clear(input)
    await user.type(input, '-3')
    await user.click(retention.getByRole('button', { name: 'Save' }))
    const error = await retention.findByRole('alert')
    expect(error).toHaveTextContent('invalid GIM_HUB_EVENT_RETENTION_DAYS: expected a non-negative integer')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAttribute('aria-describedby', error.id)
    expect(lastMutation()?.body).toEqual({ value: -3 })

    await user.click(retention.getByRole('button', { name: 'Cancel' }))
    expect(retention.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('saves a duration in seconds', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const retry = await row('GIM_HUB_PUSH_RETRY_SECONDS')
    await user.click(retry.getByRole('button', { name: 'Edit' }))
    expect(retry.getByText('In seconds.')).toBeInTheDocument()
    const input = retry.getByLabelText('New value for GIM_HUB_PUSH_RETRY_SECONDS')
    await user.clear(input)
    await user.type(input, '90')
    await user.click(retry.getByRole('button', { name: 'Save' }))
    expect(await retry.findByText('90 seconds')).toBeInTheDocument()
    expect(lastMutation()?.body).toEqual({ value: 90 })
  })

  it('saves a string and a url', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const topic = await row('GIM_HUB_PUSH_TOPIC')
    await user.click(topic.getByRole('button', { name: 'Edit' }))
    const input = topic.getByLabelText('New value for GIM_HUB_PUSH_TOPIC')
    await user.clear(input)
    await user.type(input, 'gim-athens')
    await user.click(topic.getByRole('button', { name: 'Save' }))
    expect(await topic.findByText('gim-athens')).toBeInTheDocument()
    expect(lastMutation()?.body).toEqual({ value: 'gim-athens' })

    const url = await row('GIM_HUB_PUBLIC_URL')
    await user.click(url.getByRole('button', { name: 'Edit' }))
    const urlInput = url.getByLabelText('New value for GIM_HUB_PUBLIC_URL')
    expect(urlInput).toHaveValue('https://hub.athens.example')
    await user.clear(urlInput)
    await user.type(urlInput, 'https://hub.split.example')
    await user.click(url.getByRole('button', { name: 'Save' }))
    expect(await url.findByText('https://hub.split.example')).toBeInTheDocument()
    expect(lastMutation()).toEqual({ key: 'PUT /settings/GIM_HUB_PUBLIC_URL', csrf: CSRF, body: { value: 'https://hub.split.example' } })
  })

  it('saves a bool with the switch', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const enabled = await row('GIM_HUB_FEDERATION_ENABLED')
    expect(enabled.getAllByText('off')).toHaveLength(2)
    await user.click(enabled.getByRole('button', { name: 'Edit' }))
    const toggle = enabled.getByRole('switch', { name: 'New value for GIM_HUB_FEDERATION_ENABLED' })
    expect(toggle).not.toBeChecked()
    await user.click(toggle)
    expect(toggle).toBeChecked()
    await user.click(enabled.getByRole('button', { name: 'Save' }))
    expect(await enabled.findByText('on')).toBeInTheDocument()
    expect(lastMutation()?.body).toEqual({ value: true })
  })

  it('saves an enum with the select', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const mode = await row('GIM_HUB_USER_LIST_MODE')
    await user.click(mode.getByRole('button', { name: 'Edit' }))
    await user.click(mode.getByRole('combobox', { name: 'New value for GIM_HUB_USER_LIST_MODE' }))
    await user.click(await screen.findByRole('option', { name: 'deny' }))
    await user.click(mode.getByRole('button', { name: 'Save' }))
    expect(await mode.findByText('Saved.')).toBeInTheDocument()
    expect(lastMutation()?.body).toEqual({ value: 'deny' })
  })

  it('sends a list as a JSON array, one entry per line', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const bootstrap = await row('GIM_HUB_P2P_BOOTSTRAP')
    await user.click(bootstrap.getByRole('button', { name: 'Edit' }))
    expect(bootstrap.getByText('One entry per line.')).toBeInTheDocument()
    const input = bootstrap.getByLabelText('New value for GIM_HUB_P2P_BOOTSTRAP')
    await user.type(input, '/dns4/split.example/tcp/4001\n\n  /dns4/zadar.example/tcp/4001  \n')
    await user.click(bootstrap.getByRole('button', { name: 'Save' }))
    expect(await bootstrap.findByText('/dns4/split.example/tcp/4001, /dns4/zadar.example/tcp/4001')).toBeInTheDocument()
    expect(lastMutation()?.body).toEqual({ value: ['/dns4/split.example/tcp/4001', '/dns4/zadar.example/tcp/4001'] })

    await user.click(bootstrap.getByRole('button', { name: 'Edit' }))
    expect(bootstrap.getByLabelText('New value for GIM_HUB_P2P_BOOTSTRAP'))
      .toHaveValue('/dns4/split.example/tcp/4001\n/dns4/zadar.example/tcp/4001')
  })

  it('keeps secrets write-only', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const secret = await row('GIM_HUB_PUSH_WEBHOOK_SECRET')
    expect(secret.getByText('not set')).toBeInTheDocument()
    expect(secret.getByRole('button', { name: 'Clear' })).toBeDisabled()

    await user.click(secret.getByRole('button', { name: 'Replace' }))
    const input = secret.getByLabelText('New value for GIM_HUB_PUSH_WEBHOOK_SECRET')
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveValue('')
    expect(secret.getByRole('button', { name: 'Save' })).toBeDisabled()
    await user.type(input, SECRET)
    await user.click(secret.getByRole('button', { name: 'Save' }))

    expect(await secret.findByText('set')).toBeInTheDocument()
    expect(lastMutation()?.body).toEqual({ value: SECRET })
    expect(document.body).not.toHaveTextContent(SECRET)

    // Replacing again starts from an empty field; the stored value is never shown.
    await user.click(secret.getByRole('button', { name: 'Replace' }))
    expect(secret.getByLabelText('New value for GIM_HUB_PUSH_WEBHOOK_SECRET')).toHaveValue('')
    await user.click(secret.getByRole('button', { name: 'Cancel' }))

    await user.click(secret.getByRole('button', { name: 'Clear' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Clear' }))
    expect(await secret.findByText('Cleared.')).toBeInTheDocument()
    expect(await secret.findByText('not set')).toBeInTheDocument()
    expect(lastMutation()).toEqual({ key: 'DELETE /settings/GIM_HUB_PUSH_WEBHOOK_SECRET', csrf: CSRF, body: undefined })
  })

  it('resets to the default after confirmation', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const retention = await row('GIM_HUB_EVENT_RETENTION_DAYS')
    await user.click(retention.getByRole('button', { name: 'Reset to default' }))
    const dialog = within(await screen.findByRole('alertdialog'))
    expect(dialog.getByText(/GIM_HUB_EVENT_RETENTION_DAYS is removed; the default \(7\) applies/)).toBeInTheDocument()
    await user.click(dialog.getByRole('button', { name: 'Cancel' }))
    expect(state.mutations).toEqual([])

    await user.click(retention.getByRole('button', { name: 'Reset to default' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Reset to default' }))
    expect(await retention.findByText('Reset to default.')).toBeInTheDocument()
    expect(retention.getByText('default')).toBeInTheDocument()
    expect(state.mutations).toEqual([{ key: 'DELETE /settings/GIM_HUB_EVENT_RETENTION_DAYS', csrf: CSRF, body: undefined }])
  })

  it('shows no restart banner while nothing is pending', async () => {
    renderApp('/settings')
    await screen.findByText('GIM_HUB_PUBLIC_URL')
    expect(screen.queryByText('Restart required')).not.toBeInTheDocument()
  })

  it('offers a confirmed restart through lode when supervised', async () => {
    const user = userEvent.setup()
    state.settings = state.settings.map(s => (s.key === 'GIM_HUB_PUBLIC_URL' ? { ...s, restart_pending: true } : s))
    renderApp('/settings')
    expect(await screen.findByText('Restart required')).toBeInTheDocument()
    expect((await row('GIM_HUB_PUBLIC_URL')).getByText('pending restart')).toBeInTheDocument()

    await user.click(await screen.findByRole('button', { name: 'Restart now' }))
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Restart now' }))
    expect(await screen.findByText('Restart requested.')).toBeInTheDocument()
    expect(state.mutations).toEqual([{ key: 'POST /lode/restart', csrf: CSRF, body: undefined }])
  })

  it('asks for a manual restart when not supervised', async () => {
    state.lodeSupervised = false
    state.settings = state.settings.map(s => (s.key === 'GIM_HUB_PUBLIC_URL' ? { ...s, restart_pending: true } : s))
    renderApp('/settings')
    expect(await screen.findByText('Restart the hub to apply.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Restart now' })).not.toBeInTheDocument()
  })

  it('shows the banner after saving a restart setting', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const enabled = await row('GIM_HUB_FEDERATION_ENABLED')
    await user.click(enabled.getByRole('button', { name: 'Edit' }))
    await user.click(enabled.getByRole('switch'))
    await user.click(enabled.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Restart required')).toBeInTheDocument()
    expect(await enabled.findByText('pending restart')).toBeInTheDocument()
  })

  it('renders in Chinese', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    await screen.findByText('GIM_HUB_PUBLIC_URL')
    await user.click(screen.getByRole('button', { name: 'Switch language to 中文' }))
    expect(await screen.findByRole('heading', { name: '设置' })).toBeInTheDocument()
    expect((await row('GIM_HUB_RATE_LIMIT_PER_MINUTE')).getByText('环境变量')).toBeInTheDocument()
  })
})
