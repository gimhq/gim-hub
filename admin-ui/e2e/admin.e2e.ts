import process from 'node:process'
import { expect, test } from '@playwright/test'

function env(name: string): string {
  const value = process.env[name]
  if (!value)
    throw new Error(`${name} is not set (run scripts/admin-e2e.sh)`)
  return value
}

const token = env('E2E_TOKEN')
const userId = env('E2E_USER_ID')
const handle = env('E2E_HANDLE')
const deviceId = env('E2E_DEVICE_ID')
const sessionRef = env('E2E_SESSION_REF')
const newHub = env('E2E_NEW_HUB')
const clientUrl = env('E2E_CLIENT_URL')
const retentionKey = env('E2E_RETENTION_KEY')
const retentionDays = Number(env('E2E_RETENTION_DAYS'))
const envKey = env('E2E_ENV_KEY')
const envValue = Number(env('E2E_ENV_VALUE'))
const otherDeviceId = env('E2E_OTHER_DEVICE_ID')

function log(message: string) {
  process.stdout.write(`admin-e2e: ${message}\n`)
}

test('admin UI end to end', async ({ page, request }) => {
  const nav = page.getByRole('navigation')

  await test.step('1. login with the token', async () => {
    await page.goto('/admin/')
    await expect(page).toHaveURL(/\/admin\/login/)
    await page.getByLabel('Admin token').fill(token)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible()
    log('ok   1. logged in with the token, overview shown')
  })

  await test.step('2. search the user and open the detail', async () => {
    await nav.getByRole('link', { name: 'Users' }).click()
    await page.getByLabel('Search users').fill(handle)
    await page.getByRole('button', { name: 'Search' }).click()
    await expect(page).toHaveURL(new RegExp(`q=${handle}`))
    await page.getByRole('link', { name: userId }).click()
    await expect(page.getByRole('heading', { name: `User ${userId}` })).toBeVisible()
    await expect(page.getByRole('cell', { name: deviceId })).toBeVisible()
    await expect(page.getByText(sessionRef)).toBeVisible()
    log(`ok   2. found ${handle}, detail of ${userId} shows device ${deviceId} with session ${sessionRef}`)
  })

  await test.step('3. revoke the device sessions', async () => {
    const row = page.getByRole('row').filter({ hasText: deviceId })
    await row.getByRole('button', { name: 'Revoke sessions' }).click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Revoke sessions' }).click()
    await expect(page.getByRole('status')).toHaveText('Revoked 1 session.')
    await expect(page.getByText(sessionRef)).toBeHidden()
    const detail = await page.request.get(`/admin/api/users/${userId}`)
    expect(detail.status()).toBe(200)
    const body = await detail.json()
    const device = body.devices.find((d: { device_id: string }) => d.device_id === deviceId)
    expect(device.sessions).toEqual([])
    log('ok   3. revoked 1 session; the UI and GET /admin/api/users/{id} show none left')
  })

  await test.step('4. edit the allowlist', async () => {
    await nav.getByRole('link', { name: 'Federation' }).click()
    const editor = page.getByLabel('Allowlist file')
    await expect(editor).toBeVisible()
    const before = await editor.inputValue()
    await editor.fill(`${before.trimEnd()}\n${newHub} /dns4/hub-new.example.eu/tcp/4001\n`)
    await page.getByRole('button', { name: 'Save and apply' }).click()
    await expect(page.getByText('Allowlist saved and applied.')).toBeVisible()
    const allowlist = await page.request.get('/admin/api/federation/allowlist')
    expect(allowlist.status()).toBe(200)
    const body = await allowlist.json()
    expect(body.source).toBe('stored')
    expect(body.read_only).toBe(false)
    expect(body.text).toContain(newHub)
    expect(body.entries.map((entry: { hub_id: string }) => entry.hub_id)).toContain(newHub)
    log(`ok   4. allowlist (source ${body.source}) saved with ${newHub}; GET returns ${body.entries.length} entries`)
  })

  await test.step('5. lode: check now', async () => {
    await nav.getByRole('link', { name: 'lode' }).click()
    await expect(page.getByText('0.3.1')).toBeVisible()
    await page.getByRole('button', { name: 'Check now' }).click()
    await expect(page.getByRole('status')).toHaveText('Update check requested.')
    log('ok   5. lode panel (current 0.3.0, available 0.3.1): check requested')
  })

  await test.step('6. audit log', async () => {
    await nav.getByRole('link', { name: 'Audit log' }).click()
    for (const action of ['device_sessions_revoke', 'allowlist_update', 'lode_check']) {
      const row = page.getByRole('row').filter({ has: page.getByRole('cell', { name: action, exact: true }) })
      await expect(row.first()).toBeVisible()
      await expect(row.first()).toContainText('token')
    }
    await expect(page.getByRole('cell', { name: `${userId}/${deviceId}` })).toBeVisible()
    log('ok   6. audit log lists device_sessions_revoke, allowlist_update and lode_check by token')
  })

  await test.step('7. no /admin/ on the client listener', async () => {
    const response = await request.get(`${clientUrl}/admin/`)
    expect(response.status()).toBe(404)
    log(`ok   7. GET ${clientUrl}/admin/ -> 404`)
  })

  await test.step('8. edit a live setting', async () => {
    await nav.getByRole('link', { name: 'Settings' }).click()
    const row = page.getByRole('listitem', { name: retentionKey, exact: true })
    await expect(row.getByText('default', { exact: true })).toBeVisible()
    await expect(row.getByText('live', { exact: true })).toBeVisible()
    await row.getByRole('button', { name: 'Edit' }).click()
    await row.getByLabel(`New value for ${retentionKey}`).fill(String(retentionDays))
    await row.getByRole('button', { name: 'Save' }).click()
    await expect(row.getByRole('status')).toHaveText('Saved.')
    await expect(row.getByText('stored', { exact: true })).toBeVisible()
    await expect(row.getByText(/ by token$/)).toBeVisible()

    const item = await (await page.request.get(`/admin/api/settings/${retentionKey}`)).json()
    expect(item).toMatchObject({ value: retentionDays, source: 'stored', read_only: false, apply: 'live', updated_by: 'token' })
    // Applied at once: the overview reports the running hub's retention.
    const overview = await (await page.request.get('/admin/api/overview')).json()
    expect(overview.event_retention_days).toBe(retentionDays)
    await nav.getByRole('link', { name: 'Overview' }).click()
    await expect(page.getByText(`${retentionDays} days`)).toBeVisible()
    log(`ok   8. ${retentionKey} 7 -> ${retentionDays} in the UI; GET item source stored, overview retention ${overview.event_retention_days} days`)
  })

  await test.step('9. a setting from the environment is read-only', async () => {
    await nav.getByRole('link', { name: 'Settings' }).click()
    const row = page.getByRole('listitem', { name: envKey, exact: true })
    await expect(row.getByText('environment', { exact: true })).toBeVisible()
    await expect(row.getByText(/^Set by environment/)).toBeVisible()
    await expect(row.getByText(String(envValue), { exact: true })).toBeVisible()
    await expect(row.getByRole('button')).toHaveCount(0)

    const item = await (await page.request.get(`/admin/api/settings/${envKey}`)).json()
    expect(item).toMatchObject({ value: envValue, source: 'env', read_only: true })
    const session = await (await page.request.get('/admin/api/session')).json()
    const put = await page.request.put(`/admin/api/settings/${envKey}`, {
      headers: { 'X-CSRF-Token': session.csrf_token },
      data: { value: envValue + 1 },
    })
    expect(put.status()).toBe(409)
    const error = (await put.json()).error
    expect(error.code).toBe('conflict')
    log(`ok   9. ${envKey}=${envValue} from env: row read-only (no buttons); PUT -> 409 ${error.code} "${error.message}"`)
  })

  await test.step('10. user policy: deny the seeded user, then open again', async () => {
    const sessions = async () => {
      const body = await (await page.request.get(`/admin/api/users/${userId}`)).json()
      return body.devices.flatMap((d: { sessions: unknown[] }) => d.sessions).length
    }
    expect(await sessions()).toBe(1)

    await nav.getByRole('link', { name: 'Settings' }).click()
    const row = page.getByRole('listitem', { name: 'GIM_HUB_USER_POLICY', exact: true })
    await row.getByRole('button', { name: 'Edit' }).click()
    await row.getByRole('combobox', { name: 'New value for GIM_HUB_USER_POLICY' }).click()
    await page.getByRole('option', { name: 'deny' }).click()
    await row.getByRole('button', { name: 'Save' }).click()
    await expect(row.getByRole('status')).toHaveText('Saved.')

    await nav.getByRole('link', { name: 'User policy' }).click()
    await expect(page.getByText('Every user except those on the list is admitted.')).toBeVisible()
    await page.getByLabel('Handle or user ID').fill(`@${handle}`)
    await page.getByLabel('Note').fill('e2e')
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    const entry = page.getByRole('row').filter({ has: page.getByRole('cell', { name: userId }) })
    await expect(entry).toContainText(`@${handle}`)
    await expect(page.getByText('1 user of this hub is not admitted')).toBeVisible()

    // Applied at once: the sessions (here of the second device) are gone and
    // sign-in is refused.
    expect(await sessions()).toBe(0)
    const challenge = await request.post(`${clientUrl}/v2/auth/challenge`, {
      data: { user_id: userId, device_id: otherDeviceId },
    })
    expect(challenge.status()).toBe(403)
    expect(await challenge.json()).toEqual({
      error: { code: 'user_not_admitted', message: 'user is not admitted on this hub' },
    })
    log(`ok   10. GIM_HUB_USER_POLICY=deny with @${handle} listed: sessions deleted, POST /v2/auth/challenge -> 403 user_not_admitted`)

    await entry.getByRole('button', { name: 'Remove' }).click()
    await page.getByRole('alertdialog').getByRole('button', { name: 'Remove' }).click()
    await expect(page.getByText('The list is empty.')).toBeVisible()
    await page.getByRole('combobox', { name: 'New mode' }).click()
    await page.getByRole('option', { name: 'open' }).click()
    await page.getByRole('button', { name: 'Apply mode' }).click()
    await expect(page.getByText('Every user is admitted; the list is kept but not enforced.')).toBeVisible()
    const policy = await (await page.request.get('/admin/api/users/policy')).json()
    expect(policy).toMatchObject({ mode: 'open', mode_source: 'stored', not_admitted_users: 0, entries: [] })
    const reopened = await request.post(`${clientUrl}/v2/auth/challenge`, {
      data: { user_id: userId, device_id: otherDeviceId },
    })
    expect(reopened.status()).toBe(200)
    log('ok   10. removed from the list, mode back to open; POST /v2/auth/challenge -> 200')
  })
})
