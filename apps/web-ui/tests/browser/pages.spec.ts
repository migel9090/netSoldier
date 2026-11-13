import { test, expect, signIn } from './fixtures'
import { IDS_SUMMARY } from './stub/backends'

test('every page renders without CSP violations or console errors', async ({ page, problems }) => {
  await page.goto('/login')
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeEnabled()
  await signIn(page)

  const pages: [string, string][] = [
    ['/', 'Dashboard'],
    ['/devices', 'Devices'],
    ['/devices/aa:bb:cc:00:00:01', 'kids-tablet'],
    ['/map', 'Device Map'],
    ['/alerts', 'Alerts'],
    ['/killswitch', 'Killswitch'],
  ]
  for (const [path, heading] of pages) {
    await page.goto(path)
    // Rendered by the client: a blocked boot script leaves the page empty.
    await expect(page.getByRole('heading', { level: 1, name: heading }), path).toBeVisible()
    await expect(page.locator('.loading')).toHaveCount(0)
    expect(await problems.cspViolations(), path).toEqual([])
  }
  expect(problems.failedResponses).toEqual([])
  expect(problems.consoleErrors).toEqual([])
})

test('a device detail page loads by MAC from the device list', async ({ page }) => {
  await signIn(page)
  await page.goto('/devices')
  await page.getByRole('link', { name: 'aa:bb:cc:00:00:01' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'kids-tablet' })).toBeVisible()
  await expect(page.getByText('192.168.1.77')).toBeVisible()
  await expect(page.getByText('Device not found')).toHaveCount(0)
  // Device alerts newest first, headed by the summary even without a domain.
  const headlines = page.getByTestId('device-alerts').getByTestId('alert-headline')
  await expect(headlines).toHaveText([
    'Suricata: ET POLICY outbound telnet',
    /^DNS query for dev2\.example\s*dev2\.example$/,
    /^DNS query for dev1\.example\s*dev1\.example$/,
  ])
})

test('the dashboard lists the newest alerts first, headed by their summary', async ({ page }) => {
  await signIn(page)
  const rows = page.getByTestId('recent-alerts').locator('tbody tr')
  await expect(rows.getByTestId('alert-headline')).toHaveText([
    IDS_SUMMARY,
    /^DNS query for d7\.example, listed by ThreatFox\s*d7\.example$/,
    /^DNS query for d6\.example/,
    /^DNS query for d5\.example/,
    /^DNS query for d4\.example/,
  ])
  await expect(rows.first().getByTestId('alert-client')).toHaveText(
    /^living-room-tv\s*192\.168\.1\.78$/,
  )
  await expect(page.getByTestId('alert-count')).toHaveText('8')
})

test('an IDS alert without a domain shows its summary and device, with no empty cells', async ({
  page,
}) => {
  await signIn(page)
  await page.goto('/alerts')
  const row = page.locator('tr[data-alert-id="DET-e2e-8"]')
  await expect(row.getByTestId('alert-headline')).toHaveText(
    new RegExp(`^${IDS_SUMMARY}\\s*ids-signature$`),
  )
  await expect(row.getByTestId('alert-client')).toHaveText(
    /^living-room-tv\s*aa:bb:cc:00:00:02\s*192\.168\.1\.78\s*$/,
  )
  for (const text of await row.locator('td').allInnerTexts()) expect(text.trim()).not.toBe('')
  // The device links to its detail page by MAC.
  await row.getByRole('link', { name: 'aa:bb:cc:00:00:02' }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'living-room-tv' })).toBeVisible()
})

test('alerts from an engine that predates contract v2 fall back to the domain', async ({
  page,
  stub,
}) => {
  await stub.set({ alertsShape: 'v1' })
  await signIn(page)
  await expect(page.getByTestId('recent-alerts').getByTestId('alert-headline').first()).toHaveText(
    'd8.example',
  )
  await page.goto('/alerts')
  const row = page.locator('tr[data-alert-id="DET-8"]')
  await expect(row.getByTestId('alert-headline')).toHaveText(/^d8\.example\s*ioc$/)
  for (const text of await row.locator('td').allInnerTexts()) expect(text.trim()).not.toBe('')
})

test('a backend outage is shown as an error, not as zero', async ({ page, stub }) => {
  await signIn(page)
  await stub.set({ down: ['detection-engine'] })
  await page.goto('/')
  await expect(page.getByTestId('dashboard-error')).toContainText('Detection engine')
  await expect(page.getByTestId('alert-count')).toHaveText('—')
  await expect(page.getByTestId('device-count')).toHaveText('4')
})

test('a backend refusing the API key is a configuration error, not a sign-out', async ({
  page,
  stub,
}) => {
  await signIn(page)
  await stub.set({ rejectKey: ['killswitch'] })
  await page.goto('/killswitch')
  await expect(page.locator('p.error')).toContainText('KILLSWITCH_API_KEY')
  await expect(page).toHaveURL(/\/killswitch$/)
})

test('the backends get the API keys and the actor; the browser never sees a key', async ({
  page,
  stub,
}) => {
  const keys: string[] = []
  page.on('response', async (r) => {
    if (r.url().includes('/api/')) keys.push(await r.text().catch(() => ''))
  })
  await signIn(page, 'Anna')
  await page.goto('/killswitch')
  await expect(page.getByTestId('pending-table')).toBeVisible()

  const seen = await stub.seen()
  expect(seen.length).toBeGreaterThan(0)
  for (const s of seen) {
    expect(s.authorization, `${s.service} ${s.path}`).toMatch(/^Bearer e2e-/)
    expect(s.actor).toBe('Anna')
  }
  expect(keys.join('\n')).not.toContain('e2e-killswitch-operator-token')
})
