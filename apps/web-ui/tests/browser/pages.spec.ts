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
    ['/killswitch/history', 'Killswitch History'],
    ['/killswitch/audit', 'Killswitch Audit Log'],
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

test('devices with open conflicts are marked in the list', async ({ page, stub }) => {
  await stub.set({ deviceTotal: 812 })
  await signIn(page)
  await page.goto('/devices')
  const printer = page.locator('tr[data-mac="aa:bb:cc:00:00:03"]')
  await expect(printer.getByTestId('conflict-badge')).toHaveText('⚠ 2 conflicts')
  await expect(page.getByTestId('conflict-badge')).toHaveCount(1)
  await expect(page.getByTestId('conflict-note')).toContainText(
    '1 device has open conflicts: something on the network is claiming to be it',
  )
  // A binding that is not live yet says so.
  await expect(page.locator('tr[data-mac="aa:bb:cc:00:00:04"]').getByTestId('ip-state')).toHaveText(
    'tentative',
  )
  // GET /devices returns a page; the total comes from X-Total-Count.
  await expect(page.getByTestId('device-total')).toContainText('Showing 4 of 812 devices')
  const list = (await stub.seen()).find((s) => s.path === '/devices')!
  expect(list.search).toBe('?limit=1000')
})

test('a device page puts its conflicts first, saying who claimed what', async ({ page }) => {
  await signIn(page)
  await page.goto('/devices/aa:bb:cc:00:00:03')
  const conflicts = page.getByTestId('device-conflicts')
  await expect(conflicts.getByRole('heading')).toContainText(
    'Something on the network is claiming to be this device (2 conflicts',
  )
  const rows = conflicts.getByTestId('conflict')
  await expect(rows.first()).toContainText(
    "Another device (02:de:ad:be:ef:01) claimed this device's address 192.168.1.79 over ARP.",
  )
  await expect(rows.nth(1)).toContainText('mDNS offered the name "printer-setup" for this device.')
  await expect(rows.first()).toContainText('14')
  // Where each value came from, and how far the address is trusted.
  await expect(page.getByTestId('ip-card')).toContainText('live (re-confirmed recently); from DHCP')
  // Before everything else on the page.
  const order = await page
    .locator('main section')
    .evaluateAll((s) => s.map((e) => e.getAttribute('data-testid') ?? e.className))
  expect(order[0]).toBe('device-conflicts')

  // A device without conflicts shows none.
  await page.goto('/devices/aa:bb:cc:00:00:01')
  await expect(page.getByRole('heading', { level: 1, name: 'kids-tablet' })).toBeVisible()
  await expect(page.getByTestId('device-conflicts')).toHaveCount(0)
})

// A single-device read attaches at most ten and sets conflict_count to how
// many it attached, while the list counts all of them.
test('a device page does not understate conflicts the inventory cut off', async ({
  page,
  stub,
}) => {
  await stub.set({ manyConflicts: true })
  await signIn(page)
  await page.goto('/devices')
  await expect(page.getByTestId('conflict-badge')).toHaveText('⚠ 15 conflicts')
  await page.goto('/devices/aa:bb:cc:00:00:03')
  const conflicts = page.getByTestId('device-conflicts')
  await expect(conflicts.getByRole('heading')).toContainText('(at least 10 conflicts')
  await expect(conflicts.getByTestId('conflict')).toHaveCount(10)
  await expect(conflicts).toContainText('shows the 10 most recent')
})

test('marking a false positive asks first, sends the signal class and says whether it was saved', async ({
  page,
  stub,
}) => {
  await signIn(page)
  await page.goto('/alerts')
  const row = page.locator('tr[data-alert-id="DET-e2e-8"]')

  let question = ''
  page.once('dialog', (d) => {
    question = d.message()
    void d.dismiss()
  })
  await row.getByRole('button', { name: 'Mark FP' }).click()
  await expect.poll(() => question).toContain('30 days')
  expect(question).toContain('no longer reach the killswitch')
  expect(question).toContain('living-room-tv (192.168.1.78)')
  const posts = async () =>
    (await stub.seen()).filter((s) => s.path === '/feedback' && s.method === 'POST')
  expect(await posts()).toEqual([])

  page.once('dialog', (d) => void d.accept())
  await row.getByRole('button', { name: 'Mark FP' }).click()
  await expect(page.getByTestId('feedback-note').first()).toHaveText(
    'Marked 203.0.113.9 as a false positive for 30 days. Saved.',
  )
  await expect(row.getByTestId('fp-marked')).toBeVisible()
  const [sent] = await posts()
  expect(JSON.parse(sent.body)).toEqual({
    alert_id: 'DET-e2e-8',
    matched_ioc: '203.0.113.9',
    client_ip: '192.168.1.78',
    signal_class: 'ids-signature',
    verdict: 'false_positive',
  })
  expect(sent.actor).toBe('Michal')

  const suppression = page.getByTestId('suppressions-table').locator('tr[data-ioc="203.0.113.9"]')
  await expect(suppression).toContainText('ids-signature')
  await expect(suppression).toContainText('192.168.1.78')
  await expect(suppression).toContainText('Michal')
})

test('a verdict the engine could not save is in force but flagged as not saved', async ({
  page,
  stub,
}) => {
  await stub.set({ persistFeedback: false })
  await signIn(page)
  await page.goto('/alerts')
  page.once('dialog', (d) => void d.accept())
  await page
    .locator('tr[data-alert-id="DET-e2e-7"]')
    .getByRole('button', { name: 'Mark FP' })
    .click()
  const note = page.getByTestId('feedback-note').first()
  await expect(note).toContainText('was NOT saved')
  await expect(note).toHaveClass(/note-warn/)
})

test('an active suppression can be lifted', async ({ page, stub }) => {
  await signIn(page)
  await page.goto('/alerts')
  const row = page.locator('tr[data-alert-id="DET-e2e-6"]')
  page.once('dialog', (d) => void d.accept())
  await row.getByRole('button', { name: 'Mark FP' }).click()
  await expect(row.getByTestId('fp-marked')).toBeVisible()

  let question = ''
  page.once('dialog', (d) => {
    question = d.message()
    void d.accept()
  })
  const suppression = page.getByTestId('suppressions-table').locator('tr[data-ioc="d6.example"]')
  await suppression.getByRole('button', { name: 'Lift' }).click()
  await expect(page.getByText('Nothing is suppressed.')).toBeVisible()
  expect(question).toContain('reach the killswitch again')
  await expect(row.getByRole('button', { name: 'Mark FP' })).toBeVisible()
  const lifted = (await stub.seen()).filter((s) => s.path === '/feedback' && s.method === 'POST')
  expect(JSON.parse(lifted.at(-1)!.body)).toMatchObject({
    matched_ioc: 'd6.example',
    client_ip: '192.168.1.77',
    signal_class: 'ioc',
    verdict: 'confirmed',
  })
})

test('the alert pages ask the engine for a bounded number of alerts', async ({ page, stub }) => {
  await signIn(page)
  await page.goto('/alerts')
  await expect(page.locator('tr[data-alert-id="DET-e2e-8"]')).toBeVisible()
  const searches = (await stub.seen()).filter((s) => s.path === '/alerts').map((s) => s.search)
  // The dashboard counts up to 1000; the alerts page starts with 500.
  expect(searches).toEqual(['?limit=1000', '?limit=500'])
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
