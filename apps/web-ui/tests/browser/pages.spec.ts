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
  // When it ends comes from the engine's list (expires_at), read back.
  await expect(page.getByTestId('feedback-note').first()).toHaveText(
    /^Marked 203\.0\.113\.9 as a false positive: silenced until .+ \(30 days left\)\. Saved\.$/,
  )
  await expect(row.getByTestId('fp-marked')).toBeVisible()
  await expect(row).toContainText('30 days left')
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
  await expect(note).toContainText('forgotten when the engine restarts')
  await expect(note).toHaveClass(/note-warn/)
})

const feedbackPosts = async (stub: { seen: () => Promise<{ path: string; method: string }[]> }) =>
  (await stub.seen()).filter((s) => s.method === 'POST' && s.path.startsWith('/feedback'))

// A "confirmed" verdict used to stand in for this, recording the indicator
// as a true positive.
test('lifting a suppression ends that one suppression, and records no verdict', async ({
  page,
  stub,
}) => {
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
  await expect(page.getByTestId('feedback-note').first()).toHaveText(
    'Lifted the suppression of d6.example (ioc) on 192.168.1.77. Saved.',
  )
  await expect(page.getByText('Nothing is suppressed.')).toBeVisible()
  expect(question).toContain('reach the killswitch again')
  expect(question).toContain('does not record the indicator as malicious')
  await expect(row.getByRole('button', { name: 'Mark FP' })).toBeVisible()

  const [verdict, lifted, ...more] = await feedbackPosts(stub)
  expect(more).toEqual([])
  expect(verdict.path).toBe('/feedback')
  expect(lifted.path).toBe('/feedback/lift')
  const sent = (await stub.seen()).find((s) => s.path === '/feedback/lift')!
  expect(JSON.parse(sent.body)).toEqual({
    matched_ioc: 'd6.example',
    client_ip: '192.168.1.77',
    signal_class: 'ioc',
    reason: 'suppression lifted in the web UI',
  })
  expect(sent.actor).toBe('Michal')
})

test('a suppression that is already gone: the page says so and shows the list as it is', async ({
  page,
  stub,
}) => {
  await stub.suppressions([
    { matched_ioc: 'd6.example', client_ip: '192.168.1.77', signal_class: 'ioc' },
  ])
  await signIn(page)
  await page.goto('/alerts')
  const suppression = page.getByTestId('suppressions-table').locator('tr[data-ioc="d6.example"]')
  await expect(suppression).toBeVisible()

  // Lifted in another browser (or expired) while this page shows it.
  await stub.suppressions([])
  page.once('dialog', (d) => void d.accept())
  await suppression.getByRole('button', { name: 'Lift' }).click()
  const note = page.getByTestId('feedback-note').first()
  await expect(note).toHaveText(
    'Nothing to lift: the suppression of d6.example (ioc) on 192.168.1.77 was no longer in force (lifted already, or it expired).',
  )
  await expect(note).toHaveClass(/note-warn/)
  await expect(page.getByText('Nothing is suppressed.')).toBeVisible()
})

test('a lift the engine could not save is flagged: the suppression comes back on restart', async ({
  page,
  stub,
}) => {
  await stub.set({ persistFeedback: false })
  await stub.suppressions([{ matched_ioc: '203.0.113.9', signal_class: 'ids-signature' }])
  await signIn(page)
  await page.goto('/alerts')
  page.once('dialog', (d) => void d.accept())
  await page
    .getByTestId('suppressions-table')
    .locator('tr[data-ioc="203.0.113.9"]')
    .getByRole('button', { name: 'Lift' })
    .click()
  const note = page.getByTestId('feedback-note').first()
  await expect(note).toContainText(
    'Lifted the suppression of 203.0.113.9 (ids-signature) on every device. It applies now but was NOT saved: when the detection engine restarts, the suppression comes back (until ',
  )
  await expect(note).toHaveClass(/note-warn/)
})

test('lifting a device’s suppression says when another one keeps it silenced', async ({
  page,
  stub,
}) => {
  await stub.suppressions([
    { matched_ioc: 'd6.example', client_ip: '192.168.1.77', signal_class: 'ioc' },
    { matched_ioc: 'd6.example', signal_class: 'ioc', ageMinutes: 120 },
  ])
  await signIn(page)
  await page.goto('/alerts')
  let question = ''
  page.once('dialog', (d) => {
    question = d.message()
    void d.dismiss()
  })
  await page
    .getByTestId('suppressions-table')
    .locator('tr[data-ioc="d6.example"]', { hasText: '192.168.1.77' })
    .getByRole('button', { name: 'Lift' })
    .click()
  await expect.poll(() => question).toContain('also suppressed on every device')
  expect(question).not.toContain('reach the killswitch again')
  expect(await feedbackPosts(stub)).toEqual([])
})

test('suppressions say when they end and how long is left, wherever they are shown', async ({
  page,
  stub,
}) => {
  // Made a day ago, by an engine that suppresses for 7 days.
  await stub.set({ suppressionTtlDays: 7 })
  await stub.suppressions([
    { matched_ioc: 'd6.example', client_ip: '192.168.1.77', signal_class: 'ioc', ageMinutes: 1440 },
  ])
  await signIn(page)
  await page.goto('/alerts')
  const ends = page
    .getByTestId('suppressions-table')
    .locator('tr[data-ioc="d6.example"]')
    .getByTestId('suppression-ends')
  await expect(ends).toContainText('6 days left')
  await expect(page.locator('section.suppressions')).toContainText('(7 days after it was made)')
  const marked = page.locator('tr[data-alert-id="DET-e2e-6"]')
  await expect(marked).toContainText('6 days left')
  await expect(marked.getByTestId('fp-marked')).toHaveAttribute(
    'title',
    /, until .+ \(6 days left\)/,
  )

  // A new verdict is said to last as long as the engine's own do.
  let question = ''
  page.once('dialog', (d) => {
    question = d.message()
    void d.dismiss()
  })
  await page
    .locator('tr[data-alert-id="DET-e2e-5"]')
    .getByRole('button', { name: 'Mark FP' })
    .click()
  await expect.poll(() => question).toContain('For 7 days, detections')
})

test('an engine that does not say when a suppression ends gets an estimate, marked as one', async ({
  page,
  stub,
}) => {
  await stub.set({ suppressionExpiry: false })
  await stub.suppressions([{ matched_ioc: 'd6.example', signal_class: 'ioc', ageMinutes: 1440 }])
  await signIn(page)
  await page.goto('/alerts')
  const ends = page.getByTestId('suppression-ends')
  await expect(ends).toContainText('about ')
  await expect(ends).toContainText('estimated: the engine did not say; 30 days is its default')
})

test('alerts recorded while silenced are dimmed, labelled, lead to their suppression, and cannot be marked again', async ({
  page,
  stub,
}) => {
  // DET-e2e-5 was silenced by a suppression still in force; DET-e2e-4 by one
  // that has ended since. The engine only stopped the response.
  await stub.set({ silenced: ['DET-e2e-5', 'DET-e2e-4'] })
  await stub.suppressions([
    { matched_ioc: 'd5.example', client_ip: '192.168.1.77', signal_class: 'ioc', ageMinutes: 1440 },
  ])
  await signIn(page)

  // The dashboard marks them too, and leads to them.
  const recent = page.getByTestId('recent-alerts')
  await expect(page.getByTestId('silenced-count')).toHaveText(
    '2 of them silenced by a suppression, not sent to the killswitch',
  )
  const onDashboard = recent.locator('tr[data-alert-id="DET-e2e-5"]')
  await expect(onDashboard).toHaveAttribute('data-silenced', 'true')
  await expect(onDashboard.locator('td').first()).toHaveCSS('opacity', '0.55')
  await expect(recent.locator('tr[data-alert-id="DET-e2e-6"]')).not.toHaveAttribute('data-silenced')
  await onDashboard.getByTestId('silenced').click()
  await expect(page).toHaveURL(/\/alerts#alert-[0-9a-f]{8}$/)
  const row = page.locator('tr[data-alert-id="DET-e2e-5"]')
  await expect(row).toHaveClass(/targeted/)
  await expect(row).toBeInViewport()

  await expect(row).toHaveAttribute('data-silenced', 'true')
  await expect(row.locator('td').first()).toHaveCSS('opacity', '0.55')
  await expect(row.getByTestId('silenced')).toHaveText('Silenced')
  await expect(row.getByRole('button', { name: 'Mark FP' })).toHaveCount(0)
  await expect(page.getByTestId('silenced-count')).toHaveText(
    '2 silenced by a suppression (not sent to the killswitch)',
  )

  const ended = page.locator('tr[data-alert-id="DET-e2e-4"]')
  await expect(ended.getByTestId('silenced-by')).toHaveText('the suppression has ended since')
  await expect(ended.getByRole('button', { name: 'Mark FP' })).toHaveCount(0)

  // No `suppressed`: an ordinary alert.
  const open = page.locator('tr[data-alert-id="DET-e2e-6"]')
  await expect(open).not.toHaveAttribute('data-silenced')
  await expect(open.getByRole('button', { name: 'Mark FP' })).toBeVisible()

  // From the alert to the suppression that silenced it.
  await row.getByRole('link', { name: 'see the suppression (29 days left)' }).click()
  await expect(page).toHaveURL(/#suppression-[0-9a-f]{8}$/)
  const suppression = page.getByTestId('suppressions-table').locator('tr[data-ioc="d5.example"]')
  await expect(suppression).toHaveClass(/targeted/)
  await expect(suppression).toBeInViewport()
  await expect(row).not.toHaveClass(/targeted/)
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
