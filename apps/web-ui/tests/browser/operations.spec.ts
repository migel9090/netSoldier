import type { Page } from '@playwright/test'
import { test, expect, signIn } from './fixtures'
import { COMPOSITE_ID } from './stub/backends'

/**
 * The operational views (step 131): what is blocked and why, who approved
 * it, and whether the system sees the network — answered from the UI, in
 * front of the stub backends.
 */

const finding = (page: Page, key: string) => page.getByTestId(`finding-${key}`)

test.describe('system health', () => {
  test('says the system sees the network, with each source and the mode', async ({
    page,
    stub,
    problems,
  }) => {
    await signIn(page)
    await page.getByRole('link', { name: 'Health' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'System Health' })).toBeVisible()

    await expect(finding(page, 'capture')).toHaveAttribute('data-verdict', 'ok')
    await expect(finding(page, 'capture')).toContainText(
      'the network agent netagent-lab on eth0 is reporting',
    )
    await expect(finding(page, 'capture')).toContainText('capturing arp, dhcp, mdns')
    await expect(finding(page, 'dns')).toHaveAttribute('data-verdict', 'ok')
    await expect(finding(page, 'sensors')).toHaveAttribute('data-verdict', 'ok')
    await expect(finding(page, 'sensors')).toHaveText(/All 2 sensor sources are keeping up/)
    await expect(finding(page, 'intel')).toHaveAttribute('data-verdict', 'ok')
    await expect(finding(page, 'intel')).toContainText('threat-intel-sync holds 1340 indicators')

    const services = page.getByTestId('services-table')
    for (const s of ['killswitch', 'detection-engine', 'device-inventory', 'threat-intel-sync']) {
      await expect(services.locator(`tr[data-service="${s}"]`)).toHaveAttribute('data-up', 'true')
    }
    await expect(page.getByTestId('capture-devices')).toHaveText('4')
    await expect(
      page.getByTestId('feeds-table').locator('tr[data-source="spamhaus"]'),
    ).toHaveAttribute('data-verdict', 'ok')
    await expect(
      page.getByTestId('feeds-table').locator('tr[data-source="threatfox"]'),
    ).toContainText('disabled')
    await expect(page.getByTestId('sensors-table').locator('tbody tr')).toHaveCount(2)
    // Pending actions, as the controller counts them.
    await expect(page.getByTestId('pending-count')).toHaveText('3')

    // The mode, at the top of the page.
    await expect(page.getByTestId('mode-auto-block')).toHaveAttribute('data-on', 'true')
    await expect(page.getByTestId('mode-available')).toHaveText('DNS Sinkhole, ARP Isolation')

    // Composed by the UI's server: the page never talks to a backend, and
    // the threat-intel-sync stub was read without a key.
    const tis = (await stub.seen()).filter((s) => s.service === 'threat-intel-sync')
    expect(tis.map((s) => s.path).sort()).toEqual(['/metrics', '/readyz'])
    expect(tis.every((s) => s.authorization === null)).toBe(true)
    expect(problems.failedResponses).toEqual([])
    expect(await problems.cspViolations()).toEqual([])
  })

  test('an agent gone quiet, failing DNS polls and feeds that never synced are failures', async ({
    page,
    stub,
  }) => {
    await stub.set({ agent: 'gone', dnsFailing: true, intel: 'not-ready', sensors: 'behind' })
    await signIn(page)
    await page.goto('/health')
    await expect(finding(page, 'capture')).toHaveAttribute('data-verdict', 'fail')
    await expect(finding(page, 'capture')).toContainText(
      'NOT seeing the network: no heartbeat within the timeout.',
    )
    await expect(finding(page, 'dns')).toHaveAttribute('data-verdict', 'fail')
    await expect(finding(page, 'dns')).toContainText('NOT reading DNS')
    await expect(finding(page, 'sensors')).toHaveAttribute('data-verdict', 'warn')
    await expect(finding(page, 'sensors')).toContainText('Behind or failing: zeek_ssl.')
    await expect(finding(page, 'intel')).toHaveAttribute('data-verdict', 'fail')
    await expect(page.getByTestId('intel-ready')).toHaveText(
      'NOT ready: no source has delivered a set yet',
    )
    const spamhaus = page.getByTestId('feeds-table').locator('tr[data-source="spamhaus"]')
    await expect(spamhaus).toHaveAttribute('data-verdict', 'fail')
    await expect(spamhaus).toContainText('never')
    await expect(page.getByTestId('capture-heartbeat')).toContainText('10 min ago')
  })

  test('a service that cannot be read is unknown, never zero', async ({ page, stub }) => {
    await stub.set({ down: ['detection-engine', 'threat-intel-sync'] })
    await signIn(page)
    await page.goto('/health')
    const de = page.getByTestId('services-table').locator('tr[data-service="detection-engine"]')
    await expect(de).toHaveAttribute('data-up', 'false')
    await expect(de).toContainText('/healthz: answered HTTP 503')
    await expect(finding(page, 'dns')).toHaveAttribute('data-verdict', 'unknown')
    await expect(finding(page, 'sensors')).toHaveAttribute('data-verdict', 'unknown')
    await expect(finding(page, 'intel')).toHaveAttribute('data-verdict', 'unknown')
    await expect(page.getByTestId('dns-facts')).toHaveCount(0)
    await expect(page.getByTestId('intel-error')).toContainText('/readyz: answered HTTP 503')
    // The rest still answers.
    await expect(finding(page, 'capture')).toHaveAttribute('data-verdict', 'ok')
  })

  test('without capture expected or sensors, it says so instead of reporting a failure', async ({
    page,
    stub,
  }) => {
    await stub.set({ agent: 'none', sensors: 'none' })
    await signIn(page)
    await page.goto('/health')
    await expect(finding(page, 'capture')).toHaveAttribute('data-verdict', 'off')
    await expect(finding(page, 'capture')).toContainText('NETAGENT_EXPECT_CAPTURE=none')
    await expect(finding(page, 'sensors')).toHaveAttribute('data-verdict', 'off')
    await expect(page.getByTestId('sensors-none')).toBeVisible()
  })
})

test.describe('policy', () => {
  test('shows the thresholds, the enforcement types and why some are not offered, and who is protected', async ({
    page,
    stub,
  }) => {
    await stub.set({
      autoBlockReason: 'auto-block disabled: POLICY_AUTO_BLOCK=off',
      rejectedProtection: 1,
    })
    await signIn(page)
    await page.goto('/killswitch')
    await page.getByTestId('killswitch-nav').getByRole('link', { name: 'Policy' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Killswitch Policy' })).toBeVisible()

    await expect(page.getByTestId('mode-auto-block')).toHaveAttribute('data-on', 'false')
    await expect(page.getByTestId('mode-auto-block-reason')).toHaveText(
      'auto-block disabled: POLICY_AUTO_BLOCK=off',
    )
    await expect(page.getByTestId('mode-auto-block')).toContainText(
      'Configured: off (POLICY_AUTO_BLOCK=off).',
    )

    const value = (key: string) =>
      page.getByTestId('policy-rows').locator(`tr[data-key="${key}"]`).getByTestId('policy-value')
    await expect(value('auto_min')).toHaveText('confidence ≥ 90, severity ≥ critical')
    await expect(value('pend_min')).toHaveText('confidence ≥ 50, severity ≥ medium')
    await expect(value('auto_min_signals')).toHaveText('2 signal classes')
    await expect(value('default_ttl')).toHaveText('1 h')
    await expect(value('pending_ttl')).toHaveText('24 h')

    const types = page.getByTestId('action-types')
    await expect(types.locator('tr[data-type="dns_sinkhole"]')).toHaveAttribute(
      'data-available',
      'true',
    )
    await expect(types.locator('tr[data-type="arp_isolate"]')).toHaveAttribute(
      'data-available',
      'true',
    )
    const acl = types.locator('tr[data-type="switch_acl"]')
    await expect(acl).toHaveAttribute('data-available', 'false')
    await expect(acl.getByTestId('unavailable-reason')).toHaveText('SWITCH_WEBHOOK_URL not set')

    const protectedList = page.getByTestId('protected-table')
    await expect(protectedList.locator('tbody tr')).toHaveCount(3)
    await expect(protectedList.locator('tr[data-value="10.9.0.0/30"]')).toContainText('network')
    await expect(page.getByTestId('rejected-entries')).toContainText(
      '1 protection entry was refused',
    )
  })

  test('a policy the controller cannot serve is an error, not an empty policy', async ({
    page,
    stub,
  }) => {
    await stub.set({ policyDown: true })
    await signIn(page)
    await page.goto('/killswitch/policy')
    await expect(page.getByTestId('mode-error')).toContainText('The mode is unknown')
    await expect(page.getByTestId('policy-error')).toBeVisible()
    await expect(page.getByTestId('action-types')).toHaveCount(0)
    // GET /allowlist still answers.
    await expect(page.getByTestId('protected-table')).toBeVisible()
  })
})

test.describe('what is blocked and why', () => {
  test('an active block’s page names the device, the approver, the rule, the signals and the trail', async ({
    page,
  }) => {
    await signIn(page)
    await page.goto('/killswitch')
    await page.getByTestId('active-table').getByRole('link', { name: 'ACT-e2e-a1' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Action ACT-e2e-a1' })).toBeVisible()
    await expect(page.getByTestId('action-state')).toContainText('enforced')
    await expect(page.getByTestId('action-device')).toContainText('laptop')
    await expect(page.getByTestId('action-device')).toContainText('aa:bb:cc:00:00:04')
    await expect(page.getByTestId('action-approved-by')).toHaveText('Anna')
    await expect(page.getByTestId('action-rule')).toHaveText(
      'pending: confidence=80 severity=high signals=1',
    )
    const signal = page.getByTestId('signals-table').locator('tbody tr')
    await expect(signal).toHaveCount(1)
    await expect(signal).toContainText('ioc')
    await expect(signal).toContainText('80%')
    await expect(signal).toContainText('d4.example')
    await expect(signal).toContainText('threatfox')
    await expect(page.getByTestId('action-trail').getByTestId('audit-what')).toHaveText([
      'enforced',
      'approved',
      'proposed, waiting for approval',
    ])
    await expect(page.getByTestId('action-trail').getByTestId('audit-actor')).toHaveText([
      'Anna',
      'Anna',
      'the policy (automatic)',
    ])
  })

  test('a combined detection is broken down into its signals, on the action and on the alerts page', async ({
    page,
    stub,
  }) => {
    await stub.reset({ composite: true })
    await signIn(page)
    await page.goto('/killswitch/actions/ACT-e2e-p3')
    await expect(page.getByTestId('signals-composite')).toContainText(
      'A combined detection: 3 signals',
    )
    const rows = page.getByTestId('signals-table').locator('tbody tr')
    await expect(rows).toHaveCount(3)
    await expect(rows.nth(1)).toHaveAttribute('data-signal-class', 'beacon')
    await expect(rows.nth(1)).toContainText('70%')
    await expect(rows.nth(1)).toContainText('203.0.113.50')
    await expect(rows.nth(1)).toContainText('rita')

    await page.getByRole('link', { name: 'The detection on the alerts page' }).click()
    const alert = page.locator(`tr[data-alert-id="${COMPOSITE_ID}"]`)
    await expect(alert).toHaveClass(/targeted/)
    // Opened by the link: the breakdown is shown under the row.
    const toggle = alert.getByTestId('signals-toggle')
    await expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const details = page.locator(`tr[data-signals-of="${COMPOSITE_ID}"]`)
    await expect(details.getByTestId('signals-table').locator('tbody tr')).toHaveCount(3)
    // And closed again, from the keyboard.
    await toggle.focus()
    await page.keyboard.press('Enter')
    await expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await expect(details).toHaveCount(0)
    await expect(toggle).toHaveText('▸ 3 signals (combined)')
  })

  test('a detection the engine no longer lists says so; the action still says who and why', async ({
    page,
    stub,
  }) => {
    // The older alert shape names its alerts DET-1…, so DET-e2e-6 is not among them.
    await stub.set({ alertsShape: 'v1' })
    await signIn(page)
    await page.goto('/killswitch/actions/ACT-e2e-h1')
    await expect(page.getByTestId('action-state')).toContainText('reverted (lifted)')
    await expect(page.getByTestId('action-who')).toContainText('the TTL reaper (automatic)')
    await expect(page.getByTestId('action-rule')).toHaveText(
      'pending: confidence=80 severity=high signals=1',
    )
    await expect(page.getByTestId('detection-absent')).toContainText(
      'no longer lists DET-e2e-6 among its newest 5000 alerts',
    )
    await expect(page.getByTestId('signals-table')).toHaveCount(0)
  })

  test('an action the controller does not know is said to be unknown', async ({ page }) => {
    await signIn(page)
    await page.goto('/killswitch/actions/ACT-nope')
    await expect(page.getByText('The killswitch does not know an action ACT-nope')).toBeVisible()
  })
})

test.describe('history and audit, narrowed down', () => {
  test.beforeEach(async ({ stub }) => {
    await stub.reset({ finished: 60 })
  })

  test('the history shows one outcome at a time', async ({ page, stub }) => {
    await signIn(page)
    await page.goto('/killswitch/history')
    await page.getByLabel('Outcome').selectOption('rejected')
    await page.getByRole('button', { name: 'Show' }).click()
    await expect(page).toHaveURL(/\?outcome=rejected$/)
    const rows = page.getByTestId('history-table').locator('tbody tr')
    await expect(rows).toHaveCount(30)
    for (const state of await rows.evaluateAll((trs) =>
      trs.map((tr) => tr.getAttribute('data-state')),
    )) {
      expect(state).toBe('rejected')
    }
    await expect(page.getByTestId('history-range')).toHaveText('1–30 of 30')
    // A filter reads everything the controller keeps, once.
    expect(
      (await stub.seen()).filter((s) => s.path === '/actions/history').map((s) => s.search),
    ).toEqual(['?limit=50', '?limit=500'])

    await page.getByLabel('Outcome').selectOption('apply_failed')
    await page.getByRole('button', { name: 'Show' }).click()
    await expect(rows).toHaveCount(1)
    await expect(rows.first()).toHaveAttribute('data-action-id', 'ACT-e2e-f1')
  })

  test('the audit log finds who did what, and says how far back it looked', async ({ page }) => {
    await signIn(page, 'Michal')
    await page.goto('/killswitch')
    await page
      .getByTestId('pending-table')
      .locator('tr[data-action-id="ACT-e2e-p1"]')
      .getByRole('button', { name: 'Approve' })
      .click()
    await page
      .getByTestId('approve-dialog')
      .getByRole('button', { name: /^Approve: / })
      .click()
    await expect(page.getByTestId('outcome').first()).toHaveAttribute('data-state', 'active')

    await page.goto('/killswitch/audit')
    await page.getByLabel('Who').fill('michal')
    await page.getByRole('button', { name: 'Search' }).click()
    await expect(page).toHaveURL(/actor=michal/)
    const rows = page.getByTestId('audit-table').locator('tbody tr')
    await expect(rows.getByTestId('audit-what')).toHaveText(['enforced', 'approved'])
    await expect(rows.getByTestId('audit-actor')).toHaveText(['Michal', 'Michal'])
    await expect(page.getByTestId('audit-scope')).toContainText('2 matching entries among the')
    await expect(page.getByTestId('audit-scope')).toContainText('That is the start of the log.')

    await page.getByLabel('Who').fill('')
    await page.getByLabel('What').selectOption('rejected')
    await page.getByRole('button', { name: 'Search' }).click()
    await expect(rows).toHaveCount(30)
    await expect(rows.getByTestId('audit-actor').first()).toHaveText('Anna')
    for (const what of await rows.getByTestId('audit-what').allInnerTexts()) {
      expect(what).toBe('rejected')
    }
    await page.getByRole('link', { name: 'clear' }).click()
    await expect(rows).toHaveCount(50)
  })
})

test.describe('suppressions', () => {
  test('are listed on their own page, with when they end, and lifted after a confirmation', async ({
    page,
    stub,
  }) => {
    await stub.suppressions([
      { matched_ioc: 'd1.example', client_ip: '192.168.1.77', signal_class: 'ioc', ageMinutes: 60 },
      { matched_ioc: 'cdn.example', signal_class: 'tls', analyst: 'Michal', ageMinutes: 10 },
    ])
    await signIn(page)
    await page.goto('/alerts')
    await page.getByTestId('alerts-nav').getByRole('link', { name: 'Suppressions' }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Suppressions' })).toBeVisible()
    await expect(page.getByTestId('suppression-count')).toHaveText(
      '2 in force, 1 of them on every device.',
    )
    const rows = page.getByTestId('suppressions-table').locator('tbody tr')
    // Newest first.
    await expect(rows.first()).toHaveAttribute('data-ioc', 'cdn.example')
    await expect(rows.first()).toContainText('every device')
    await expect(rows.first().getByTestId('suppression-ends')).toContainText('30 days left')

    // Cancelling the confirmation lifts nothing.
    page.once('dialog', (d) => void d.dismiss())
    await rows.nth(1).getByRole('button', { name: 'Lift' }).click()
    await expect(rows).toHaveCount(2)
    expect((await stub.seen()).some((s) => s.path === '/feedback/lift')).toBe(false)

    let question = ''
    page.once('dialog', (d) => {
      question = d.message()
      void d.accept()
    })
    await rows.nth(1).getByRole('button', { name: 'Lift' }).click()
    await expect(page.getByTestId('feedback-note').first()).toHaveText(
      'Lifted the suppression of d1.example (ioc) on 192.168.1.77. Saved.',
    )
    expect(question).toContain('Lift the suppression of d1.example (ioc) on 192.168.1.77?')
    await expect(rows).toHaveCount(1)
  })
})
