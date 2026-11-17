import type { Page } from '@playwright/test'
import { test, expect, signIn } from './fixtures'
import { REAL_DEVICES, THREAT_DOMAINS, escapeRegExp, sinkholeRule } from './real/stack'

/**
 * The production build in front of the real killswitch-controller,
 * device-inventory and detection-engine (tests/browser/real/stack.ts).
 *
 * Every unit test passed while nobody could sign in, and the stubs were
 * written from what the UI assumed the services would answer. These run
 * the household's path against what the services really answer.
 */

/** The stack's control port: AdGuard's querylog and rules, the stand-in netagent. */
class Real {
  constructor(readonly base: string) {}

  /** A DNS query AdGuard logged; the detection engine reads it within a second. */
  async query(host: string, client: string): Promise<void> {
    const res = await fetch(`${this.base}/querylog`, {
      method: 'POST',
      body: JSON.stringify({ host, client }),
    })
    if (!res.ok) throw new Error(`querylog: ${res.status}`)
  }

  async rules(): Promise<string[]> {
    return (await fetch(`${this.base}/rules`)).json()
  }

  /** The netagent reports the isolations (and held releases) it was asked for as carried out. */
  async confirmIsolations(): Promise<number> {
    const res = await fetch(`${this.base}/agent/confirm`, { method: 'POST' })
    return ((await res.json()) as { confirmed: number }).confirmed
  }

  /** While set, the netagent holds releases until confirmIsolations(). */
  async holdReleases(hold: boolean): Promise<void> {
    const res = await fetch(`${this.base}/agent/hold-releases`, {
      method: 'POST',
      body: JSON.stringify({ hold }),
    })
    if (!res.ok) throw new Error(`hold-releases: ${res.status}`)
  }
}

/** A GET through the UI's proxy, from the signed-in page (the browser resolves netsoldier.lan). */
function apiGet<T>(page: Page, path: string): Promise<T> {
  return page.evaluate(async (p) => (await fetch(p)).json(), path) as Promise<T>
}

const real = new Real(process.env.E2E_REAL_CONTROL ?? '')
const [TABLET, TV] = REAL_DEVICES
const [TABLET_DOMAIN, TV_DOMAIN] = THREAT_DOMAINS

// One set of services with shared state: in order.
test.describe.configure({ mode: 'serial' })

const outcome = (page: Page) => page.getByTestId('outcome').first()
const actionRow = (page: Page, table: string, id: string) =>
  page.getByTestId(table).locator(`tr[data-action-id="${id}"]`)

/** Waits for the detection of `domain` to reach the approval queue; returns its id. */
async function pendingFor(page: Page, domain: string): Promise<string> {
  // Detected within a second or two, then listed on the page's next
  // 10-second refresh.
  const row = page.getByTestId('pending-table').locator('tr', { hasText: domain })
  await expect(row).toBeVisible({ timeout: 30_000 })
  const id = await row.getAttribute('data-action-id')
  if (!id) throw new Error('pending row without an action id')
  return id
}

test('sign in, approve a detection, see it enforced by its approver, revert it, read the audit trail', async ({
  page,
}) => {
  test.setTimeout(90_000)
  await signIn(page, 'Michal')
  await page.goto('/killswitch')
  await expect(page.getByRole('heading', { level: 1, name: 'Killswitch' })).toBeVisible()

  // Whether the controller blocks on its own, and why not, as GET /policy says.
  const policy = await apiGet<{ auto_block_allowed: boolean; auto_block_disabled_reason: string }>(
    page,
    '/api/killswitch/policy',
  )
  const status = page.getByTestId('auto-block')
  await expect(status).toHaveAttribute('data-on', String(policy.auto_block_allowed))
  if (!policy.auto_block_allowed) {
    await expect(status.getByTestId('auto-block-reason')).toHaveText(
      policy.auto_block_disabled_reason,
    )
  }

  // The kids' tablet looks up a domain on the threat list.
  await real.query(TABLET_DOMAIN, TABLET.ip)
  const id = await pendingFor(page, TABLET_DOMAIN)
  const pending = actionRow(page, 'pending-table', id)
  // The engine named the device from the inventory; the controller kept it.
  await expect(pending).toContainText(TABLET.hostname)
  await expect(pending).toContainText(TABLET.mac)

  await pending.getByRole('button', { name: 'Approve' }).click()
  const dialog = page.getByTestId('approve-dialog')
  await expect(dialog.getByRole('radio', { name: /^DNS sinkhole \(default\)/ })).toBeChecked()
  // GET /policy offers the isolation too: the stand-in netagent is polling.
  await expect(dialog.getByRole('radio', { name: /^Cut off from the network/ })).not.toBeChecked()
  await dialog.getByRole('button', { name: 'Approve: DNS sinkhole' }).click()

  await expect(outcome(page)).toHaveAttribute('data-state', 'active')
  await expect(outcome(page)).toContainText(`is now blocked for ${TABLET.hostname}`)
  const active = actionRow(page, 'active-table', id)
  await expect(active).toHaveAttribute('data-state', 'active')
  await expect(active.getByTestId('approved-by')).toHaveText('Michal')
  expect(await real.rules()).toContain(sinkholeRule(TABLET_DOMAIN))

  page.once('dialog', (d) => void d.accept('checked, it was the school app'))
  await active.getByRole('button', { name: 'Revert' }).click()
  await expect(outcome(page)).toHaveAttribute('data-state', 'reverted')
  await expect(active).toHaveCount(0)
  expect(await real.rules()).not.toContain(sinkholeRule(TABLET_DOMAIN))

  await page.getByTestId('killswitch-nav').getByRole('link', { name: 'Audit log' }).click()
  const trail = page.getByTestId('audit-table').locator(`tr[data-action-id="${id}"]`)
  await expect(trail.getByTestId('audit-what')).toHaveText([
    'reverted (lifted)',
    'enforced',
    'approved',
    'proposed, waiting for approval',
  ])
  await expect(trail.getByTestId('audit-actor')).toHaveText([
    'Michal',
    'Michal',
    'Michal',
    'the policy (automatic)',
  ])
  for (const i of [0, 1, 2]) {
    const entry = trail.nth(i)
    await expect(entry).toContainText(TABLET.hostname)
    await expect(entry).toContainText(TABLET_DOMAIN)
    await expect(entry).toContainText('confidence=80 severity=high')
  }
  await expect(trail.first()).toContainText('checked, it was the school app')

  await page.getByTestId('killswitch-nav').getByRole('link', { name: 'History' }).click()
  const done = actionRow(page, 'history-table', id)
  await expect(done.getByTestId('outcome-state')).toHaveText('reverted (lifted)')
  await expect(done.getByTestId('ended-by')).toHaveText('Michal')
})

test('an isolation waits for the network agent: in progress, then enforced when it confirms', async ({
  page,
}) => {
  test.setTimeout(120_000)
  await signIn(page, 'Michal')
  await page.goto('/killswitch')
  await real.query(TV_DOMAIN, TV.ip)
  const id = await pendingFor(page, TV_DOMAIN)

  await actionRow(page, 'pending-table', id).getByRole('button', { name: 'Approve' }).click()
  const dialog = page.getByTestId('approve-dialog')
  await dialog.getByRole('radio', { name: /^Cut off from the network/ }).check()
  await expect(dialog.getByTestId('approve-question')).toContainText(
    `Cut off from the network (ARP isolation) for ${TV.hostname}`,
  )
  await dialog.getByRole('button', { name: /^Approve: Cut off/ }).click()

  // The agent holds the isolation; after 9 s the controller answers 202
  // with the action still approved.
  await expect(outcome(page)).toHaveAttribute('data-state', 'approved', { timeout: 20_000 })
  await expect(outcome(page)).toHaveClass(/outcome-progress/)
  await expect(outcome(page)).toContainText('waiting for the network agent to confirm')
  await expect(actionRow(page, 'progress-table', id).getByTestId('progress-what')).toContainText(
    'being applied as ARP Isolation — waiting for the network agent to confirm',
  )
  // GET /actions/active does not list it, and the page does not pretend it does.
  await expect(actionRow(page, 'active-table', id)).toHaveCount(0)
  expect((await apiGet<{ in_flight?: string }>(page, `/api/killswitch/${id}`)).in_flight).toBe(
    'apply',
  )

  expect(await real.confirmIsolations()).toBe(1)
  await expect(outcome(page)).toHaveAttribute('data-state', 'active', { timeout: 15_000 })
  await expect(outcome(page)).toContainText(`is now blocked for ${TV.hostname}`)
  const active = actionRow(page, 'active-table', id)
  await expect(active).toContainText('ARP Isolation')
  await expect(active.getByTestId('approved-by')).toHaveText('Michal')
  await expect(page.getByTestId('progress-table')).toHaveCount(0)
  await expect(active.getByTestId('being-lifted')).toHaveCount(0)

  // The agent holds the release: after 9 s the controller answers 202 with
  // the action still active and in_flight "revert" — being lifted.
  await real.holdReleases(true)
  page.once('dialog', (d) => void d.accept('lifted'))
  await active.getByRole('button', { name: 'Revert' }).click()
  await expect(outcome(page)).toHaveClass(/outcome-progress/, { timeout: 20_000 })
  await expect(outcome(page)).toHaveAttribute('data-state', 'active')
  await expect(outcome(page)).toContainText('Reverting')
  await expect(active.getByTestId('being-lifted')).toHaveText('being lifted — still in force')
  await expect(active.getByRole('button', { name: 'Revert' })).toBeDisabled()
  await expect(actionRow(page, 'progress-table', id).getByTestId('progress-what')).toContainText(
    'being lifted — waiting for the network agent to confirm',
  )
  expect((await apiGet<{ in_flight?: string }>(page, `/api/killswitch/${id}`)).in_flight).toBe(
    'revert',
  )

  await real.holdReleases(false)
  expect(await real.confirmIsolations()).toBe(1)
  await expect(outcome(page)).toHaveAttribute('data-state', 'reverted', { timeout: 15_000 })
  await expect(active).toHaveCount(0)

  await page.goto(`/killswitch/audit?action=${id}`)
  const trail = page.getByTestId('audit-table').locator('tbody tr')
  await expect(trail.getByTestId('audit-what')).toHaveText([
    'reverted (lifted)',
    'enforced',
    'approved',
    'proposed, waiting for approval',
  ])
  await expect(trail.getByTestId('audit-actor')).toHaveText([
    'Michal',
    'the network agent',
    'Michal',
    'the policy (automatic)',
  ])
  await expect(trail.nth(2)).toContainText('approved as arp_isolate (proposed dns_sinkhole)')
})

test('alerts and false-positive feedback against the real detection engine', async ({ page }) => {
  await signIn(page, 'Michal')
  await page.goto('/alerts')
  const alert = page.locator('tr[data-alert-id]', { hasText: TABLET_DOMAIN }).first()
  await expect(alert).toBeVisible()
  await expect(alert.getByTestId('alert-client')).toContainText(TABLET.hostname)

  page.once('dialog', (d) => void d.accept())
  await alert.getByRole('button', { name: 'Mark FP' }).click()
  // The engine records verdicts in its local store (DB_PATH): saved, and
  // GET /feedback says when it ends.
  await expect(page.getByTestId('feedback-note').first()).toHaveText(
    new RegExp(
      `^Marked ${escapeRegExp(TABLET_DOMAIN)} as a false positive: silenced until .+ \\(30 days left\\)\\. Saved\\.$`,
    ),
  )
  await expect(alert.getByTestId('fp-marked')).toBeVisible()
  const suppression = page
    .getByTestId('suppressions-table')
    .locator(`tr[data-ioc="${TABLET_DOMAIN}"]`)
  await expect(suppression).toContainText('ioc')
  await expect(suppression).toContainText(TABLET.ip)
  await expect(suppression).toContainText('Michal')
  await expect(suppression.getByTestId('suppression-ends')).toContainText('30 days left')
  await expect(suppression.getByTestId('suppression-ends')).not.toContainText('estimated')

  // POST /feedback/lift ends it: no "confirmed" verdict.
  page.once('dialog', (d) => void d.accept())
  await suppression.getByRole('button', { name: 'Lift' }).click()
  await expect(page.getByTestId('feedback-note').first()).toHaveText(
    `Lifted the suppression of ${TABLET_DOMAIN} (ioc) on ${TABLET.ip}. Saved.`,
  )
  await expect(page.getByText('Nothing is suppressed.')).toBeVisible()
  await expect(alert.getByRole('button', { name: 'Mark FP' })).toBeVisible()
})

// The engine keeps recording detections while a suppression applies; a
// change in progress marks them `suppressed: true` in GET /alerts. Until the
// engine in this tree sends the field, this test says so and skips.
test('a detection recorded while silenced is shown as silenced', async ({ page }) => {
  test.setTimeout(60_000)
  await signIn(page, 'Michal')
  await page.goto('/alerts')
  const first = page.locator('tr[data-alert-id]', { hasText: TV_DOMAIN }).first()
  await expect(first).toBeVisible()
  page.once('dialog', (d) => void d.accept())
  await first.getByRole('button', { name: 'Mark FP' }).click()
  await expect(first.getByTestId('fp-marked')).toBeVisible()

  type Listed = { id: string; matched_ioc?: string; suppressed?: boolean }
  const before = new Set(
    (await apiGet<Listed[]>(page, '/api/alerts?limit=500')).map((a: Listed) => a.id),
  )
  await real.query(TV_DOMAIN, TV.ip)
  let fresh: Listed | undefined
  await expect
    .poll(
      async () => {
        const all = await apiGet<Listed[]>(page, '/api/alerts?limit=500')
        fresh = all.find((a) => a.matched_ioc === TV_DOMAIN && !before.has(a.id))
        return Boolean(fresh)
      },
      { timeout: 20_000 },
    )
    .toBe(true)

  const sent = fresh!.suppressed === true
  if (sent) {
    await page.reload()
    const row = page.locator(`tr[data-alert-id="${fresh!.id}"]`)
    await expect(row).toHaveAttribute('data-silenced', 'true')
    await expect(row.getByTestId('silenced')).toHaveText('Silenced')
    await expect(row.getByRole('button', { name: 'Mark FP' })).toHaveCount(0)
    await row.getByTestId('silenced-by').click()
    await expect(
      page.getByTestId('suppressions-table').locator(`tr[data-ioc="${TV_DOMAIN}"]`),
    ).toHaveClass(/targeted/)
  }

  // Leave nothing suppressed for the tests after this one.
  page.once('dialog', (d) => void d.accept())
  await page
    .getByTestId('suppressions-table')
    .locator(`tr[data-ioc="${TV_DOMAIN}"]`)
    .getByRole('button', { name: 'Lift' })
    .click()
  await expect(page.getByText('Nothing is suppressed.')).toBeVisible()
  test.skip(!sent, 'detection-engine does not send `suppressed` on GET /alerts yet')
})

test('the health and policy pages show what the real services report about themselves', async ({
  page,
}) => {
  await signIn(page, 'Michal')
  await page.goto('/health')
  const services = page.getByTestId('services-table')
  for (const s of ['killswitch', 'detection-engine', 'device-inventory', 'threat-intel-sync']) {
    const row = services.locator(`tr[data-service="${s}"]`)
    await expect(row, s).toHaveAttribute('data-up', 'true')
    // The probes answered and /metrics was read: the names the UI asks for exist.
    await expect(row.locator('td').nth(2), s).toHaveText('read')
    await expect(row.locator('td').last(), s).toHaveText('—')
  }
  const finding = (key: string) => page.getByTestId(`finding-${key}`)
  // The two devices the stand-in agent registered.
  await expect(page.getByTestId('capture-devices')).toHaveText(String(REAL_DEVICES.length))
  // device-inventory runs with NETAGENT_EXPECT_CAPTURE=none: healthy while
  // the agent's one heartbeat is recent, "none expected" once it is not.
  await expect(finding('capture')).toHaveAttribute('data-verdict', /^(ok|off)$/)
  // The engine reads AdGuard's query log every second.
  await expect(finding('dns')).toHaveAttribute('data-verdict', 'ok')
  // No ClickHouse here: no packet sensor is read, and the page says so.
  await expect(finding('sensors')).toHaveAttribute('data-verdict', 'off')
  await expect(page.getByTestId('sensors-none')).toBeVisible()
  // threat-intel-sync cannot reach a feed from a test: not ready, and each
  // feed it runs has never synced; the abuse.ch ones are off (COMMERCIAL_MODE).
  await expect(finding('intel')).toHaveAttribute('data-verdict', 'fail')
  await expect(page.getByTestId('intel-ready')).toContainText('NOT ready')
  const feeds = page.getByTestId('feeds-table')
  await expect(feeds.locator('tr[data-source="spamhaus"]')).toHaveAttribute('data-verdict', 'fail')
  await expect(feeds.locator('tr[data-source="threatfox"]')).toContainText('disabled')

  await page.goto('/killswitch/policy')
  const policy = await apiGet<{
    auto_block_allowed: boolean
    auto_block_disabled_reason: string
    unavailable_action_types: Record<string, string>
    available_action_types: string[]
  }>(page, '/api/killswitch/policy')
  await expect(page.getByTestId('mode-auto-block')).toHaveAttribute(
    'data-on',
    String(policy.auto_block_allowed),
  )
  if (!policy.auto_block_allowed) {
    await expect(page.getByTestId('mode-auto-block-reason')).toHaveText(
      policy.auto_block_disabled_reason,
    )
  }
  const types = page.getByTestId('action-types')
  for (const t of policy.available_action_types) {
    await expect(types.locator(`tr[data-type="${t}"]`), t).toHaveAttribute('data-available', 'true')
  }
  expect(Object.keys(policy.unavailable_action_types).length).toBeGreaterThan(0)
  for (const [t, why] of Object.entries(policy.unavailable_action_types)) {
    const row = types.locator(`tr[data-type="${t}"]`)
    await expect(row, t).toHaveAttribute('data-available', 'false')
    await expect(row.getByTestId('unavailable-reason'), t).toHaveText(why)
  }
  // ALLOWLIST_IPS=192.168.1.1 in the stack.
  await expect(
    page.getByTestId('protected-table').locator('tr[data-value="192.168.1.1"]'),
  ).toBeVisible()
})

test('devices from the hardened inventory show where their values came from', async ({ page }) => {
  await signIn(page, 'Michal')
  await page.goto('/devices')
  const tablet = page.locator(`tr[data-mac="${TABLET.mac}"]`)
  await expect(tablet).toContainText(TABLET.hostname)
  // One DHCP request: the binding is not confirmed yet.
  await expect(tablet.getByTestId('ip-state')).toHaveText('tentative')
  await expect(page.getByTestId('conflict-badge')).toHaveCount(0)

  await tablet.getByRole('link', { name: TABLET.mac }).click()
  await expect(page.getByRole('heading', { level: 1, name: TABLET.hostname })).toBeVisible()
  await expect(page.getByTestId('ip-card')).toContainText('tentative')
  await expect(page.getByTestId('ip-card')).toContainText('from DHCP')
  await expect(page.getByTestId('device-conflicts')).toHaveCount(0)
})
