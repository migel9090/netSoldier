import type { Page } from '@playwright/test'
import { test, expect, signIn } from './fixtures'

function row(page: Page, table: string, id: string) {
  return page.getByTestId(table).locator(`tr[data-action-id="${id}"]`)
}

async function openKillswitch(page: Page, actor = 'Michal') {
  await signIn(page, actor)
  await page.goto('/killswitch')
  await expect(page.getByTestId('pending-table')).toBeVisible()
}

/** Opens the approval dialog for a pending action. */
async function openApproval(page: Page, id: string) {
  await row(page, 'pending-table', id).getByRole('button', { name: 'Approve' }).click()
  const dialog = page.getByTestId('approve-dialog')
  await expect(dialog).toBeVisible()
  return dialog
}

async function approve(page: Page, id: string, choice?: RegExp) {
  const dialog = await openApproval(page, id)
  if (choice) await dialog.getByRole('radio', { name: choice }).check()
  await dialog.getByRole('button', { name: /^Approve: / }).click()
  await expect(dialog).toBeHidden()
}

const outcome = (page: Page) => page.getByTestId('outcome').first()

// The settle poll runs every 2 s.
const SETTLE = { timeout: 10_000 }

test('approve: the dialog names the device, defaults to the DNS sinkhole, and records the approver', async ({
  page,
  stub,
}) => {
  await openKillswitch(page)
  const dialog = await openApproval(page, 'ACT-e2e-p1')
  for (const part of [
    'kids-tablet',
    'aa:bb:cc:00:00:01',
    '192.168.1.77',
    'DNS query for a domain listed by ThreatFox',
  ]) {
    await expect(dialog).toContainText(part)
  }
  await expect(dialog.getByRole('radio', { name: /^DNS sinkhole \(default\)/ })).toBeChecked()
  await expect(dialog.getByTestId('approve-question')).toContainText(
    'Approve: DNS sinkhole on kids-tablet (aa:bb:cc:00:00:01, 192.168.1.77)?',
  )
  await expect(dialog.getByTestId('approve-question')).toContainText('evil.example')
  await dialog.getByRole('button', { name: 'Approve: DNS sinkhole' }).click()

  await expect(outcome(page)).toHaveAttribute('data-state', 'active')
  await expect(outcome(page)).toContainText('is now blocked for kids-tablet')
  await expect(outcome(page)).toContainText('Approved by Michal')
  await expect(row(page, 'pending-table', 'ACT-e2e-p1')).toHaveCount(0)
  const active = row(page, 'active-table', 'ACT-e2e-p1')
  await expect(active).toHaveAttribute('data-state', 'active')
  await expect(active.getByTestId('approved-by')).toHaveText('Michal')

  // The approver is the signed-in actor, sent by the proxy as a header; the
  // body names the chosen enforcement.
  const sent = (await stub.seen()).find((s) => s.path === '/actions/ACT-e2e-p1/approve')!
  expect(sent.actor).toBe('Michal')
  expect(JSON.parse(sent.body)).toEqual({ action_type: 'dns_sinkhole' })
})

test('a stronger enforcement must be picked explicitly, and the confirmation names it', async ({
  page,
  stub,
}) => {
  await openKillswitch(page)
  const dialog = await openApproval(page, 'ACT-e2e-p3')
  const isolate = dialog.getByRole('radio', { name: /^Cut off from the network \(ARP isolation\)/ })
  await expect(isolate).not.toBeChecked()
  await expect(dialog).toContainText('Cuts printer off from the router')
  await expect(dialog).toContainText('Needs the network agent (netagent)')

  await isolate.check()
  await expect(dialog.getByTestId('approve-question')).toHaveText(
    'Approve: Cut off from the network (ARP isolation) for printer (aa:bb:cc:00:00:03, 192.168.1.79)?',
  )
  await dialog
    .getByRole('button', { name: 'Approve: Cut off from the network (ARP isolation)' })
    .click()

  await expect(outcome(page)).toHaveAttribute('data-state', 'active')
  await expect(row(page, 'active-table', 'ACT-e2e-p3')).toContainText('ARP Isolation')
  const sent = (await stub.seen()).find((s) => s.path === '/actions/ACT-e2e-p3/approve')!
  expect(JSON.parse(sent.body)).toEqual({ action_type: 'arp_isolate' })
})

test('the dialog offers only what the controller reports as available', async ({ page, stub }) => {
  await stub.set({ available: ['dns_sinkhole'] })
  await openKillswitch(page)
  const dialog = await openApproval(page, 'ACT-e2e-p1')
  await expect(dialog.getByRole('radio')).toHaveCount(1)
  await expect(dialog).not.toContainText('ARP isolation')
})

test('without the policy, only the proposed enforcement is offered, and the dialog says why', async ({
  page,
  stub,
}) => {
  await openKillswitch(page)
  await stub.set({ policyDown: true })
  const dialog = await openApproval(page, 'ACT-e2e-p1')
  await expect(dialog).toContainText('Could not read which enforcement types are available')
  await expect(dialog.getByRole('radio')).toHaveCount(1)
  await expect(dialog.getByRole('radio', { name: /^DNS sinkhole/ })).toBeChecked()
  await dialog.getByRole('button', { name: 'Approve: DNS sinkhole' }).click()
  await expect(outcome(page)).toHaveAttribute('data-state', 'active')
})

test('cancelling the dialog approves nothing', async ({ page, stub }) => {
  await openKillswitch(page)
  const dialog = await openApproval(page, 'ACT-e2e-p2')
  // The action carries no client_name: the inventory's name stands in.
  await expect(dialog).toContainText('living-room-tv')
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toBeHidden()
  await expect(row(page, 'pending-table', 'ACT-e2e-p2')).toBeVisible()
  expect(await stub.count('killswitch', '/actions/ACT-e2e-p2/approve')).toBe(0)
})

test('a 202 approve is in progress — neither success nor failure — until the driver answers', async ({
  page,
  stub,
}) => {
  await stub.set({ slowApply: ['ACT-e2e-p3'] })
  await openKillswitch(page)
  await approve(page, 'ACT-e2e-p3', /^Cut off from the network/)

  await expect(outcome(page)).toHaveAttribute('data-state', 'approved')
  await expect(outcome(page)).toHaveClass(/outcome-progress/)
  await expect(outcome(page)).toContainText(
    'in progress — waiting for the network agent to confirm',
  )
  // Not listed as enforced, and not pending any more: only "in progress".
  // in_flight says "apply" for every approval; who it waits for comes from
  // the action type.
  const progress = row(page, 'progress-table', 'ACT-e2e-p3')
  await expect(progress).toContainText('not enforced until confirmed')
  await expect(progress.getByTestId('progress-what')).toContainText(
    'being applied as ARP Isolation — waiting for the network agent to confirm',
  )
  await expect(row(page, 'active-table', 'ACT-e2e-p3')).toHaveCount(0)
  await expect(row(page, 'pending-table', 'ACT-e2e-p3')).toHaveCount(0)

  // Still approved on the next reads: still in progress.
  await expect
    .poll(() => stub.count('killswitch', '/actions/ACT-e2e-p3'), SETTLE)
    .toBeGreaterThan(1)
  await expect(page.getByTestId('outcome')).toHaveCount(1)

  await stub.settle('ACT-e2e-p3')
  await expect(outcome(page)).toHaveAttribute('data-state', 'active', SETTLE)
  await expect(outcome(page)).toContainText('is now blocked for printer')
  await expect(row(page, 'active-table', 'ACT-e2e-p3')).toBeVisible()
  await expect(page.getByTestId('progress-table')).toHaveCount(0)
})

test('an apply that fails after a 202 is reported as a failure once it settles', async ({
  page,
  stub,
}) => {
  await stub.set({ slowApply: ['ACT-e2e-p3'] })
  await openKillswitch(page)
  await approve(page, 'ACT-e2e-p3', /^Cut off from the network/)
  await expect(outcome(page)).toHaveAttribute('data-state', 'approved')

  await stub.settle('ACT-e2e-p3', 'apply_failed')
  await expect(outcome(page)).toHaveAttribute('data-state', 'apply_failed', SETTLE)
  await expect(outcome(page)).toContainText('could NOT be applied')
  await expect(row(page, 'failures-table', 'ACT-e2e-p3')).toContainText(
    'apply failed — not enforced',
  )
})

test('an approval still in progress is found again after a reload', async ({ page, stub }) => {
  await stub.set({ slowApply: ['ACT-e2e-p2'] })
  await openKillswitch(page)
  await approve(page, 'ACT-e2e-p2')
  await expect(outcome(page)).toHaveAttribute('data-state', 'approved')

  // GET /actions/active does not list it; the page finds it in the audit log.
  await page.reload()
  await expect(row(page, 'progress-table', 'ACT-e2e-p2')).toContainText('DNS Sinkhole')
  await expect(row(page, 'progress-table', 'ACT-e2e-p2')).toContainText('Michal')

  await stub.settle('ACT-e2e-p2')
  await expect(row(page, 'active-table', 'ACT-e2e-p2')).toBeVisible(SETTLE)
  await expect(page.getByTestId('progress-table')).toHaveCount(0)
})

// Once with a controller that reports in_flight, once with one that
// predates it: the page's own revert is followed either way.
for (const inFlight of [true, false]) {
  test(`a 202 revert keeps the block listed as in force until the driver confirms${inFlight ? '' : ' (no in_flight)'}`, async ({
    page,
    stub,
  }) => {
    await stub.set({ slowRevert: ['ACT-e2e-a1'], inFlight })
    await openKillswitch(page)
    page.once('dialog', (d) => void d.accept('done with it'))
    await row(page, 'active-table', 'ACT-e2e-a1').getByRole('button', { name: 'Revert' }).click()

    await expect(outcome(page)).toHaveAttribute('data-state', 'active')
    await expect(outcome(page)).toHaveClass(/outcome-progress/)
    await expect(outcome(page)).toContainText('stays in force until then')
    const active = row(page, 'active-table', 'ACT-e2e-a1')
    await expect(active.getByTestId('being-lifted')).toHaveText('being lifted — still in force')
    await expect(active.getByRole('button', { name: 'Revert' })).toBeDisabled()
    await expect(row(page, 'progress-table', 'ACT-e2e-a1')).toContainText('being lifted')

    await stub.settle('ACT-e2e-a1')
    await expect(outcome(page)).toHaveAttribute('data-state', 'reverted', SETTLE)
    await expect(outcome(page)).toContainText('the block on laptop')
    await expect(active).toHaveCount(0)
  })
}

test('a block someone else is lifting shows as being lifted, not as an ordinary block', async ({
  page,
  stub,
}) => {
  // The TTL reaper (or another operator) started a revert the driver has
  // not confirmed; this page did not start it.
  await stub.beginRevert('ACT-e2e-a1', 'ttl')
  await openKillswitch(page)
  const active = row(page, 'active-table', 'ACT-e2e-a1')
  await expect(active).toHaveAttribute('data-lifting', 'true')
  await expect(active.getByTestId('being-lifted')).toHaveText('being lifted — still in force')
  await expect(active.getByRole('button', { name: 'Revert' })).toBeDisabled()
  const progress = row(page, 'progress-table', 'ACT-e2e-a1')
  await expect(progress).toHaveAttribute('data-verb', 'revert')
  await expect(progress.getByTestId('progress-what')).toContainText(
    'being lifted — waiting for AdGuard to answer; still in force until it is confirmed',
  )
  // Nobody asked from here: nothing to report.
  await expect(page.getByTestId('outcome')).toHaveCount(0)

  await stub.settle('ACT-e2e-a1')
  await page.reload()
  await expect(page.getByTestId('active-table')).toHaveCount(0)
  await expect(page.getByTestId('progress-table')).toHaveCount(0)
})

test('without in_flight, an older controller’s active block is shown as it was', async ({
  page,
  stub,
}) => {
  await stub.set({ inFlight: false })
  await stub.beginRevert('ACT-e2e-a1', 'ttl')
  await openKillswitch(page)
  const active = row(page, 'active-table', 'ACT-e2e-a1')
  await expect(active).toHaveAttribute('data-state', 'active')
  await expect(active.getByTestId('being-lifted')).toHaveCount(0)
  await expect(active.getByRole('button', { name: 'Revert' })).toBeEnabled()
  await expect(page.getByTestId('progress-table')).toHaveCount(0)
})

// The state stays revert_failed while a retry runs: only in_flight tells a
// retry under way from one that failed again.
test('retrying a failed revert is in progress, not another failure, until it answers', async ({
  page,
  stub,
}) => {
  await stub.set({ failRevert: ['ACT-e2e-a1'] })
  await openKillswitch(page)
  page.once('dialog', (d) => void d.accept('done with it'))
  await row(page, 'active-table', 'ACT-e2e-a1').getByRole('button', { name: 'Revert' }).click()
  await expect(outcome(page)).toHaveAttribute('data-state', 'revert_failed')

  // AdGuard is back, but slow.
  await stub.set({ failRevert: [], slowRevert: ['ACT-e2e-a1'] })
  page.once('dialog', (d) => void d.accept('try again'))
  const active = row(page, 'active-table', 'ACT-e2e-a1')
  await active.getByRole('button', { name: 'Revert' }).click()
  await expect(outcome(page)).toHaveClass(/outcome-progress/)
  await expect(outcome(page)).toHaveAttribute('data-state', 'revert_failed')
  await expect(outcome(page)).toContainText('Retrying the revert of ACT-e2e-a1: in progress')
  await expect(active.getByTestId('being-lifted')).toHaveText(
    'retrying the revert — still in force',
  )
  await expect(row(page, 'failures-table', 'ACT-e2e-a1')).toContainText(
    'revert failed — retrying now, still enforced',
  )
  await expect(row(page, 'progress-table', 'ACT-e2e-a1')).toContainText(
    'retrying a revert that failed',
  )

  await stub.settle('ACT-e2e-a1')
  await expect(outcome(page)).toHaveAttribute('data-state', 'reverted', SETTLE)
  await expect(active).toHaveCount(0)
})

test.describe('why automatic blocking is off', () => {
  test('on: the page says what happens without anyone approving', async ({ page }) => {
    await openKillswitch(page)
    const status = page.getByTestId('auto-block')
    await expect(status).toHaveAttribute('data-on', 'true')
    await expect(status).toContainText('Automatic blocking is on')
  })

  test('off for a reason the UI knows: the reason as given, and what it means', async ({
    page,
    stub,
  }) => {
    await stub.set({ autoBlockReason: 'auto-block disabled: POLICY_AUTO_BLOCK is off' })
    await openKillswitch(page)
    const status = page.getByTestId('auto-block')
    await expect(status).toHaveAttribute('data-on', 'false')
    await expect(status).toContainText('Automatic blocking is off.')
    await expect(status).toContainText('Nothing is blocked unless someone approves it here')
    await expect(status).toContainText(
      'switched off in the killswitch settings (POLICY_AUTO_BLOCK)',
    )
    await expect(status.getByTestId('auto-block-reason')).toHaveText(
      'auto-block disabled: POLICY_AUTO_BLOCK is off',
    )
  })

  test('off for a reason the UI has never heard of: shown verbatim', async ({ page, stub }) => {
    await stub.set({ autoBlockReason: 'auto-block disabled: maintenance window until 18:00' })
    await openKillswitch(page)
    const status = page.getByTestId('auto-block')
    await expect(status).toContainText('Automatic blocking is off.')
    await expect(status.getByTestId('auto-block-reason')).toHaveText(
      'auto-block disabled: maintenance window until 18:00',
    )
  })
})

test('an action someone else already handled: the 409 says so, with its state now', async ({
  page,
  browser,
}) => {
  await page.clock.install()
  await openKillswitch(page)
  const dialog = await openApproval(page, 'ACT-e2e-p1')

  // Anna rejects it in another browser while the dialog is open here.
  const other = await (await browser.newContext()).newPage()
  await signIn(other, 'Anna')
  await other.goto('/killswitch')
  other.once('dialog', (d) => void d.accept('not ours'))
  await row(other, 'pending-table', 'ACT-e2e-p1').getByRole('button', { name: 'Reject' }).click()
  await expect(other.getByTestId('outcome').first()).toHaveAttribute('data-state', 'rejected')
  await other.context().close()

  await dialog.getByRole('button', { name: /^Approve: / }).click()
  await expect(outcome(page)).toHaveAttribute('data-state', 'rejected')
  await expect(outcome(page)).toHaveClass(/outcome-warn/)
  await expect(outcome(page)).toContainText('action ACT-e2e-p1 is rejected, not pending')
  await expect(outcome(page)).toContainText('It is now rejected')
  await expect(row(page, 'pending-table', 'ACT-e2e-p1')).toHaveCount(0)
})

test('a type that became unavailable is refused with 422, and the dialog then offers what is left', async ({
  page,
  stub,
}) => {
  await openKillswitch(page)
  const dialog = await openApproval(page, 'ACT-e2e-p3')
  await dialog.getByRole('radio', { name: /^Cut off from the network/ }).check()
  // The agent stops polling while the dialog is open.
  await stub.set({ available: ['dns_sinkhole'] })
  await dialog.getByRole('button', { name: /^Approve: / }).click()

  await expect(outcome(page)).toHaveClass(/outcome-fail/)
  await expect(outcome(page)).toContainText('"arp_isolate" is not available')
  await expect(outcome(page)).toContainText('Available now: DNS Sinkhole')
  await expect(row(page, 'pending-table', 'ACT-e2e-p3')).toBeVisible()

  await openApproval(page, 'ACT-e2e-p3')
  await expect(dialog.getByRole('radio')).toHaveCount(1)
})

test('an approve that returns apply_failed is shown as a failure', async ({ page, stub }) => {
  await stub.set({ failApply: ['ACT-e2e-p3'] })
  await openKillswitch(page)
  await approve(page, 'ACT-e2e-p3')

  await expect(outcome(page)).toHaveAttribute('data-state', 'apply_failed')
  await expect(outcome(page)).toContainText('could NOT be applied')
  await expect(outcome(page)).toContainText('AdGuard at 10.0.0.53 unreachable')

  const failure = row(page, 'failures-table', 'ACT-e2e-p3')
  await expect(failure).toContainText('apply failed — not enforced')
  await expect(row(page, 'active-table', 'ACT-e2e-p3')).toHaveCount(0)
  await expect(row(page, 'pending-table', 'ACT-e2e-p3')).toHaveCount(0)
})

test('a revert that returns 502 revert_failed is shown as still enforced', async ({
  page,
  stub,
}) => {
  await stub.set({ failRevert: ['ACT-e2e-a1'] })
  await openKillswitch(page)

  page.once('dialog', (d) => void d.accept('done with it'))
  await row(page, 'active-table', 'ACT-e2e-a1').getByRole('button', { name: 'Revert' }).click()

  await expect(outcome(page)).toHaveAttribute('data-state', 'revert_failed')
  await expect(outcome(page)).toContainText('still in force')

  const active = row(page, 'active-table', 'ACT-e2e-a1')
  await expect(active).toHaveAttribute('data-state', 'revert_failed')
  await expect(active).toContainText('revert failed — still enforced')
  await expect(row(page, 'failures-table', 'ACT-e2e-a1')).toContainText('still enforced')
})

test('rows keep their order across refreshes', async ({ page, stub }) => {
  await stub.set({ shuffle: true })
  await page.clock.install()
  await openKillswitch(page)

  const ids = () =>
    page
      .getByTestId('pending-table')
      .locator('tbody tr')
      .evaluateAll((rows) => rows.map((r) => r.getAttribute('data-action-id')))
  const expected = ['ACT-e2e-p1', 'ACT-e2e-p2', 'ACT-e2e-p3'] // oldest first
  expect(await ids()).toEqual(expected)

  for (let i = 0; i < 3; i++) {
    const before = await stub.count('killswitch', '/actions/pending')
    await page.clock.runFor(10_000)
    await expect.poll(() => stub.count('killswitch', '/actions/pending')).toBeGreaterThan(before)
    expect(await ids()).toEqual(expected)
  }
})

test('reject records the outcome, the reason and the actor', async ({ page, stub }) => {
  await openKillswitch(page)
  page.once('dialog', (d) => void d.accept('False positive'))
  await row(page, 'pending-table', 'ACT-e2e-p2').getByRole('button', { name: 'Reject' }).click()
  await expect(outcome(page)).toHaveAttribute('data-state', 'rejected')
  await expect(row(page, 'pending-table', 'ACT-e2e-p2')).toHaveCount(0)
  const sent = (await stub.seen()).find((s) => s.path === '/actions/ACT-e2e-p2/reject')!
  expect(sent.actor).toBe('Michal')
  expect(JSON.parse(sent.body)).toEqual({ reason: 'False positive' })
})

test('past failures come from the controller', async ({ page }) => {
  await openKillswitch(page)
  await expect(row(page, 'failures-table', 'ACT-e2e-f1')).toContainText('AdGuard returned 500')
})

test.describe('history and audit log', () => {
  test.beforeEach(async ({ stub }) => {
    await stub.reset({ finished: 60 })
  })

  test('history lists finished actions with who ended them, fifty at a time', async ({
    page,
    stub,
  }) => {
    await signIn(page)
    await page.goto('/killswitch/history')
    const rows = page.getByTestId('history-table').locator('tbody tr')
    await expect(rows).toHaveCount(50)
    // Most recently finished first, in the controller's order.
    await expect(rows.nth(0)).toHaveAttribute('data-action-id', 'ACT-e2e-f1')
    await expect(rows.nth(1)).toHaveAttribute('data-action-id', 'ACT-e2e-h1')
    await expect(row(page, 'history-table', 'ACT-e2e-f1').getByTestId('ended-by')).toHaveText(
      'the driver (apply failed)',
    )
    const h1 = row(page, 'history-table', 'ACT-e2e-h1')
    await expect(h1.getByTestId('outcome-state')).toHaveText('reverted (lifted)')
    await expect(h1.getByTestId('ended-by')).toHaveText('the TTL reaper (automatic)')
    await expect(h1).toContainText('kids-tablet')

    await page.getByRole('button', { name: 'Show 50 more' }).click()
    await expect(rows).toHaveCount(62)
    await expect(page.getByRole('button', { name: 'Show 50 more' })).toHaveCount(0)
    const searches = (await stub.seen())
      .filter((s) => s.path === '/actions/history')
      .map((s) => s.search)
    expect(searches).toEqual(['?limit=50', '?limit=100'])
  })

  test('the audit log says who did what, when, to which device and why, and pages back', async ({
    page,
    stub,
  }) => {
    await openKillswitch(page)
    await approve(page, 'ACT-e2e-p1')
    await expect(outcome(page)).toHaveAttribute('data-state', 'active')

    await page.getByTestId('killswitch-nav').getByRole('link', { name: 'Audit log' }).click()
    const rows = page.getByTestId('audit-table').locator('tbody tr')
    await expect(rows).toHaveCount(50)
    const [enforced, approved] = [rows.nth(0), rows.nth(1)]
    for (const [r, what] of [
      [enforced, 'enforced'],
      [approved, 'approved'],
    ] as const) {
      await expect(r).toHaveAttribute('data-action-id', 'ACT-e2e-p1')
      await expect(r.getByTestId('audit-actor')).toHaveText('Michal')
      await expect(r.getByTestId('audit-what')).toHaveText(what)
      await expect(r).toContainText('kids-tablet')
      await expect(r).toContainText('pending: confidence=80 severity=high signals=1')
      await expect(r).toContainText('DNS query for a domain listed by ThreatFox')
    }

    const newestSeq = Number(await rows.first().getAttribute('data-seq'))
    await page.getByRole('button', { name: 'Older' }).click()
    await expect(rows.first()).toHaveAttribute('data-seq', String(newestSeq - 50))
    await page.getByRole('button', { name: 'Newer' }).click()
    await expect(rows.first()).toHaveAttribute('data-seq', String(newestSeq))
    expect((await stub.seen()).filter((s) => s.path === '/audit').map((s) => s.search)).toContain(
      `?limit=50&before=${newestSeq - 49}`,
    )

    // One action's trail, from its link.
    await rows.first().getByRole('link', { name: 'ACT-e2e-p1' }).click()
    await expect(rows).toHaveCount(3)
    await expect(rows.getByTestId('audit-what')).toHaveText([
      'enforced',
      'approved',
      'proposed, waiting for approval',
    ])
    await expect(rows.last().getByTestId('audit-actor')).toHaveText('the policy (automatic)')
  })
})
