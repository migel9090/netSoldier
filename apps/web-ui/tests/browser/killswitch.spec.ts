import type { Page } from '@playwright/test'
import { test, expect, signIn } from './fixtures'

function row(page: Page, table: string, id: string) {
  return page.getByTestId(table).locator(`tr[data-action-id="${id}"]`)
}

async function openKillswitch(page: Page) {
  await signIn(page)
  await page.goto('/killswitch')
  await expect(page.getByTestId('pending-table')).toBeVisible()
}

test('approve: the confirmation names the device and the block, and the new state is shown', async ({
  page,
  stub,
}) => {
  await openKillswitch(page)

  let message = ''
  page.once('dialog', (d) => {
    message = d.message()
    void d.accept()
  })
  await row(page, 'pending-table', 'ACT-e2e-p1').getByRole('button', { name: 'Approve' }).click()

  const outcome = page.getByTestId('outcome').first()
  await expect(outcome).toHaveAttribute('data-state', 'active')
  await expect(outcome).toContainText('is now blocked for kids-tablet')

  for (const part of [
    'kids-tablet',
    'aa:bb:cc:00:00:01',
    '192.168.1.77',
    'DNS Sinkhole',
    'evil.example',
    'DNS query for a domain listed by ThreatFox',
  ]) {
    expect(message).toContain(part)
  }

  await expect(row(page, 'pending-table', 'ACT-e2e-p1')).toHaveCount(0)
  await expect(row(page, 'active-table', 'ACT-e2e-p1')).toHaveAttribute('data-state', 'active')

  // The approver is the signed-in actor, sent by the proxy as a header.
  const approve = (await stub.seen()).find((s) => s.path === '/actions/ACT-e2e-p1/approve')!
  expect(approve.actor).toBe('Michal')
  expect(approve.body).toBe('{}')
})

test('the confirmation falls back to the inventory name when the action has none', async ({
  page,
}) => {
  await openKillswitch(page)
  let message = ''
  page.once('dialog', (d) => {
    message = d.message()
    void d.dismiss()
  })
  await row(page, 'pending-table', 'ACT-e2e-p2').getByRole('button', { name: 'Approve' }).click()
  await expect.poll(() => message).toContain('living-room-tv')
  await expect(row(page, 'pending-table', 'ACT-e2e-p2')).toBeVisible()
})

test('an approve that returns apply_failed is shown as a failure', async ({ page, stub }) => {
  await stub.set({ failApply: ['ACT-e2e-p3'] })
  await openKillswitch(page)

  page.once('dialog', (d) => void d.accept())
  await row(page, 'pending-table', 'ACT-e2e-p3').getByRole('button', { name: 'Approve' }).click()

  const outcome = page.getByTestId('outcome').first()
  await expect(outcome).toHaveAttribute('data-state', 'apply_failed')
  await expect(outcome).toContainText('could NOT be applied')
  await expect(outcome).toContainText('AdGuard at 10.0.0.53 unreachable')

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

  const outcome = page.getByTestId('outcome').first()
  await expect(outcome).toHaveAttribute('data-state', 'revert_failed')
  await expect(outcome).toContainText('still in force')

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

test('reject records the outcome and removes the row', async ({ page }) => {
  await openKillswitch(page)
  page.once('dialog', (d) => void d.accept('False positive'))
  await row(page, 'pending-table', 'ACT-e2e-p2').getByRole('button', { name: 'Reject' }).click()
  await expect(page.getByTestId('outcome').first()).toHaveAttribute('data-state', 'rejected')
  await expect(row(page, 'pending-table', 'ACT-e2e-p2')).toHaveCount(0)
})

test('history and past failures from a v2 controller are listed', async ({ page }) => {
  await openKillswitch(page)
  await expect(row(page, 'history-table', 'ACT-e2e-h1')).toContainText('reverted')
  await expect(row(page, 'failures-table', 'ACT-e2e-f1')).toContainText('AdGuard returned 500')
})

test.describe('a controller that predates contract v2', () => {
  test.beforeEach(async ({ stub }) => {
    await stub.reset({ legacy: true, failApply: ['ACT-e2e-p1'], failRevert: ['ACT-e2e-a1'] })
  })

  test('missing endpoints read as "not available yet"', async ({ page }) => {
    await openKillswitch(page)
    await expect(page.getByText('does not report past failures yet')).toBeVisible()
    await expect(page.getByText('History is not available')).toBeVisible()
    await expect(page.locator('p.error')).toHaveCount(0)
  })

  test('a legacy failed state renders as a failure', async ({ page }) => {
    await openKillswitch(page)
    page.once('dialog', (d) => void d.accept())
    await row(page, 'pending-table', 'ACT-e2e-p1').getByRole('button', { name: 'Approve' }).click()
    const outcome = page.getByTestId('outcome').first()
    await expect(outcome).toHaveAttribute('data-state', 'failed')
    await expect(outcome).toContainText('could NOT be applied')
    await expect(row(page, 'failures-table', 'ACT-e2e-p1')).toContainText('apply failed')
  })

  test('a failed revert stays listed as enforced although the controller drops it', async ({
    page,
  }) => {
    await page.clock.install()
    await openKillswitch(page)
    page.once('dialog', (d) => void d.accept('done'))
    await row(page, 'active-table', 'ACT-e2e-a1').getByRole('button', { name: 'Revert' }).click()
    await expect(page.getByTestId('outcome').first()).toContainText('still in force')

    // Survives the next refresh, re-read from GET /actions/{id}.
    await page.clock.runFor(10_000)
    const active = row(page, 'active-table', 'ACT-e2e-a1')
    await expect(active).toContainText('revert failed — still enforced')
    await expect(active).toHaveAttribute('data-state', 'failed')
  })
})
