import type { Browser, BrowserContext, Page } from '@playwright/test'
import { test, expect, PASSWORD } from './fixtures'

/**
 * Password guessing must not lock the household out of the approval UI.
 *
 * Runs against its own server (see global-setup.ts), which trusts
 * X-Forwarded-For so guesses can come from many "addresses". Its global
 * window is exhausted here and stays so for the rest of the run.
 */

const BASE = process.env.E2E_LOCKOUT_URL ?? ''
const DIRECT = process.env.E2E_LOCKOUT_DIRECT ?? ''

const PAUSED = 'browsers that have signed in here before are not affected'

const contexts: BrowserContext[] = []

async function context(browser: Browser, address: string): Promise<BrowserContext> {
  const c = await browser.newContext({ extraHTTPHeaders: { 'X-Forwarded-For': address } })
  contexts.push(c)
  return c
}

test.afterEach(async () => {
  await Promise.all(contexts.splice(0).map((c) => c.close()))
})

async function trySignIn(page: Page, actor: string): Promise<void> {
  await page.goto(`${BASE}/login`)
  await page.getByLabel('Who are you?').fill(actor)
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
}

/** Wrong guesses straight at the server, as a LAN attacker would send them. */
async function guess(address: string, times: number): Promise<number[]> {
  const statuses: number[] = []
  for (let i = 0; i < times; i++) {
    const res = await fetch(`${DIRECT}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: BASE, 'X-Forwarded-For': address },
      body: JSON.stringify({ password: `guess ${i}`, actor: 'x' }),
    })
    statuses.push(res.status)
  }
  return statuses
}

test('a browser that signed in before is not locked out by password guessing', async ({
  browser,
}) => {
  test.skip(!BASE, 'no lockout server')

  // The household's browser signs in once, then signs out.
  const household = await context(browser, '192.168.1.20')
  const page = await household.newPage()
  await trySignIn(page, 'Anna')
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login$/)
  const [device] = await household.cookies()
  expect(device).toMatchObject({
    name: 'netsoldier_device',
    path: '/api/login',
    httpOnly: true,
    sameSite: 'Strict',
  })

  // An attacker uses up the household's own address window, then the global one.
  expect(await guess('192.168.1.20', 5)).toEqual([401, 401, 401, 401, 401])
  for (const address of ['10.66.0.1', '10.66.0.2', '10.66.0.3']) await guess(address, 5)
  expect(await guess('10.66.0.4', 1)).toEqual([429])

  // A browser that never signed in here is paused, and told why.
  const stranger = await (await context(browser, '192.168.1.21')).newPage()
  await trySignIn(stranger, 'Guest')
  await expect(stranger.getByTestId('login-error')).toContainText(PAUSED)

  // A forged device cookie earns no exemption.
  const forger = await context(browser, '192.168.1.22')
  const sig = device.value.slice(-1) === 'A' ? 'B' : 'A'
  await forger.addCookies([{ ...device, value: device.value.slice(0, -1) + sig }])
  const forged = await forger.newPage()
  await trySignIn(forged, 'Mallory')
  await expect(forged.getByTestId('login-error')).toContainText(PAUSED)

  // The household's browser still gets in, from its exhausted address.
  await trySignIn(page, 'Anna')
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  await expect(page.getByTestId('actor')).toHaveText('Anna')
})
