import { test as base, expect, type Page } from '@playwright/test'
import type { Scenario, Seen } from './stub/backends'

/** Drives the stub backends' control port (see stub/backends.ts). */
export class Stub {
  constructor(readonly base: string) {}

  async reset(scenario: Partial<Scenario> = {}): Promise<void> {
    const res = await fetch(`${this.base}/reset`, {
      method: 'POST',
      body: JSON.stringify(scenario),
    })
    if (!res.ok) throw new Error(`stub reset: ${res.status}`)
  }

  async set(scenario: Partial<Scenario>): Promise<void> {
    const res = await fetch(`${this.base}/scenario`, {
      method: 'POST',
      body: JSON.stringify(scenario),
    })
    if (!res.ok) throw new Error(`stub scenario: ${res.status}`)
  }

  /** Delivers the driver's late answer to an operation that got a 202. */
  async settle(id: string, state?: string): Promise<void> {
    const res = await fetch(`${this.base}/settle`, {
      method: 'POST',
      body: JSON.stringify({ id, state }),
    })
    if (!res.ok) throw new Error(`stub settle ${id}: ${res.status}`)
  }

  async seen(): Promise<Seen[]> {
    return (await fetch(`${this.base}/seen`)).json()
  }

  async count(service: Seen['service'], path: string): Promise<number> {
    return (await this.seen()).filter((s) => s.service === service && s.path === path).length
  }
}

/** Everything the page reported that a working UI never should. */
export interface PageProblems {
  cspViolations: () => Promise<string[]>
  consoleErrors: string[]
  /** "<status> <url>" of every response with status >= 400. */
  failedResponses: string[]
}

export const test = base.extend<{ stub: Stub; problems: PageProblems }>({
  // The servers run on ephemeral ports chosen in global-setup.ts.
  baseURL: async ({}, use, testInfo) => {
    const urls: Record<string, string | undefined> = {
      'lan-http': process.env.E2E_HTTP_URL,
      tls: process.env.E2E_TLS_URL,
      'real-backends': process.env.E2E_REAL_URL,
    }
    const url = urls[testInfo.project.name]
    if (!url) testInfo.skip(true, `no server for project ${testInfo.project.name}`)
    await use(url)
  },

  // Automatic, so no test inherits the previous test's scenario.
  stub: [
    async ({}, use) => {
      const stub = new Stub(process.env.E2E_STUB_CONTROL!)
      await stub.reset()
      await use(stub)
    },
    { auto: true },
  ],

  problems: async ({ page }, use) => {
    const consoleErrors: string[] = []
    page.on('console', (m) => {
      if (m.type() === 'error') consoleErrors.push(m.text())
    })
    page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`))
    const failedResponses: string[] = []
    page.on('response', (r) => {
      if (r.status() >= 400) failedResponses.push(`${r.status()} ${r.url()}`)
    })
    // Init scripts are injected by the browser, outside the page's CSP, so
    // this listener exists before the page's first script runs.
    await page.addInitScript(() => {
      const w = window as unknown as { __csp: string[] }
      w.__csp = []
      document.addEventListener('securitypolicyviolation', (e) => {
        w.__csp.push(`${e.violatedDirective} blocked ${e.blockedURI || 'inline'}`)
      })
    })
    await use({
      consoleErrors,
      failedResponses,
      cspViolations: () => page.evaluate(() => (window as unknown as { __csp: string[] }).__csp),
    })
  },
})

export { expect }

export const PASSWORD = process.env.E2E_PASSWORD ?? ''

export async function signIn(page: Page, actor = 'Michal'): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Who are you?').fill(actor)
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
}
