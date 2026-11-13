import { defineConfig, devices } from '@playwright/test'

/**
 * Browser tests against the production build (`node build`) and stub
 * backends; servers are started by tests/browser/global-setup.ts on
 * ephemeral 127.0.0.1 ports. Run with `npm run test:e2e`, which builds first.
 *
 * Browser: Playwright's Chromium (`npx playwright install chromium`, or
 * `--with-deps chromium` on a bare CI image). To use a system Chromium
 * instead, set PLAYWRIGHT_CHROMIUM_EXECUTABLE to its path.
 */
export default defineConfig({
  testDir: './tests/browser',
  testMatch: '*.spec.ts',
  globalSetup: './tests/browser/global-setup.ts',
  // One stub backend with shared state: tests run one at a time.
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    ...devices['Desktop Chrome'],
    trace: 'retain-on-failure',
    launchOptions: {
      // netsoldier.lan stands in for a LAN host name; see global-setup.ts.
      args: ['--host-resolver-rules=MAP netsoldier.lan 127.0.0.1'],
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE || undefined,
    },
  },
  projects: [
    { name: 'lan-http' },
    {
      name: 'tls',
      testMatch: 'auth.spec.ts',
      use: { ignoreHTTPSErrors: true },
    },
  ],
})
