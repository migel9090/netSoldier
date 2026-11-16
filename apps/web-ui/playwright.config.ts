import { defineConfig, devices } from '@playwright/test'

/**
 * Browser tests against the production build (`node build`), in front of
 * stub backends and, for real-backends.spec.ts, the real Go services built
 * from this tree; servers are started by tests/browser/global-setup.ts on
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
    { name: 'lan-http', testIgnore: 'real-backends.spec.ts' },
    {
      name: 'tls',
      testMatch: 'auth.spec.ts',
      use: { ignoreHTTPSErrors: true },
    },
    // The UI in front of the real Go services (tests/browser/real/stack.ts);
    // needs the Go toolchain, or E2E_REAL_BACKENDS=skip to leave it out.
    { name: 'real-backends', testMatch: 'real-backends.spec.ts' },
  ],
})
