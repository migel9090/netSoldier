import { test, expect, signIn, PASSWORD } from './fixtures'

// Runs twice: "lan-http" (plain HTTP on a LAN host name) and "tls" (behind a
// TLS-terminating proxy). Sign-in was broken in both.

test('sign-in sets the session cookies and lands on the dashboard', async ({
  page,
  context,
  baseURL,
}, testInfo) => {
  await signIn(page, 'Michal')
  await expect(page).toHaveURL(`${baseURL}/`)
  await expect(page.getByTestId('actor')).toHaveText('Michal')

  const tls = testInfo.project.name === 'tls'
  const cookies = Object.fromEntries((await context.cookies()).map((c) => [c.name, c]))
  expect(cookies.netsoldier_session).toMatchObject({
    httpOnly: true,
    secure: tls,
    sameSite: 'Strict',
    path: '/',
  })
  expect(cookies.netsoldier_csrf).toMatchObject({
    httpOnly: false,
    secure: tls,
    sameSite: 'Strict',
  })
  expect(cookies.netsoldier_device).toMatchObject({
    httpOnly: true,
    secure: tls,
    sameSite: 'Strict',
    path: '/api/login',
  })
  // Long-lived (about 180 days), unlike the 12 h session.
  expect(cookies.netsoldier_device.expires * 1000 - Date.now()).toBeGreaterThan(170 * 86400_000)

  // The session survives a reload: it really is in the cookie jar.
  await page.goto('/killswitch')
  await expect(page.getByRole('heading', { name: 'Killswitch' })).toBeVisible()
})

test('a wrong password is refused', async ({ page, context }) => {
  await page.goto('/login')
  await page.getByLabel('Password').fill('not the password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByTestId('login-error')).toHaveText('invalid credentials')
  expect(await context.cookies()).toEqual([])
})

test('a non-ASCII name is rejected at sign-in with a helpful message', async ({
  page,
  context,
}) => {
  await page.goto('/login')
  await page.getByLabel('Who are you?').fill('Łukasz')
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  const error = page.getByTestId('login-error')
  await expect(error).toContainText('plain ASCII')
  await expect(error).toContainText('Try "Lukasz"')
  await expect(page).toHaveURL(/\/login$/)
  expect(await context.cookies()).toEqual([])
})

// The killswitch refuses every approve, reject and revert signed with one of
// its own actor names; such a session could look at the page but never act.
test('a name the killswitch keeps for itself is rejected at sign-in', async ({ page, context }) => {
  await page.goto('/login')
  await page.getByLabel('Who are you?').fill('System')
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Sign in' }).click()
  const error = page.getByTestId('login-error')
  await expect(error).toContainText('"System" is reserved')
  await expect(error).toContainText('Sign in with your own name')
  await expect(page).toHaveURL(/\/login$/)
  expect(await context.cookies()).toEqual([])
})

test('sign-out clears the session', async ({ page, context }) => {
  await signIn(page, 'Anna')
  const before = (await context.cookies()).find((c) => c.name === 'netsoldier_session')!

  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login$/)
  // Only the device cookie ("this browser signed in before") stays.
  expect((await context.cookies()).map((c) => c.name)).toEqual(['netsoldier_device'])

  await page.goto('/killswitch')
  await expect(page).toHaveURL(/\/login$/)

  // A copy of the old cookie is refused too: sign-out revoked it server-side.
  await context.addCookies([before])
  const status = await page.evaluate(async () => (await fetch('/api/killswitch/pending')).status)
  expect(status).toBe(401)
})
