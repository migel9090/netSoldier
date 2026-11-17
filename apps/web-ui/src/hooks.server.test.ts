import { createHmac } from 'node:crypto'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { handle } from './hooks.server'
import * as loginEndpoint from './routes/api/login/+server'
import * as logoutEndpoint from './routes/api/logout/+server'
import { issueDeviceToken } from '#lib/server/device.ts'
import { renderMetrics, resetMetrics } from '#lib/server/metrics.ts'
import { loginLimiter } from '#lib/server/ratelimit.ts'
import { env } from './testing/env'
import { PAGE_CSP, TestBrowser, parseSetCookie, type Endpoints } from './testing/kit'

/**
 * These tests drive the whole `handle` hook — configuration, session, Origin
 * and CSRF checks, the real sign-in/sign-out endpoints through `resolve()`,
 * and the proxy against a real HTTP backend on 127.0.0.1. The previous tests
 * only exercised the helpers, and passed while nobody could sign in.
 */

const endpoints: Endpoints = {
  '/api/login': loginEndpoint as Endpoints[string],
  '/api/logout': logoutEndpoint as Endpoints[string],
}

const SECRET = 'test-session-secret-that-is-long-enough-0123456789'
const PASSWORD = 'correct horse battery staple'
const LAN = 'http://192.168.1.5:3000'
const TLS = 'https://netsoldier.lan'

interface Seen {
  method: string
  url: string
  headers: http.IncomingHttpHeaders
  body: string
}

let upstream: http.Server
let upstreamUrl = ''
let seen: Seen[] = []
interface Reply {
  status: number
  body: string
  type?: string
  headers?: Record<string, string>
}

let reply: (req: Seen) => Reply = () => ({
  status: 200,
  body: '[]',
})

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      const s: Seen = { method: req.method ?? '', url: req.url ?? '', headers: req.headers, body }
      seen.push(s)
      const r = reply(s)
      res.writeHead(r.status, { 'Content-Type': r.type ?? 'application/json', ...r.headers })
      res.end(r.body)
    })
  })
  await new Promise<void>((ok) => upstream.listen(0, '127.0.0.1', ok))
  upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`
})

afterAll(async () => {
  await new Promise((ok) => upstream.close(ok))
})

function configure(overrides: Record<string, string | undefined> = {}) {
  for (const key of Object.keys(env)) delete env[key]
  Object.assign(env, {
    SESSION_SECRET: SECRET,
    WEB_UI_PASSWORD: PASSWORD,
    ORIGIN: LAN,
    KILLSWITCH_URL: upstreamUrl,
    KILLSWITCH_API_KEY: 'killswitch-operator-token',
    DEVICE_INVENTORY_URL: upstreamUrl,
    DEVICE_API_KEY: 'device-key',
    DETECTION_ENGINE_URL: upstreamUrl,
    DETECTION_API_KEY: 'detection-key',
    ...overrides,
  })
}

function browser(origin = LAN) {
  return new TestBrowser(handle, endpoints, origin)
}

let logs: { warn: ReturnType<typeof vi.spyOn>; info: ReturnType<typeof vi.spyOn> }

beforeEach(() => {
  configure()
  seen = []
  reply = () => ({ status: 200, body: '[]' })
  loginLimiter.reset()
  resetMetrics()
  logs = {
    warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
    info: vi.spyOn(console, 'log').mockImplementation(() => {}),
  }
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

function cookiesOf(res: Response) {
  return Object.fromEntries(
    res.headers.getSetCookie().map((raw) => [parseSetCookie(raw).name, parseSetCookie(raw)]),
  )
}

describe('configuration', () => {
  it('refuses to serve without the required env, and the probe says why', async () => {
    for (const key of Object.keys(env)) delete env[key]
    const b = browser()

    const page = await b.fetch('/killswitch')
    expect(page.status).toBe(503)
    const text = await page.text()
    for (const name of ['SESSION_SECRET', 'WEB_UI_PASSWORD', 'ORIGIN', 'KILLSWITCH_API_KEY']) {
      expect(text).toContain(name)
    }

    expect((await b.fetch('/api/devices')).status).toBe(503)
    expect((await b.fetch('/api/login', { method: 'POST', body: '{}' })).status).toBe(503)

    const probe = await b.fetch('/healthz')
    expect(probe.status).toBe(503)
    expect((await probe.json()).status).toBe('unconfigured')
  })

  it('rejects a weak SESSION_SECRET', async () => {
    configure({ SESSION_SECRET: 'x' })
    const probe = await browser().fetch('/healthz')
    expect(probe.status).toBe(503)
    expect(JSON.stringify(await probe.json())).toMatch(/SESSION_SECRET is too short/)
  })

  it('rejects an ORIGIN that is not a bare http(s) origin', async () => {
    for (const bad of ['netsoldier.lan', 'http://netsoldier.lan/ui', 'ftp://netsoldier.lan']) {
      configure({ ORIGIN: bad })
      expect((await browser().fetch('/healthz')).status, bad).toBe(503)
    }
  })

  it('serves /healthz without a session once configured', async () => {
    const probe = await browser().fetch('/healthz')
    expect(probe.status).toBe(200)
    expect(await probe.json()).toEqual({ status: 'ok' })
  })

  // This port is published on the LAN; the counters are on the metrics
  // listener (metrics-listener.ts) only.
  it('answers /metrics with a 404, signed in or not, configured or not', async () => {
    const b = browser()
    const check = async (what: string) => {
      for (const method of ['GET', 'HEAD', 'POST']) {
        const res = await b.fetch('/metrics', { method })
        expect(res.status, `${what} ${method}`).toBe(404)
        expect(res.headers.get('location'), what).toBeNull()
        if (method === 'GET') expect(await res.text(), what).not.toContain('netsoldier_webui')
      }
    }
    await check('anonymous')
    await b.signIn(PASSWORD)
    await check('signed in')
    for (const key of Object.keys(env)) delete env[key]
    await check('unconfigured')
  })
})

describe('sign-in', () => {
  it('sets the session and CSRF cookies over plain HTTP, without Secure', async () => {
    const res = await browser().signIn(PASSWORD, 'michal')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ status: 'ok', actor: 'michal' })

    const { netsoldier_session: session, netsoldier_csrf: csrf } = cookiesOf(res)
    expect(session.attributes).toMatchObject({
      httponly: true,
      samesite: 'Strict',
      path: '/',
      'max-age': '43200',
    })
    expect(session.attributes.secure).toBeUndefined()
    expect(csrf.attributes.httponly).toBeUndefined()
    expect(csrf.attributes.secure).toBeUndefined()
    expect(csrf.attributes.samesite).toBe('Strict')
    // Ignored (with a console error on every page) on an untrustworthy origin.
    expect(res.headers.has('cross-origin-opener-policy')).toBe(false)
  })

  it('sets Secure cookies when ORIGIN is https', async () => {
    configure({ ORIGIN: TLS })
    const res = await browser(TLS).signIn(PASSWORD)
    expect(res.status).toBe(200)
    const { netsoldier_session: session, netsoldier_csrf: csrf } = cookiesOf(res)
    expect(session.attributes.secure).toBe(true)
    expect(session.attributes.httponly).toBe(true)
    expect(csrf.attributes.secure).toBe(true)
    expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin')
  })

  it('opens the pages and the API with the session it issued', async () => {
    const b = browser()
    await b.signIn(PASSWORD, 'anna')

    const page = await b.fetch('/killswitch')
    expect(page.status).toBe(200)
    // The page policy is SvelteKit's (with the boot script's nonce); the
    // hook must not replace it.
    expect(page.headers.get('content-security-policy')).toBe(PAGE_CSP)

    const res = await b.fetch('/api/killswitch/pending')
    expect(res.status).toBe(200)
    expect(seen).toHaveLength(1)
    expect(seen[0].url).toBe('/actions/pending')
    expect(seen[0].headers.authorization).toBe('Bearer killswitch-operator-token')
    expect(seen[0].headers['x-netsoldier-actor']).toBe('anna')
    expect(seen[0].headers.cookie).toBeUndefined()
  })

  it('sends pages and data requests without a session to /login', async () => {
    const b = browser()
    for (const isDataRequest of [false, true]) {
      const res = await b.fetch('/killswitch', { isDataRequest })
      expect(res.status).toBe(303)
      expect(res.headers.get('location')).toBe('/login')
    }
    expect((await b.fetch('/login')).status).toBe(200)
    expect((await b.fetch('/api/devices')).status).toBe(401)
  })

  it('sends a signed-in visit to /login on to the dashboard', async () => {
    const b = browser()
    await b.signIn(PASSWORD)
    const res = await b.fetch('/login')
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toBe('/')
  })

  it('refuses a cross-origin or Origin-less sign-in', async () => {
    const b = browser()
    for (const originHeader of ['http://evil.example', 'null', null]) {
      const res = await b.fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: PASSWORD }),
        originHeader,
      })
      expect(res.status, String(originHeader)).toBe(403)
      expect(res.headers.getSetCookie()).toEqual([])
    }
  })

  it('answers malformed bodies with a 4xx, never a 500', async () => {
    const cases: [string, string, number][] = [
      ['application/json', 'not json', 400],
      ['application/json', 'null', 400],
      ['application/json', '[]', 400],
      ['application/json', '{}', 400],
      ['application/json', '{"password":123}', 400],
      ['application/json', `{"password":"${PASSWORD}","actor":7}`, 400],
      ['text/plain', `{"password":"${PASSWORD}"}`, 415],
      ['application/json', JSON.stringify({ password: 'x'.repeat(10_000) }), 413],
    ]
    for (const [type, body, status] of cases) {
      const res = await browser().fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': type },
        body,
      })
      expect(res.status, body.slice(0, 40)).toBe(status)
      expect(typeof (await res.json()).error).toBe('string')
      expect(res.headers.getSetCookie()).toEqual([])
    }
  })

  it('refuses a name outside printable ASCII with a helpful message', async () => {
    const res = await browser().signIn(PASSWORD, 'Łukasz')
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.field).toBe('actor')
    expect(body.error).toContain('ASCII')
    expect(body.error).toContain('"Lukasz"')
    expect(res.headers.getSetCookie()).toEqual([])
  })

  // The killswitch refuses every mutation under these names (400), so a
  // session with one could look but never approve.
  it('refuses a name the killswitch keeps for itself', async () => {
    for (const name of ['ttl', 'System', 'netagent']) {
      const res = await browser().signIn(PASSWORD, name)
      expect(res.status, name).toBe(400)
      const body = await res.json()
      expect(body.field).toBe('actor')
      expect(body.error).toContain('is reserved')
      expect(res.headers.getSetCookie()).toEqual([])
    }
  })

  it('does not sign in on GET', async () => {
    const res = await browser().fetch(`/api/login?password=${encodeURIComponent(PASSWORD)}`)
    expect(res.status).toBe(405)
    expect(res.headers.getSetCookie()).toEqual([])
  })
})

describe('password guessing', () => {
  it('is throttled per client, logged and counted', async () => {
    const b = browser()
    for (let i = 0; i < 5; i++) {
      expect((await b.signIn('wrong', 'x', '10.0.0.7')).status).toBe(401)
    }
    const blocked = await b.signIn(PASSWORD, 'x', '10.0.0.7')
    expect(blocked.status).toBe(429)
    expect(Number(blocked.headers.get('retry-after'))).toBeGreaterThan(0)
    expect(blocked.headers.getSetCookie()).toEqual([])

    const lines = logs.warn.mock.calls.map((c: unknown[]) => JSON.parse(String(c[0])))
    expect(
      lines.filter((l: { msg: string }) => l.msg === 'sign-in failed: wrong password'),
    ).toHaveLength(5)
    expect(lines.at(-1)).toMatchObject({ client: '10.0.0.7', scope: 'client' })

    const metrics = renderMetrics()
    expect(metrics).toContain('netsoldier_webui_login_failures_total{reason="bad_password"} 5')
    expect(metrics).toContain('netsoldier_webui_login_failures_total{reason="rate_limited"} 1')

    // Another device is not locked out by this one.
    expect((await b.signIn(PASSWORD, 'x', '10.0.0.8')).status).toBe(200)
  })

  it('holds a global limit when guesses come from many addresses', async () => {
    const b = browser()
    for (let host = 1; host <= 4; host++) {
      for (let i = 0; i < 5; i++) await b.signIn('wrong', 'x', `10.0.1.${host}`)
    }
    const res = await b.signIn(PASSWORD, 'x', '10.0.1.99')
    expect(res.status).toBe(429)
    expect((await res.json()).error).toMatch(
      /paused .*browsers that have signed in here before are not affected/,
    )
  })

  it('cannot be overrun by concurrent requests', async () => {
    const b = browser()
    const results = await Promise.all(
      Array.from({ length: 50 }, () => b.signIn('wrong', 'x', '10.0.2.1')),
    )
    const statuses = results.map((r) => r.status)
    expect(statuses.filter((s) => s === 401)).toHaveLength(5)
    expect(statuses.filter((s) => s === 429)).toHaveLength(45)
  })
})

describe('device cookie', () => {
  /** Twenty wrong guesses from four fresh browsers: the global window is full. */
  async function exhaustGlobalWindow() {
    for (let host = 1; host <= 4; host++) {
      for (let i = 0; i < 5; i++) await browser().signIn('wrong', 'x', `10.0.1.${host}`)
    }
    expect((await browser().signIn(PASSWORD, 'x', '10.0.1.99')).status).toBe(429)
  }

  /** A browser that signed in once (and then signed out) from `address`. */
  async function knownBrowser(address = '10.0.9.1') {
    const b = browser()
    expect((await b.signIn(PASSWORD, 'anna', address)).status).toBe(200)
    await b.fetch('/api/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': b.csrf() },
      clientAddress: address,
    })
    expect([...b.jar.keys()]).toEqual(['netsoldier_device'])
    return b
  }

  it('is set at sign-in: long-lived, HttpOnly, SameSite=Strict, only for /api/login', async () => {
    const res = await browser().signIn(PASSWORD)
    const { netsoldier_device: device } = cookiesOf(res)
    expect(device.attributes).toMatchObject({
      httponly: true,
      samesite: 'Strict',
      path: '/api/login',
      'max-age': String(180 * 24 * 3600),
    })
    expect(device.attributes.secure).toBeUndefined()
    expect(device.value).toMatch(/^v1\.[A-Za-z0-9_-]+\.\d+\.[A-Za-z0-9_-]+$/)

    configure({ ORIGIN: TLS })
    expect(cookiesOf(await browser(TLS).signIn(PASSWORD)).netsoldier_device.attributes.secure).toBe(
      true,
    )
  })

  it('keeps its device id when the browser signs in again', async () => {
    const b = await knownBrowser()
    const id = b.jar.get('netsoldier_device')!.split('.')[1]
    await b.signIn(PASSWORD)
    expect(b.jar.get('netsoldier_device')!.split('.')[1]).toBe(id)
  })

  // The denial of service this exists for: a trickle of wrong guesses from
  // the LAN must not keep the household from signing in to approve.
  it('lets a browser that signed in before through while the global window is exhausted', async () => {
    const known = await knownBrowser('10.0.1.1')
    await exhaustGlobalWindow()
    // 10.0.1.1 has also used up its own address window; the device is exempt from both.
    const res = await known.signIn(PASSWORD, 'anna', '10.0.1.1')
    expect(res.status).toBe(200)
    expect(known.jar.has('netsoldier_session')).toBe(true)
  })

  it('gives a forged, expired or malformed cookie no exemption, and never an error', async () => {
    await exhaustGlobalWindow()
    const genuine = issueDeviceToken(SECRET).token
    const [, id, exp] = genuine.split('.')
    const bad = [
      `v1.${id}.${exp}.${'A'.repeat(43)}`, // forged signature
      issueDeviceToken('a-different-session-secret-0123456789').token,
      issueDeviceToken(SECRET, undefined, Date.now() - 181 * 24 * 3600 * 1000).token, // expired
      genuine.replace(/^v1\./, 'v2.'), // unknown version
      `v1.${id}.99999999999.${genuine.split('.')[3]}`, // expiry edited
      'garbage',
      'a.b.c.d',
      '....',
      'v1.' + 'x'.repeat(300),
      'Łukasz.ü.∞.☃',
    ]
    for (const cookie of bad) {
      const b = browser()
      b.jar.set('netsoldier_device', cookie)
      const res = await b.signIn(PASSWORD, 'x', '10.0.1.50')
      expect(res.status, cookie).toBe(429)
    }
    // The genuine cookie is honoured in the same state.
    const b = browser()
    b.jar.set('netsoldier_device', genuine)
    expect((await b.signIn(PASSWORD, 'x', '10.0.1.50')).status).toBe(200)
  })

  it('is limited by its own window, then falls back to the address and global limits', async () => {
    const known = await knownBrowser('10.0.3.1')
    for (let i = 0; i < 5; i++) {
      expect((await known.signIn('wrong', 'anna', '10.0.3.1')).status).toBe(401)
    }
    // Charged to the device only: the address still has its full budget.
    expect((await browser().signIn(PASSWORD, 'x', '10.0.3.1')).status).toBe(200)

    await exhaustGlobalWindow()
    // The device's window is used up, so its cookie is not honoured now.
    const res = await known.signIn(PASSWORD, 'anna', '10.0.3.1')
    expect(res.status).toBe(429)
  })
})

describe('sign-out', () => {
  async function signedIn() {
    const b = browser()
    await b.signIn(PASSWORD)
    return b
  }

  it('is POST-only', async () => {
    const b = await signedIn()
    expect((await b.fetch('/api/logout')).status).toBe(405)
    expect((await b.fetch('/api/devices')).status).toBe(200)
  })

  it('needs the CSRF token and the UI origin', async () => {
    const b = await signedIn()
    expect((await b.fetch('/api/logout', { method: 'POST' })).status).toBe(403)
    expect(
      (
        await b.fetch('/api/logout', {
          method: 'POST',
          headers: { 'X-CSRF-Token': b.csrf() },
          originHeader: 'http://evil.example',
        })
      ).status,
    ).toBe(403)
    expect((await b.fetch('/api/devices')).status).toBe(200)
  })

  it('clears the cookies and revokes the session server-side', async () => {
    const b = await signedIn()
    const stolen = b.jar.get('netsoldier_session')!

    const res = await b.fetch('/api/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': b.csrf() },
    })
    expect(res.status).toBe(200)
    const cleared = cookiesOf(res)
    expect(cleared.netsoldier_session.attributes['max-age']).toBe('0')
    expect(cleared.netsoldier_csrf.attributes['max-age']).toBe('0')
    // Only the device cookie survives: it is not a session.
    expect([...b.jar.keys()]).toEqual(['netsoldier_device'])

    // A copy of the cookie taken before sign-out no longer works.
    b.jar.set('netsoldier_session', stolen)
    expect((await b.fetch('/api/devices')).status).toBe(401)
  })
})

describe('API proxy', () => {
  async function signedIn(actor = 'michal') {
    const b = browser()
    await b.signIn(PASSWORD, actor)
    return b
  }

  it('requires the UI origin and the session-bound CSRF token on mutations', async () => {
    reply = () => ({ status: 200, body: '{"id":"ACT-1","state":"active"}' })
    const b = await signedIn()
    const other = await signedIn()
    const approve = (headers: Record<string, string>, originHeader?: string | null) =>
      b.fetch('/api/killswitch/ACT-1/approve', {
        method: 'POST',
        headers,
        body: '{}',
        originHeader,
      })

    expect((await approve({})).status).toBe(403)
    expect((await approve({ 'X-CSRF-Token': other.csrf() })).status).toBe(403)
    expect((await approve({ 'X-CSRF-Token': b.csrf() }, 'http://evil.example')).status).toBe(403)
    expect((await approve({ 'X-CSRF-Token': b.csrf() }, null)).status).toBe(403)
    expect(seen).toHaveLength(0)

    const ok = await approve({ 'X-CSRF-Token': b.csrf() })
    expect(ok.status).toBe(200)
    expect(seen[0]).toMatchObject({ method: 'POST', url: '/actions/ACT-1/approve', body: '{}' })
  })

  it('builds upstream headers from scratch', async () => {
    const b = await signedIn('anna')
    await b.fetch('/api/killswitch/ACT-1/reject', {
      method: 'POST',
      headers: {
        'X-CSRF-Token': b.csrf(),
        Authorization: 'Bearer forged',
        'X-Netsoldier-Actor': 'admin',
      },
      body: '{"reason":"fp"}',
    })
    expect(seen[0].headers.authorization).toBe('Bearer killswitch-operator-token')
    expect(seen[0].headers['x-netsoldier-actor']).toBe('anna')
    expect(seen[0].headers.cookie).toBeUndefined()
    expect(seen[0].headers['x-csrf-token']).toBeUndefined()
  })

  it('turns a backend 401/403 into a 502 that names the key, not a session expiry', async () => {
    const b = await signedIn()
    for (const status of [401, 403]) {
      reply = () => ({ status, body: '{"error":"unauthorized"}' })
      const res = await b.fetch('/api/killswitch/pending')
      expect(res.status).toBe(502)
      expect(res.headers.get('x-netsoldier-upstream-error')).toBe('auth')
      expect((await res.json()).error).toContain('KILLSWITCH_API_KEY')
    }
    reply = () => ({ status: 401, body: '{}' })
    expect((await b.fetch('/api/devices')).status).toBe(502)
    const metrics = renderMetrics()
    expect(metrics).toContain(
      'netsoldier_webui_upstream_errors_total{service="killswitch",kind="auth"} 2',
    )
  })

  it('reports an unreachable backend as a 502, not as empty data', async () => {
    configure({ DETECTION_ENGINE_URL: 'http://127.0.0.1:1' })
    const b = await signedIn()
    const res = await b.fetch('/api/alerts')
    expect(res.status).toBe(502)
    expect(res.headers.get('x-netsoldier-upstream-error')).toBe('unreachable')
  })

  it('passes a controller 502 (revert_failed) through with its body', async () => {
    const action = '{"id":"ACT-9","state":"revert_failed","failure_reason":"adguard down"}'
    reply = () => ({ status: 502, body: action })
    const b = await signedIn()
    const res = await b.fetch('/api/killswitch/ACT-9/revert', {
      method: 'POST',
      headers: { 'X-CSRF-Token': b.csrf() },
      body: '{}',
    })
    expect(res.status).toBe(502)
    expect(res.headers.has('x-netsoldier-upstream-error')).toBe(false)
    expect(await res.text()).toBe(action)
  })

  it('accepts a MAC whose colons were percent-encoded', async () => {
    reply = () => ({ status: 200, body: '{"mac":"aa:bb:cc:dd:ee:ff"}' })
    const b = await signedIn()
    const res = await b.fetch('/api/devices/aa%3Abb%3Acc%3Add%3Aee%3Aff')
    expect(res.status).toBe(200)
    expect(seen[0].url).toBe('/devices/aa:bb:cc:dd:ee:ff')
  })

  it('serves backend responses as JSON with a script-free policy', async () => {
    reply = () => ({ status: 200, body: '<script>alert(1)</script>', type: 'text/html' })
    const b = await signedIn()
    const res = await b.fetch('/api/devices')
    expect(res.headers.get('content-type')).toMatch(/^application\/json/)
    expect(res.headers.get('content-security-policy')).toMatch(/default-src 'none'/)
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('cache-control')).toBe('no-store')
  })

  it('reaches the killswitch policy route, the v2 lists and the audit log', async () => {
    const b = await signedIn()
    for (const path of ['policy', 'failed', 'history?limit=20', 'audit?limit=50&before=7']) {
      expect((await b.fetch(`/api/killswitch/${path}`)).status, path).toBe(200)
    }
    expect(seen.map((s) => s.url)).toEqual([
      '/policy',
      '/actions/failed',
      '/actions/history?limit=20',
      '/audit?limit=50&before=7',
    ])
  })

  it('passes ?limit= on to the detection engine', async () => {
    const b = await signedIn()
    expect((await b.fetch('/api/alerts?limit=500')).status).toBe(200)
    expect(seen[0].url).toBe('/alerts?limit=500')
  })

  it('refuses a query parameter the route does not take, before any backend call', async () => {
    const b = await signedIn()
    const res = await b.fetch('/api/killswitch/pending?state=active')
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('"state"')
    expect(seen).toHaveLength(0)
  })

  it('stamps the actor on every mutation the killswitch requires it for', async () => {
    const b = await signedIn('Anna K.')
    for (const verb of ['approve', 'reject', 'revert']) {
      await b.fetch(`/api/killswitch/ACT-1/${verb}`, {
        method: 'POST',
        headers: { 'X-CSRF-Token': b.csrf() },
        body: verb === 'approve' ? '{"action_type":"arp_isolate"}' : '{"reason":"x"}',
      })
    }
    expect(seen.map((s) => [s.url, s.headers['x-netsoldier-actor']])).toEqual([
      ['/actions/ACT-1/approve', 'Anna K.'],
      ['/actions/ACT-1/reject', 'Anna K.'],
      ['/actions/ACT-1/revert', 'Anna K.'],
    ])
    expect(seen[0].body).toBe('{"action_type":"arp_isolate"}')
  })

  it('lifts a suppression through POST /feedback/lift, as the actor and only with CSRF', async () => {
    reply = () => ({ status: 200, body: '{"status":"lifted","persisted":true}' })
    const b = await signedIn('anna')
    const body = '{"matched_ioc":"evil.example","client_ip":"192.168.1.77","signal_class":"ioc"}'
    const lift = (headers: Record<string, string>) =>
      b.fetch('/api/feedback/lift', { method: 'POST', headers, body })

    expect((await lift({})).status).toBe(403)
    expect(seen).toHaveLength(0)

    const res = await lift({ 'X-CSRF-Token': b.csrf(), 'X-Netsoldier-Actor': 'admin' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ status: 'lifted', persisted: true })
    expect(seen[0]).toMatchObject({ method: 'POST', url: '/feedback/lift', body })
    expect(seen[0].headers['x-netsoldier-actor']).toBe('anna')
    expect(seen[0].headers.authorization).toBe('Bearer detection-key')

    // "No such suppression" is the engine's answer, passed on as such.
    reply = () => ({ status: 404, body: '{"error":"no such suppression is in force"}' })
    const gone = await lift({ 'X-CSRF-Token': b.csrf() })
    expect(gone.status).toBe(404)
    expect(gone.headers.has('x-netsoldier-upstream-error')).toBe(false)
  })

  it('passes the inventory’s X-Total-Count on, and no other backend header', async () => {
    reply = () => ({
      status: 200,
      body: '[]',
      headers: { 'X-Total-Count': '812', 'Set-Cookie': 'evil=1', 'X-Backend': 'leak' },
    })
    const b = await signedIn()
    const res = await b.fetch('/api/devices?limit=1000')
    expect(res.headers.get('x-total-count')).toBe('812')
    expect(res.headers.get('set-cookie')).toBeNull()
    expect(res.headers.get('x-backend')).toBeNull()

    reply = () => ({ status: 200, body: '[]', headers: { 'X-Total-Count': '<script>' } })
    expect((await b.fetch('/api/devices')).headers.get('x-total-count')).toBeNull()
  })

  it('passes the controller’s 202, 409 and 422 through with their bodies', async () => {
    const b = await signedIn()
    for (const [status, body] of [
      [202, '{"id":"ACT-1","state":"approved"}'],
      [409, '{"id":"ACT-1","state":"rejected","error":"action ACT-1 is rejected, not pending"}'],
      [422, '{"error":"not available","available_action_types":["dns_sinkhole"]}'],
    ] as const) {
      reply = () => ({ status, body })
      const res = await b.fetch('/api/killswitch/ACT-1/approve', {
        method: 'POST',
        headers: { 'X-CSRF-Token': b.csrf() },
        body: '{}',
      })
      expect(res.status).toBe(status)
      expect(res.headers.has('x-netsoldier-upstream-error')).toBe(false)
      expect(await res.text()).toBe(body)
    }
  })

  it('never puts a non-ASCII actor into a header, even from a validly signed token', async () => {
    // A token in the pre-validation format with a Latin-2 name, signed with
    // the real secret: it must be refused, not crash every API call.
    const payload = JSON.stringify({
      v: 1,
      sid: 'abc',
      exp: Math.floor(Date.now() / 1000) + 600,
      actor: 'Łukasz',
    })
    const token = `${Buffer.from(payload).toString('base64url')}.${createHmac('sha256', SECRET).update(payload).digest('base64url')}`
    const b = browser()
    b.jar.set('netsoldier_session', token)
    const res = await b.fetch('/api/devices')
    expect(res.status).toBe(401)
    expect(seen).toHaveLength(0)
  })

  it('refuses a session issued under a reserved name before the rule existed', async () => {
    const payload = JSON.stringify({
      v: 1,
      sid: 'def',
      exp: Math.floor(Date.now() / 1000) + 600,
      actor: 'ttl',
    })
    const token = `${Buffer.from(payload).toString('base64url')}.${createHmac('sha256', SECRET).update(payload).digest('base64url')}`
    const b = browser()
    b.jar.set('netsoldier_session', token)
    expect((await b.fetch('/api/killswitch/pending')).status).toBe(401)
    expect(seen).toHaveLength(0)
  })
})
