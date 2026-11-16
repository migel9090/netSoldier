import { spawn, type ChildProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFileSync, readdirSync, readlinkSync } from 'node:fs'
import http from 'node:http'
import net, { type AddressInfo } from 'node:net'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test, expect, signIn } from './fixtures'

/**
 * The UI's port is published on the household LAN; /metrics is served on a
 * listener of its own (METRICS_ADDR) and nowhere else. Against the built
 * app: the "lan-http" instance from global-setup.ts has a metrics listener,
 * and the start-up cases run instances of their own.
 */

const appDir = resolve(fileURLToPath(new URL('.', import.meta.url)), '../..')
const direct = () => process.env.E2E_HTTP_DIRECT ?? ''
const metrics = () => process.env.E2E_HTTP_METRICS ?? ''

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const s = net.createServer()
    s.once('error', fail)
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as AddressInfo
      s.close(() => ok(port))
    })
  })
}

/** "<name> <value>" of one series in an exposition. */
function series(text: string, name: string): number {
  const line = text.split('\n').find((l) => l.startsWith(`${name} `))
  if (!line) throw new Error(`no series ${name}`)
  return Number(line.slice(name.length + 1))
}

test('the UI’s own port answers /metrics with 404, signed in or not', async ({ page }) => {
  for (const method of ['GET', 'HEAD']) {
    const res = await fetch(`${direct()}/metrics`, { method, redirect: 'manual' })
    expect(res.status, method).toBe(404)
    if (method === 'GET') expect(await res.text()).not.toContain('netsoldier_webui')
  }
  // From the household's browser, with a session.
  await signIn(page)
  const seen = await page.evaluate(async () => {
    const r = await fetch('/metrics', { redirect: 'manual' })
    return { status: r.status, body: await r.text() }
  })
  expect(seen.status).toBe(404)
  expect(seen.body).not.toContain('netsoldier_webui')
})

test('the metrics listener serves the counters, without a session, and nothing else', async ({
  page,
}) => {
  const read = async () => {
    const res = await fetch(`${metrics()}/metrics`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('text/plain; version=0.0.4; charset=utf-8')
    return res.text()
  }
  const before = await read()
  for (const name of [
    'netsoldier_webui_logins_total',
    'netsoldier_webui_login_failures_total{reason="bad_password"}',
    'netsoldier_webui_login_failures_total{reason="invalid_request"}',
    'netsoldier_webui_upstream_errors_total{service="killswitch",kind="auth"}',
    'netsoldier_webui_upstream_errors_total{service="detection-engine",kind="unreachable"}',
  ]) {
    expect(Number.isFinite(series(before, name)), name).toBe(true)
  }

  // What happens on the UI's port is counted here.
  await signIn(page)
  const malformed = await fetch(`${direct()}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: process.env.E2E_HTTP_URL ?? '' },
    body: 'not json',
  })
  expect(malformed.status).toBe(400)
  const after = await read()
  expect(series(after, 'netsoldier_webui_logins_total')).toBe(
    series(before, 'netsoldier_webui_logins_total') + 1,
  )
  const invalid = 'netsoldier_webui_login_failures_total{reason="invalid_request"}'
  expect(series(after, invalid)).toBe(series(before, invalid) + 1)

  // No page, API, probe or asset of the app.
  for (const path of ['/', '/login', '/healthz', '/api/devices', '/api/login', '/favicon.png']) {
    const res = await fetch(`${metrics()}${path}`, { redirect: 'manual' })
    expect(res.status, path).toBe(404)
    expect(await res.text(), path).toBe('not found\n')
  }
  const post = await fetch(`${metrics()}/metrics`, { method: 'POST' })
  expect(post.status).toBe(405)
})

// ── Start-up, on instances of their own ─────────────────────────────────

interface App {
  child: ChildProcess
  port: number
  output: () => string
  exited: Promise<number | null>
}

function startApp(env: Record<string, string>, port: number): App {
  let output = ''
  const child = spawn(process.execPath, ['build'], {
    cwd: appDir,
    env: {
      PATH: process.env.PATH ?? '',
      NODE_ENV: 'production',
      HOST: '127.0.0.1',
      PORT: String(port),
      ORIGIN: `http://127.0.0.1:${port}`,
      SESSION_SECRET: randomBytes(48).toString('base64'),
      WEB_UI_PASSWORD: 'metrics spec password',
      KILLSWITCH_URL: 'http://127.0.0.1:1',
      KILLSWITCH_API_KEY: 'k',
      DEVICE_INVENTORY_URL: 'http://127.0.0.1:1',
      DEVICE_API_KEY: 'd',
      DETECTION_ENGINE_URL: 'http://127.0.0.1:1',
      DETECTION_API_KEY: 'e',
      SHUTDOWN_TIMEOUT: '2',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', (c) => (output += c))
  child.stderr?.on('data', (c) => (output += c))
  const exited = new Promise<number | null>((ok) => child.once('exit', (code) => ok(code)))
  return { child, port, output: () => output, exited }
}

async function healthy(app: App): Promise<void> {
  await expect
    .poll(
      async () => {
        if (app.child.exitCode !== null) throw new Error(`exited:\n${app.output()}`)
        return fetch(`http://127.0.0.1:${app.port}/healthz`).then(
          (r) => r.status,
          () => 0,
        )
      },
      { timeout: 15_000 },
    )
    .toBe(200)
}

async function stop(app: App): Promise<void> {
  if (app.child.exitCode === null && app.child.signalCode === null) app.child.kill('SIGKILL')
  await app.exited
}

/** The TCP ports a process listens on (Linux: its socket fds against /proc/net/tcp*). */
function listeningPorts(pid: number): number[] | null {
  if (process.platform !== 'linux') return null
  const inodes = new Set<string>()
  for (const fd of readdirSync(`/proc/${pid}/fd`)) {
    try {
      const m = readlinkSync(`/proc/${pid}/fd/${fd}`).match(/^socket:\[(\d+)\]$/)
      if (m) inodes.add(m[1])
    } catch {
      // closed meanwhile
    }
  }
  const ports: number[] = []
  for (const table of ['tcp', 'tcp6']) {
    for (const line of readFileSync(`/proc/${pid}/net/${table}`, 'utf8').split('\n').slice(1)) {
      const f = line.trim().split(/\s+/)
      // local_address, state 0A (LISTEN), inode
      if (f.length > 9 && f[3] === '0A' && inodes.has(f[9])) {
        ports.push(parseInt(f[1].split(':')[1], 16))
      }
    }
  }
  return ports.sort((a, b) => a - b)
}

test('a metrics port that is taken stops the start-up, saying so', async () => {
  const taken = net.createServer()
  await new Promise<void>((ok) => taken.listen(0, '127.0.0.1', ok))
  const busy = (taken.address() as AddressInfo).port
  const port = await freePort()
  const app = startApp({ METRICS_ADDR: `127.0.0.1:${busy}` }, port)
  try {
    expect(await app.exited).not.toBe(0)
    expect(app.output()).toContain(
      `web-ui cannot start: the metrics listener cannot listen on METRICS_ADDR=127.0.0.1:${busy}: ` +
        `port ${busy} is already in use (EADDRINUSE)`,
    )
    // It never got as far as opening the UI's port.
    expect(app.output()).not.toContain('Listening on')
    await expect(fetch(`http://127.0.0.1:${port}/healthz`)).rejects.toThrow()
  } finally {
    await stop(app)
    await new Promise((ok) => taken.close(ok))
  }
})

test('a malformed METRICS_ADDR stops the start-up, saying what it takes', async () => {
  const app = startApp({ METRICS_ADDR: '9464' }, await freePort())
  try {
    expect(await app.exited).not.toBe(0)
    expect(app.output()).toContain('web-ui cannot start: METRICS_ADDR="9464" is not an address')
  } finally {
    await stop(app)
  }
})

test('METRICS_ADDR=off: the process listens on the UI’s port only', async () => {
  const port = await freePort()
  const app = startApp({ METRICS_ADDR: 'off' }, port)
  try {
    await healthy(app)
    expect(app.output()).toContain('metrics listener is off (METRICS_ADDR=off)')
    const ports = listeningPorts(app.child.pid!)
    if (ports) expect(ports).toEqual([port])
  } finally {
    await stop(app)
  }
})

test('the metrics listener does not hold up a SIGTERM, even with a scrape connection open', async () => {
  const port = await freePort()
  const metricsPort = await freePort()
  const app = startApp({ METRICS_ADDR: `127.0.0.1:${metricsPort}` }, port)
  try {
    await healthy(app)
    const ports = listeningPorts(app.child.pid!)
    if (ports) expect(ports).toEqual([port, metricsPort].sort((a, b) => a - b))

    const agent = new http.Agent({ keepAlive: true })
    await new Promise<void>((ok, fail) =>
      http
        .get({ host: '127.0.0.1', port: metricsPort, path: '/metrics', agent }, (res) => {
          res.resume()
          res.on('end', ok)
        })
        .on('error', fail),
    )
    const started = Date.now()
    app.child.kill('SIGTERM')
    expect(await app.exited).toBe(0)
    // Well inside SHUTDOWN_TIMEOUT (2 s): nothing waited for the scrape connection.
    expect(Date.now() - started).toBeLessThan(1500)
    agent.destroy()
  } finally {
    await stop(app)
  }
})
