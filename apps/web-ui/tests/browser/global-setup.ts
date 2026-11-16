import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  createWriteStream,
} from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import net, { type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { startRealStack, type RealStack, type Upstreams } from './real/stack'
import { KEYS, startStubs } from './stub/backends'

/**
 * Starts everything the browser tests talk to, on 127.0.0.1 ephemeral ports:
 *
 * - the stub backends (tests/browser/stub/backends.ts);
 * - the real backends (tests/browser/real/stack.ts): the three Go services
 *   built from this tree, unless E2E_REAL_BACKENDS=skip;
 * - the production build (`node build`) up to four times:
 *   - "lan-http": ORIGIN=http://netsoldier.lan:<port>, as on a plain-HTTP LAN;
 *   - "tls": behind a TLS-terminating proxy, ORIGIN=https://netsoldier.lan:<port>,
 *     with ADDRESS_HEADER/XFF_DEPTH as a reverse-proxy deployment sets them;
 *   - "lockout": plain HTTP with ADDRESS_HEADER, used only by lockout.spec.ts;
 *   - "real": plain HTTP in front of the real backends, for real-backends.spec.ts.
 *
 * Only "lan-http" has a metrics listener (METRICS_ADDR, on a port of its
 * own); the others run with METRICS_ADDR=off.
 *
 * The browser resolves netsoldier.lan to 127.0.0.1 (see playwright.config.ts).
 * A real host name matters: Chromium treats http://127.0.0.1 as a secure
 * context and would accept `Secure` cookies there, hiding the very bug a
 * plain-HTTP LAN deployment hits.
 *
 * Everything is shut down by the returned teardown.
 */

export const LAN_HOST = 'netsoldier.lan'
export const E2E_PASSWORD = 'e2e household password'

const appDir = resolve(fileURLToPath(new URL('.', import.meta.url)), '../..')
const logDir = join(appDir, 'test-results', 'servers')

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

async function waitHealthy(url: string, child: ChildProcess, name: string): Promise<void> {
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`${name}: node build exited with ${child.exitCode}; see ${logDir}`)
    }
    try {
      const res = await fetch(url)
      if (res.ok) return
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error(`${name}: ${url} did not become healthy in 20 s; see ${logDir}`)
}

function stubUpstreams(stubs: Awaited<ReturnType<typeof startStubs>>): Upstreams {
  return {
    killswitch: { url: stubs.urls.killswitch, key: KEYS.killswitch },
    'device-inventory': { url: stubs.urls['device-inventory'], key: KEYS['device-inventory'] },
    'detection-engine': { url: stubs.urls['detection-engine'], key: KEYS['detection-engine'] },
  }
}

function startApp(
  name: string,
  port: number,
  origin: string,
  upstreams: Upstreams,
  extraEnv: Record<string, string> = {},
): ChildProcess {
  const log = createWriteStream(join(logDir, `${name}.log`))
  const child = spawn(process.execPath, ['build'], {
    cwd: appDir,
    // Built from scratch so nothing from the developer's shell leaks in.
    env: {
      PATH: process.env.PATH ?? '',
      NODE_ENV: 'production',
      HOST: '127.0.0.1',
      PORT: String(port),
      ORIGIN: origin,
      SESSION_SECRET: randomBytes(48).toString('base64'),
      WEB_UI_PASSWORD: E2E_PASSWORD,
      KILLSWITCH_URL: upstreams.killswitch.url,
      KILLSWITCH_API_KEY: upstreams.killswitch.key,
      DEVICE_INVENTORY_URL: upstreams['device-inventory'].url,
      DEVICE_API_KEY: upstreams['device-inventory'].key,
      DETECTION_ENGINE_URL: upstreams['detection-engine'].url,
      DETECTION_API_KEY: upstreams['detection-engine'].key,
      SHUTDOWN_TIMEOUT: '2',
      // Several instances run at once: none takes the default :9464. The
      // lan-http one gets a port of its own (metrics.spec.ts).
      METRICS_ADDR: 'off',
      ...extraEnv,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.pipe(log)
  child.stderr?.pipe(log)
  return child
}

/** A throwaway self-signed certificate for the TLS proxy, or null without openssl. */
function makeCertificate(dir: string): { key: Buffer; cert: Buffer } | null {
  try {
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:prime256v1',
        '-nodes',
        '-days',
        '1',
        '-subj',
        `/CN=${LAN_HOST}`,
        '-addext',
        `subjectAltName=DNS:${LAN_HOST}`,
        '-keyout',
        join(dir, 'key.pem'),
        '-out',
        join(dir, 'cert.pem'),
      ],
      { stdio: 'ignore' },
    )
    return { key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }
  } catch {
    return null
  }
}

/** Terminates TLS and forwards to the app, the way an Ingress or Caddy would. */
function tlsProxy(credentials: { key: Buffer; cert: Buffer }, appPort: number): https.Server {
  return https.createServer(credentials, (req, res) => {
    const upstream = http.request(
      {
        host: '127.0.0.1',
        port: appPort,
        method: req.method,
        path: req.url,
        headers: {
          ...req.headers,
          'x-forwarded-proto': 'https',
          'x-forwarded-for': req.socket.remoteAddress ?? '',
        },
      },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers)
        up.pipe(res)
      },
    )
    upstream.on('error', () => {
      res.writeHead(502)
      res.end()
    })
    req.pipe(upstream)
  })
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  const exited = new Promise<void>((ok) => child.once('exit', () => ok()))
  child.kill('SIGTERM')
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000)
  await exited
  clearTimeout(timer)
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  if (!existsSync(join(appDir, 'build', 'index.js'))) {
    throw new Error('No production build: run `npm run build` first (`npm run test:e2e` does).')
  }
  mkdirSync(logDir, { recursive: true })

  const children: ChildProcess[] = []
  let real: RealStack | null = null
  const killAll = () => {
    children.forEach((c) => c.kill('SIGKILL'))
    real?.kill()
  }
  process.once('exit', killAll)

  const stubs = await startStubs()
  const upstreams = stubUpstreams(stubs)
  const certDir = mkdtempSync(join(tmpdir(), 'netsoldier-e2e-'))
  let proxy: https.Server | null = null

  let realStarting: Promise<RealStack> | null = null

  const teardown = async () => {
    await Promise.all(children.map(stop))
    await realStarting?.catch(() => {})
    await real?.close()
    if (proxy) {
      proxy.closeAllConnections()
      await new Promise((ok) => proxy!.close(ok))
    }
    await stubs.close()
    rmSync(certDir, { recursive: true, force: true })
    process.removeListener('exit', killAll)
  }

  try {
    // Building the Go services takes longest on a cold cache: start it first.
    if (process.env.E2E_REAL_BACKENDS !== 'skip') {
      realStarting = startRealStack(resolve(appDir, '../..'), logDir).then((s) => (real = s))
      // Awaited below; this only keeps an early failure from counting as unhandled.
      realStarting.catch(() => {})
    }

    const httpPort = await freePort()
    const metricsPort = await freePort()
    const httpApp = startApp('lan-http', httpPort, `http://${LAN_HOST}:${httpPort}`, upstreams, {
      METRICS_ADDR: `127.0.0.1:${metricsPort}`,
    })
    children.push(httpApp)
    await waitHealthy(`http://127.0.0.1:${httpPort}/healthz`, httpApp, 'lan-http')
    process.env.E2E_HTTP_URL = `http://${LAN_HOST}:${httpPort}`
    process.env.E2E_HTTP_DIRECT = `http://127.0.0.1:${httpPort}`
    process.env.E2E_HTTP_METRICS = `http://127.0.0.1:${metricsPort}`

    // For lockout.spec.ts alone: its sign-in windows get exhausted on
    // purpose, and it trusts X-Forwarded-For so the test can guess from
    // many addresses.
    const lockoutPort = await freePort()
    const lockoutApp = startApp(
      'lockout',
      lockoutPort,
      `http://${LAN_HOST}:${lockoutPort}`,
      upstreams,
      {
        ADDRESS_HEADER: 'X-Forwarded-For',
        XFF_DEPTH: '1',
      },
    )
    children.push(lockoutApp)
    await waitHealthy(`http://127.0.0.1:${lockoutPort}/healthz`, lockoutApp, 'lockout')
    process.env.E2E_LOCKOUT_URL = `http://${LAN_HOST}:${lockoutPort}`
    process.env.E2E_LOCKOUT_DIRECT = `http://127.0.0.1:${lockoutPort}`

    const credentials = makeCertificate(certDir)
    if (credentials) {
      const appPort = await freePort()
      proxy = tlsProxy(credentials, appPort)
      await new Promise<void>((ok) => proxy!.listen(0, '127.0.0.1', ok))
      const tlsPort = (proxy.address() as AddressInfo).port
      const tlsApp = startApp('tls', appPort, `https://${LAN_HOST}:${tlsPort}`, upstreams, {
        ADDRESS_HEADER: 'X-Forwarded-For',
        XFF_DEPTH: '1',
      })
      children.push(tlsApp)
      await waitHealthy(`http://127.0.0.1:${appPort}/healthz`, tlsApp, 'tls')
      process.env.E2E_TLS_URL = `https://${LAN_HOST}:${tlsPort}`
    } else {
      console.warn('openssl not found: the TLS project will be skipped')
    }

    if (realStarting) {
      const stack = await realStarting
      const realPort = await freePort()
      const realApp = startApp('real', realPort, `http://${LAN_HOST}:${realPort}`, stack.upstreams)
      children.push(realApp)
      await waitHealthy(`http://127.0.0.1:${realPort}/healthz`, realApp, 'real')
      process.env.E2E_REAL_URL = `http://${LAN_HOST}:${realPort}`
      process.env.E2E_REAL_CONTROL = stack.control
    } else {
      console.warn('E2E_REAL_BACKENDS=skip: the real-backend browser test will be skipped')
    }

    process.env.E2E_STUB_CONTROL = stubs.control
    process.env.E2E_PASSWORD = E2E_PASSWORD
  } catch (e) {
    await teardown()
    throw e
  }

  return teardown
}
