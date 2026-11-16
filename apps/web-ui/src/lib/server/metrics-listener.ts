import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { log } from './log'
import { METRICS_CONTENT_TYPE, renderMetrics } from './metrics'

/**
 * GET /metrics on a listener of its own, in the same process.
 *
 * The UI's port is published on the household LAN, and /metrics used to be
 * served there too, without a session. It now answers 404 there, and the
 * counters are served here instead: a port the deployment never publishes,
 * so who reaches it is decided by the NetworkPolicy (Kubernetes) or the
 * container network (Podman), not by a session. This listener serves
 * nothing but GET/HEAD /metrics — no page, no API, no probe, no asset.
 *
 *   METRICS_ADDR  host:port, :port (every interface) or [v6]:port;
 *                 `off` serves no metrics. Default :9464.
 *
 * A value that cannot be used — malformed, or a port that cannot be bound —
 * stops the web UI from starting, with the reason: a deployment that scrapes
 * the port would otherwise only see a target that is down, with nothing in
 * the UI's log saying why.
 */

export const METRICS_ADDR_VAR = 'METRICS_ADDR'
export const DEFAULT_METRICS_ADDR = ':9464'

export interface ListenAddr {
  /** Undefined: every interface. */
  host: string | undefined
  port: number
  /** As configured, for messages. */
  text: string
}

export type MetricsAddrResult = { ok: true; addr: ListenAddr | null } | { ok: false; error: string }

/** `null` address: metrics are off. */
export function parseMetricsAddr(raw: string | undefined): MetricsAddrResult {
  const value = (raw ?? '').trim()
  if (value === '') return parseMetricsAddr(DEFAULT_METRICS_ADDR)
  if (value.toLowerCase() === 'off') return { ok: true, addr: null }
  const m = value.match(/^(?:\[([0-9A-Fa-f:.]+)\]|([A-Za-z0-9.-]*)):(\d{1,5})$/)
  const port = m ? Number(m[3]) : NaN
  if (!m || port < 1 || port > 65535) {
    return {
      ok: false,
      error:
        `${METRICS_ADDR_VAR}="${value}" is not an address to listen on: use host:port, :port ` +
        `(every interface) or [IPv6]:port with a port from 1 to 65535, or off to serve no metrics`,
    }
  }
  return { ok: true, addr: { host: m[1] ?? (m[2] || undefined), port, text: value } }
}

const BASE_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
}

function plain(res: http.ServerResponse, status: number, text: string, extra = {}) {
  res.writeHead(status, {
    ...BASE_HEADERS,
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(text),
    ...extra,
  })
  res.end(text)
}

/** The whole of what this listener answers. */
export function serveMetrics(req: http.IncomingMessage, res: http.ServerResponse): void {
  const path = (req.url ?? '').split('?')[0]
  if (path !== '/metrics') return plain(res, 404, 'not found\n')
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return plain(res, 405, 'method not allowed\n', { Allow: 'GET, HEAD' })
  }
  const body = renderMetrics()
  res.writeHead(200, {
    ...BASE_HEADERS,
    'Content-Type': METRICS_CONTENT_TYPE,
    'Content-Length': Buffer.byteLength(body),
  })
  res.end(req.method === 'HEAD' ? undefined : body)
}

function bindProblem(addr: ListenAddr, err: NodeJS.ErrnoException): string {
  switch (err.code) {
    case 'EADDRINUSE':
      return `port ${addr.port} is already in use`
    case 'EACCES':
      return `not allowed to listen on port ${addr.port}`
    case 'EADDRNOTAVAIL':
      return `${addr.host} is not an address of this host`
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return `${addr.host} does not resolve`
    default:
      return err.message
  }
}

/** Starts the listener; rejects, with a message naming METRICS_ADDR, if it cannot. */
export function listenForMetrics(addr: ListenAddr): Promise<http.Server> {
  const server = http.createServer(serveMetrics)
  // Requests are tiny and come from a scraper: do not let a slow client
  // hold a socket open.
  server.headersTimeout = 10_000
  server.requestTimeout = 10_000
  return new Promise((ok, fail) => {
    server.once('error', (err: NodeJS.ErrnoException) => {
      fail(
        new Error(
          `the metrics listener cannot listen on ${METRICS_ADDR_VAR}=${addr.text}: ` +
            `${bindProblem(addr, err)}${err.code ? ` (${err.code})` : ''}. Set ` +
            `${METRICS_ADDR_VAR} to a free host:port, or to off to serve no metrics.`,
        ),
      )
    })
    server.listen({ host: addr.host, port: addr.port }, () => {
      server.removeAllListeners('error')
      server.on('error', (err) => log('ERROR', 'metrics listener failed', { error: err.message }))
      ok(server)
    })
  })
}

// One per process. `vite dev` may run the init hook again after a reload;
// the previous listener is closed first instead of failing on its port.
const HANDLE = Symbol.for('netsoldier.web-ui.metrics-listener')
type Holder = { [HANDLE]?: { server: http.Server; onShutdown: () => void } }

function close(server: http.Server): Promise<void> {
  server.closeAllConnections()
  return new Promise((ok) => server.close(() => ok()))
}

/** Closes the listener this process started, if any. */
export async function stopMetricsListener(): Promise<void> {
  const holder = globalThis as Holder
  const running = holder[HANDLE]
  if (!running) return
  delete holder[HANDLE]
  process.removeListener('sveltekit:shutdown', running.onShutdown)
  await close(running.server)
}

/**
 * Reads METRICS_ADDR and starts the listener, or logs that metrics are off.
 * Throws when the value is unusable or the port cannot be bound: the caller
 * (the server's init hook) lets that stop the start-up.
 */
export async function startMetricsListener(raw: string | undefined): Promise<http.Server | null> {
  await stopMetricsListener()

  const parsed = parseMetricsAddr(raw)
  if (!parsed.ok) {
    log('ERROR', 'web-ui cannot start: invalid METRICS_ADDR', { error: parsed.error })
    throw new Error(`web-ui cannot start: ${parsed.error}`)
  }
  if (!parsed.addr) {
    log('INFO', 'metrics listener is off (METRICS_ADDR=off): /metrics is not served')
    return null
  }

  let server: http.Server
  try {
    server = await listenForMetrics(parsed.addr)
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e)
    log('ERROR', 'web-ui cannot start: metrics listener', { error })
    throw new Error(`web-ui cannot start: ${error}`)
  }
  // Never what keeps the process alive: when adapter-node has closed the
  // UI's own server on SIGTERM/SIGINT, this one goes too, open scrape
  // connections included.
  server.unref()
  const onShutdown = () => void stopMetricsListener()
  process.once('sveltekit:shutdown', onShutdown)
  ;(globalThis as Holder)[HANDLE] = { server, onShutdown }

  const { address, port } = server.address() as AddressInfo
  log('INFO', 'metrics listener started', {
    metrics_addr: parsed.addr.text,
    address,
    port,
    path: '/metrics',
  })
  return server
}
