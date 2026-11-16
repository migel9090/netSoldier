import http from 'node:http'
import net, { type AddressInfo } from 'node:net'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { countLoginFailure, resetMetrics } from './metrics'
import {
  DEFAULT_METRICS_ADDR,
  parseMetricsAddr,
  startMetricsListener,
  stopMetricsListener,
} from './metrics-listener'

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

/** A raw request, so nothing (fetch's URL normalisation) hides what was asked. */
function request(
  port: number,
  method: string,
  path: string,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((ok, fail) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, agent: false }, (res) => {
      let body = ''
      res.on('data', (c) => (body += c))
      res.on('end', () => ok({ status: res.statusCode ?? 0, headers: res.headers, body }))
    })
    req.on('error', fail)
    req.end()
  })
}

let logs: string[]

beforeEach(() => {
  resetMetrics()
  logs = []
  for (const level of ['log', 'warn', 'error'] as const) {
    vi.spyOn(console, level).mockImplementation((line: unknown) => void logs.push(String(line)))
  }
})

afterEach(async () => {
  await stopMetricsListener()
  vi.restoreAllMocks()
})

describe('METRICS_ADDR', () => {
  it('defaults to :9464, on every interface', () => {
    expect(DEFAULT_METRICS_ADDR).toBe(':9464')
    for (const raw of [undefined, '', '  ']) {
      expect(parseMetricsAddr(raw)).toEqual({
        ok: true,
        addr: { host: undefined, port: 9464, text: ':9464' },
      })
    }
  })

  it('takes host:port, :port, [v6]:port and off', () => {
    expect(parseMetricsAddr('127.0.0.1:9100')).toMatchObject({
      ok: true,
      addr: { host: '127.0.0.1', port: 9100 },
    })
    expect(parseMetricsAddr('[::1]:9100')).toMatchObject({ ok: true, addr: { host: '::1' } })
    expect(parseMetricsAddr('metrics.local:9100')).toMatchObject({
      ok: true,
      addr: { host: 'metrics.local' },
    })
    expect(parseMetricsAddr(':1')).toMatchObject({ ok: true, addr: { port: 1 } })
    expect(parseMetricsAddr('off')).toEqual({ ok: true, addr: null })
    expect(parseMetricsAddr(' OFF ')).toEqual({ ok: true, addr: null })
  })

  it('refuses anything else, saying what it takes', () => {
    for (const bad of [
      '9464',
      'localhost',
      ':0',
      ':65536',
      ':-1',
      '::1:9100',
      'http://0.0.0.0:9464',
      '0.0.0.0:9464/metrics',
      'a b:9464',
      'false',
    ]) {
      const r = parseMetricsAddr(bad)
      expect(r.ok, bad).toBe(false)
      if (!r.ok) expect(r.error).toContain('METRICS_ADDR=')
    }
  })
})

describe('the metrics listener', () => {
  async function started(): Promise<number> {
    const port = await freePort()
    const server = await startMetricsListener(`127.0.0.1:${port}`)
    expect(server).not.toBeNull()
    return port
  }

  it('serves the counters on GET /metrics, without a session', async () => {
    const port = await started()
    countLoginFailure('bad_password')
    const res = await request(port, 'GET', '/metrics')
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toBe('text/plain; version=0.0.4; charset=utf-8')
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.headers['x-content-type-options']).toBe('nosniff')
    expect(res.body).toContain('netsoldier_webui_login_failures_total{reason="bad_password"} 1')
    expect(res.body).toContain('netsoldier_webui_logins_total 0')
    expect(res.body).toContain(
      'netsoldier_webui_upstream_errors_total{service="killswitch",kind="auth"} 0',
    )

    const head = await request(port, 'HEAD', '/metrics')
    expect(head.status).toBe(200)
    expect(head.body).toBe('')
    expect((await request(port, 'GET', '/metrics?ignored=1')).status).toBe(200)
  })

  it('serves nothing else of the app', async () => {
    const port = await started()
    for (const path of [
      '/',
      '/healthz',
      '/login',
      '/alerts',
      '/api/login',
      '/api/devices',
      '/api/killswitch/pending',
      '/_app/version.json',
      '/metrics/',
      '/metrics/../healthz',
      '//metrics',
      '/METRICS',
    ]) {
      const res = await request(port, 'GET', path)
      expect(res.status, path).toBe(404)
      expect(res.body, path).toBe('not found\n')
    }
    for (const method of ['POST', 'PUT', 'DELETE']) {
      const res = await request(port, method, '/metrics')
      expect(res.status, method).toBe(405)
      expect(res.headers.allow).toBe('GET, HEAD')
    }
  })

  it('logs where it listens', async () => {
    const port = await started()
    const line = logs.map((l) => JSON.parse(l)).find((l) => l.msg === 'metrics listener started')
    expect(line).toMatchObject({ level: 'INFO', port, address: '127.0.0.1', path: '/metrics' })
  })

  it('with off, listens nowhere and says so', async () => {
    expect(await startMetricsListener('off')).toBeNull()
    expect(logs.join('\n')).toContain('metrics listener is off (METRICS_ADDR=off)')
  })

  it('refuses to start on a port that is taken, naming it and METRICS_ADDR', async () => {
    const taken = net.createServer()
    await new Promise<void>((ok) => taken.listen(0, '127.0.0.1', ok))
    const { port } = taken.address() as AddressInfo
    try {
      await expect(startMetricsListener(`127.0.0.1:${port}`)).rejects.toThrow(
        `web-ui cannot start: the metrics listener cannot listen on METRICS_ADDR=127.0.0.1:${port}: ` +
          `port ${port} is already in use (EADDRINUSE). Set METRICS_ADDR to a free host:port, ` +
          'or to off to serve no metrics.',
      )
      const line = JSON.parse(logs.find((l) => l.includes('cannot start'))!)
      expect(line).toMatchObject({ level: 'ERROR', msg: 'web-ui cannot start: metrics listener' })
    } finally {
      await new Promise((ok) => taken.close(ok))
    }
  })

  it('refuses to start on an address that is not this host’s, or a malformed one', async () => {
    await expect(startMetricsListener('192.0.2.1:9464')).rejects.toThrow(
      /METRICS_ADDR=192\.0\.2\.1:9464: 192\.0\.2\.1 is not an address of this host \(EADDRNOTAVAIL\)/,
    )
    await expect(startMetricsListener('9464')).rejects.toThrow(
      /^web-ui cannot start: METRICS_ADDR="9464" is not an address to listen on/,
    )
  })

  it('closes, open connections included, when the server shuts down', async () => {
    const port = await started()
    // A scraper's keep-alive connection must not hold the process open.
    const agent = new http.Agent({ keepAlive: true })
    await new Promise<void>((ok, fail) =>
      http
        .get({ host: '127.0.0.1', port, path: '/metrics', agent }, (res) => {
          res.resume()
          res.on('end', ok)
        })
        .on('error', fail),
    )
    // What adapter-node emits once it has closed the UI's own server.
    ;(process.emit as (event: string) => boolean)('sveltekit:shutdown')
    await expect
      .poll(() =>
        request(port, 'GET', '/metrics').then(
          () => 'open',
          () => 'closed',
        ),
      )
      .toBe('closed')
    agent.destroy()
  })

  it('replaces the listener it started before, instead of failing on its port', async () => {
    const port = await started()
    expect(await startMetricsListener(`127.0.0.1:${port}`)).not.toBeNull()
    expect((await request(port, 'GET', '/metrics')).status).toBe(200)
  })
})
