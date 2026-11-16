import { execFile, spawn, type ChildProcess } from 'node:child_process'
import { createWriteStream, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import net, { type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

/**
 * The real backends for tests/browser/real-backends.spec.ts: the three Go
 * services built from this tree and started the way tests/e2e starts them
 * (testhelpers_test.go, phase1_test.go), on 127.0.0.1 ephemeral ports, with
 * authentication on. Around them, the two things a test machine does not
 * have:
 *
 * - a stub AdGuard Home (querylog for the detection engine, filtering rules
 *   for the killswitch's sinkhole), whose querylog the test fills;
 * - a stand-in netagent that registers two devices with device-inventory
 *   (one DHCP request each) and polls the killswitch for isolations. It
 *   holds an isolation until the test confirms it, which is what makes the
 *   controller answer an approve with 202.
 *
 * Detections take the production path: AdGuard querylog → detection engine
 * (static threat list) → signed webhook → killswitch POST /evaluate.
 */

const execFileAsync = promisify(execFile)

const TOKENS = {
  operator: 'real-e2e-operator-token',
  ingest: 'real-e2e-ingest-token',
  webhookSecret: 'real-e2e-webhook-secret',
  agentKillswitch: 'real-e2e-agent-killswitch-token',
  agentInventory: 'real-e2e-agent-inventory-token',
  device: 'real-e2e-device-api-key',
  detection: 'real-e2e-detection-api-key',
}

/** The devices the stand-in agent registers, and the domains the threat list flags. */
export const REAL_DEVICES = [
  { mac: 'aa:bb:cc:00:00:42', ip: '192.168.1.42', hostname: 'kids-tablet' },
  { mac: 'aa:bb:cc:00:00:43', ip: '192.168.1.43', hostname: 'living-room-tv' },
] as const
export const THREAT_DOMAINS = ['evil.example.com', 'c2.example.net'] as const

/**
 * `s` as a literal inside a RegExp, every metacharacter escaped: the one
 * way these tests put a domain (or any other string) into a pattern.
 */
export function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * The AdGuard rule the killswitch writes for `domain`: the domain itself,
 * anchored, not a substring of some other rule.
 */
export function sinkholeRule(domain: string): string {
  return `||${domain}^`
}

export type Service = 'killswitch' | 'device-inventory' | 'detection-engine'
export type Upstreams = Record<Service, { url: string; key: string }>

export interface RealStack {
  upstreams: Upstreams
  /** The test's control port: querylog entries, sinkhole rules, agent confirmations. */
  control: string
  close(): Promise<void>
  /** SIGKILLs the services at once, for a test runner that is exiting. */
  kill(): void
}

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

function listen(server: http.Server): Promise<string> {
  return new Promise((ok) =>
    server.listen(0, '127.0.0.1', () => {
      ok(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)
    }),
  )
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((ok) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => ok(body))
  })
}

function sendJSON(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

async function build(repoRoot: string, app: string, out: string): Promise<string> {
  const bin = join(out, app)
  try {
    await execFileAsync('go', ['build', '-o', bin, `./cmd/${app}`], {
      cwd: join(repoRoot, 'apps', app),
      // As tests/e2e builds them. The modules need Go 1.27.4: GOTOOLCHAIN=auto
      // uses the installed toolchain when it is new enough and fetches the
      // required one otherwise, whatever the shell says ("local" can only
      // fail here). E2E_GOTOOLCHAIN overrides it.
      env: {
        ...process.env,
        CGO_ENABLED: '0',
        GOWORK: 'off',
        GOTOOLCHAIN: process.env.E2E_GOTOOLCHAIN || 'auto',
      },
      timeout: 10 * 60_000,
      maxBuffer: 16 * 1024 * 1024,
    })
  } catch (e) {
    const err = e as { code?: string; stderr?: string; message: string }
    if (err.code === 'ENOENT') {
      throw new Error(
        'The real-backend browser test needs the Go toolchain to build the services ' +
          '(go not found on PATH). Install Go, or set E2E_REAL_BACKENDS=skip to leave it out.',
      )
    }
    throw new Error(`go build ${app} failed:\n${err.stderr ?? err.message}`)
  }
  return bin
}

async function waitHealthy(url: string, child: ChildProcess, name: string, logs: string) {
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null)
      throw new Error(`${name} exited with ${child.exitCode}; see ${logs}`)
    try {
      if ((await fetch(url)).ok) return
    } catch {
      // not listening yet
    }
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error(`${name}: ${url} did not become healthy in 30 s; see ${logs}`)
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return
  const exited = new Promise<void>((ok) => child.once('exit', () => ok()))
  child.kill('SIGINT')
  const timer = setTimeout(() => child.kill('SIGKILL'), 10_000)
  await exited
  clearTimeout(timer)
}

/** A DHCP REQUEST for `ip` with a host name, as netagent would capture it. */
function dhcpRequest(mac: string, ip: string, hostname: string): Buffer {
  const hw = Buffer.from(mac.split(':').map((h) => parseInt(h, 16)))
  const options = Buffer.concat([
    Buffer.from([53, 1, 3]), // REQUEST
    Buffer.from([50, 4, ...ip.split('.').map(Number)]), // requested address
    Buffer.from([12, hostname.length]),
    Buffer.from(hostname, 'ascii'),
    Buffer.from([55, 4, 1, 3, 6, 15]), // parameter request list
    Buffer.from([255]),
  ])
  const bootp = Buffer.alloc(240)
  bootp[0] = 1 // BOOTREQUEST
  bootp[1] = 1 // Ethernet
  bootp[2] = 6
  bootp.writeUInt32BE(0x4e534501, 4) // xid
  hw.copy(bootp, 28) // chaddr
  bootp.writeUInt32BE(0x63825363, 236) // magic cookie
  const payload = Buffer.concat([bootp, options])
  const udp = Buffer.alloc(8)
  udp.writeUInt16BE(68, 0)
  udp.writeUInt16BE(67, 2)
  udp.writeUInt16BE(8 + payload.length, 4)
  const ipv4 = Buffer.alloc(20)
  ipv4[0] = 0x45
  ipv4.writeUInt16BE(20 + 8 + payload.length, 2)
  ipv4[8] = 64
  ipv4[9] = 17 // UDP
  ipv4.fill(0xff, 16, 20) // to 255.255.255.255
  const eth = Buffer.alloc(14)
  eth.fill(0xff, 0, 6)
  hw.copy(eth, 6) // the link-layer source is the client: the inventory checks it
  eth.writeUInt16BE(0x0800, 12)
  return Buffer.concat([eth, ipv4, udp, payload])
}

interface QueryLogEntry {
  question: { host: string; type: string }
  client: string
  time: string
  reason: string
}

/** AdGuard Home's querylog and filtering API, as far as the services use them. */
function adguard(querylog: QueryLogEntry[], rules: { list: string[] }): http.Server {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://adguard')
    const body = await readBody(req)
    if (req.method === 'GET' && url.pathname === '/control/querylog') {
      const limit = Number(url.searchParams.get('limit') ?? 100) || 100
      const olderThan = url.searchParams.get('older_than')
      const cut = olderThan ? Date.parse(olderThan) : Infinity
      const data = [...querylog]
        .sort((a, b) => Date.parse(b.time) - Date.parse(a.time))
        .filter((e) => Date.parse(e.time) < cut)
        .slice(0, limit)
      return sendJSON(res, 200, { data, oldest: data.at(-1)?.time ?? '' })
    }
    if (req.method === 'GET' && url.pathname === '/control/filtering/status') {
      return sendJSON(res, 200, { enabled: true, user_rules: rules.list })
    }
    if (req.method === 'POST' && url.pathname === '/control/filtering/set_rules') {
      rules.list = (JSON.parse(body) as { rules: string[] }).rules ?? []
      res.writeHead(200)
      return res.end()
    }
    sendJSON(res, 404, { error: 'not found' })
  })
}

interface AgentCommand {
  id: string
  type: string
  mac: string
  ip: string
  ttl_seconds?: number
}

/**
 * netagent's side of contract v2 §8.2: polls, reports results and the
 * isolations it has in force. Isolations are held until confirm(); releases
 * are carried out at once, or — while holdReleases is set — held until
 * confirm() too, which is what makes the controller answer a revert with 202.
 */
class StandInAgent {
  private results: { id: string; ok: boolean; error: string }[] = []
  private active = new Map<string, { mac: string; ip: string; expires: string }>()
  private held: AgentCommand[] = []
  private heldReleases: AgentCommand[] = []
  holdReleases = false
  private timer: NodeJS.Timeout | null = null
  private polling = false

  constructor(private readonly killswitch: string) {}

  start() {
    this.timer = setInterval(() => void this.poll(), 500)
  }

  async stop() {
    if (this.timer) clearInterval(this.timer)
    while (this.polling) await new Promise((r) => setTimeout(r, 20))
  }

  confirm(): number {
    const n = this.held.length + this.heldReleases.length
    for (const c of this.held.splice(0)) this.isolate(c)
    for (const c of this.heldReleases.splice(0)) this.release(c)
    return n
  }

  state() {
    return {
      held: this.held.map((c) => c.mac),
      heldReleases: this.heldReleases.map((c) => c.mac),
      active: [...this.active.keys()],
    }
  }

  private isolate(c: AgentCommand) {
    const expires = new Date(Date.now() + (c.ttl_seconds ?? 3600) * 1000).toISOString()
    this.active.set(c.mac, { mac: c.mac, ip: c.ip, expires })
    this.results.push({ id: c.id, ok: true, error: '' })
  }

  private release(c: AgentCommand) {
    this.active.delete(c.mac)
    this.results.push({ id: c.id, ok: true, error: '' })
  }

  private async poll() {
    if (this.polling) return
    this.polling = true
    const results = this.results.splice(0)
    try {
      const res = await fetch(`${this.killswitch}/agent/v1/poll`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${TOKENS.agentKillswitch}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ agent: 'e2e-agent', results, active: [...this.active.values()] }),
      })
      if (!res.ok) throw new Error(`poll: ${res.status}`)
      const { commands } = (await res.json()) as { commands: AgentCommand[] }
      for (const c of commands ?? []) {
        if (c.type === 'arp_isolate') this.held.push(c)
        else if (c.type === 'arp_release') {
          if (this.holdReleases) this.heldReleases.push(c)
          else this.release(c)
        }
      }
    } catch {
      this.results.unshift(...results) // report them on the next poll
    } finally {
      this.polling = false
    }
  }
}

export async function startRealStack(repoRoot: string, logDir: string): Promise<RealStack> {
  const work = mkdtempSync(join(tmpdir(), 'netsoldier-real-e2e-'))
  const children: ChildProcess[] = []
  const servers: http.Server[] = []
  let agent: StandInAgent | null = null

  const close = async () => {
    await agent?.stop()
    await Promise.all(children.map(stop))
    await Promise.all(
      servers.map(
        (s) =>
          new Promise<void>((ok) => {
            s.closeAllConnections()
            s.close(() => ok())
          }),
      ),
    )
    rmSync(work, { recursive: true, force: true })
  }

  try {
    const [ks, inv, det] = await Promise.all(
      (['killswitch-controller', 'device-inventory', 'detection-engine'] as const).map((app) =>
        build(repoRoot, app, work),
      ),
    )

    const querylog: QueryLogEntry[] = []
    const rules = { list: [] as string[] }
    const ag = adguard(querylog, rules)
    servers.push(ag)
    const agURL = await listen(ag)

    const run = async (name: string, bin: string, env: Record<string, string>) => {
      const port = await freePort()
      const log = createWriteStream(join(logDir, `real-${name}.log`))
      // From scratch, like the UI's: nothing from the developer's shell.
      const child = spawn(bin, [], {
        env: { PATH: process.env.PATH ?? '', LISTEN_ADDR: `127.0.0.1:${port}`, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
      child.stdout?.pipe(log)
      child.stderr?.pipe(log)
      children.push(child)
      const url = `http://127.0.0.1:${port}`
      await waitHealthy(`${url}/healthz`, child, name, logDir)
      return url
    }

    const invURL = await run('device-inventory', inv, {
      DB_PATH: join(work, 'devices.db'),
      DEVICE_API_KEY: TOKENS.device,
      NETAGENT_TOKEN: TOKENS.agentInventory,
      // No capture agent is expected (readiness ignores the heartbeat).
      NETAGENT_EXPECT_CAPTURE: 'none',
    })

    // The stand-in agent reports the household's devices before any
    // detection needs them: one DHCP request each.
    const frames = REAL_DEVICES.map((d) => ({
      t: Date.now() * 1_000_000,
      proto: 'dhcp',
      data: dhcpRequest(d.mac, d.ip, d.hostname).toString('base64'),
    }))
    const posted = await fetch(`${invURL}/agent/v1/frames`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKENS.agentInventory}` },
      body: JSON.stringify({
        agent: 'e2e-agent',
        interface: 'eth0',
        frames,
        results: [],
        status: { capture: { dhcp: true }, dropped: 0 },
      }),
    })
    if (!posted.ok) throw new Error(`device-inventory refused the frames: ${posted.status}`)
    for (const d of REAL_DEVICES) {
      const deadline = Date.now() + 10_000
      for (;;) {
        const r = await fetch(`${invURL}/devices/by-ip/${d.ip}`, {
          headers: { Authorization: `Bearer ${TOKENS.device}` },
        })
        if (r.ok) break
        if (Date.now() > deadline) throw new Error(`device-inventory never bound ${d.ip}`)
        await new Promise((ok) => setTimeout(ok, 100))
      }
    }

    const ksURL = await run('killswitch', ks, {
      KILLSWITCH_DB_PATH: join(work, 'killswitch.db'),
      ADGUARD_URL: agURL,
      ADGUARD_USER: 'admin',
      ADGUARD_PASSWORD: 'test',
      KILLSWITCH_API_KEY: TOKENS.operator,
      KILLSWITCH_INGEST_TOKEN: TOKENS.ingest,
      WEBHOOK_SECRET: TOKENS.webhookSecret,
      ALLOWLIST_IPS: '192.168.1.1',
      // ARP isolation through the agent: the gateway pinned by both
      // identifiers, and a confirmation window longer than the 9 s the
      // controller waits before answering an approve with 202.
      NETAGENT_KILLSWITCH_TOKEN: TOKENS.agentKillswitch,
      GATEWAY_IP: '192.168.1.1',
      GATEWAY_MAC: '00:11:22:33:44:01',
      KILLSWITCH_AGENT_CONFIRM_TIMEOUT: '90s',
      KILLSWITCH_REAPER_INTERVAL: '1s',
    })
    agent = new StandInAgent(ksURL)
    agent.start()

    const threatList = join(work, 'domains.txt')
    writeFileSync(threatList, THREAT_DOMAINS.join('\n') + '\n')
    const detURL = await run('detection-engine', det, {
      DB_PATH: join(work, 'detection-engine.db'),
      ADGUARD_URL: agURL,
      ADGUARD_USER: 'admin',
      ADGUARD_PASSWORD: 'test',
      THREATLIST_PATH: threatList,
      POLL_INTERVAL: '1s',
      WEBHOOK_URL: `${ksURL}/evaluate`,
      WEBHOOK_SECRET: TOKENS.webhookSecret,
      WEBHOOK_TOKEN: TOKENS.ingest,
      DETECTION_API_KEY: TOKENS.detection,
      DEVICE_INVENTORY_URL: invURL,
      DEVICE_API_KEY: TOKENS.device,
      OTEL_EXPORTER_OTLP_ENDPOINT: 'localhost:1',
    })

    // The test's levers: put a DNS query in AdGuard's log, read the
    // sinkhole rules, confirm held isolations (and releases, when held).
    const control = http.createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', 'http://control')
      const body = await readBody(req)
      if (req.method === 'POST' && url.pathname === '/querylog') {
        const { host, client } = JSON.parse(body) as { host: string; client: string }
        querylog.push({
          question: { host, type: 'A' },
          client,
          time: new Date().toISOString(),
          reason: 'NotFilteredNotFound',
        })
        return sendJSON(res, 200, { ok: true })
      }
      if (req.method === 'GET' && url.pathname === '/rules') return sendJSON(res, 200, rules.list)
      if (req.method === 'POST' && url.pathname === '/agent/confirm') {
        return sendJSON(res, 200, { confirmed: agent!.confirm() })
      }
      if (req.method === 'POST' && url.pathname === '/agent/hold-releases') {
        agent!.holdReleases = (JSON.parse(body) as { hold: boolean }).hold
        return sendJSON(res, 200, { hold: agent!.holdReleases })
      }
      if (req.method === 'GET' && url.pathname === '/agent')
        return sendJSON(res, 200, agent!.state())
      sendJSON(res, 404, { error: 'not found' })
    })
    servers.push(control)
    const controlURL = await listen(control)

    return {
      upstreams: {
        killswitch: { url: ksURL, key: TOKENS.operator },
        'device-inventory': { url: invURL, key: TOKENS.device },
        'detection-engine': { url: detURL, key: TOKENS.detection },
      },
      control: controlURL,
      close,
      kill: () => children.forEach((c) => c.kill('SIGKILL')),
    }
  } catch (e) {
    await close()
    throw e
  }
}
