import http from 'node:http'
import type { AddressInfo } from 'node:net'

/**
 * Stub backends for the browser tests: the killswitch-controller,
 * device-inventory and detection-engine HTTP APIs as contract v2 §4–§5 define
 * them, each on its own 127.0.0.1 port and each demanding its own bearer
 * token, plus a control port the tests use to pick a scenario.
 *
 * `legacy: true` switches the killswitch to today's controller behaviour:
 * no /actions/failed or /actions/history (404), a single `failed` state, a
 * failed revert answered with a 502 error message and the action dropped from
 * /actions/active, and `null` for empty lists.
 */

export const KEYS = {
  killswitch: 'e2e-killswitch-operator-token',
  'device-inventory': 'e2e-device-inventory-key',
  'detection-engine': 'e2e-detection-engine-key',
} as const

export type Service = keyof typeof KEYS

export interface Scenario {
  legacy: boolean
  /** Return list endpoints in a different order on every call. */
  shuffle: boolean
  /** Action ids whose driver apply fails. */
  failApply: string[]
  /** Action ids whose driver revert fails. */
  failRevert: string[]
  /** Services that refuse the web UI's key (401) whatever it sends. */
  rejectKey: Service[]
  /** Services answering 503. */
  down: Service[]
  /** GET /alerts shape: contract v2 (default) or the engine's older one. */
  alertsShape: 'v2' | 'v1'
}

export interface Seen {
  service: Service
  method: string
  path: string
  authorization: string | null
  actor: string | null
  body: string
}

type Action = Record<string, unknown> & { id: string; state: string; timestamp: string }

const DEFAULT_SCENARIO: Scenario = {
  legacy: false,
  shuffle: false,
  failApply: [],
  failRevert: [],
  rejectKey: [],
  down: [],
  alertsShape: 'v2',
}

export const DEVICES = [
  { mac: 'aa:bb:cc:00:00:01', ip: '192.168.1.77', hostname: 'kids-tablet' },
  { mac: 'aa:bb:cc:00:00:02', ip: '192.168.1.78', hostname: 'living-room-tv' },
  { mac: 'aa:bb:cc:00:00:03', ip: '192.168.1.79', hostname: 'printer' },
  { mac: 'aa:bb:cc:00:00:04', ip: '192.168.1.80', hostname: 'laptop' },
].map((d) => ({
  ...d,
  dhcp_fingerprint: '1,3,6,15,119,252',
  vendor_class: 'android-dhcp-14',
  vendor: 'Example Corp',
  os: 'Android',
  device_type: 'tablet',
  labels: [],
  first_seen: '2026-11-01T10:00:00Z',
  last_seen: '2026-11-16T10:00:00Z',
}))

function iso(base: number, minutes: number): string {
  return new Date(base + minutes * 60_000).toISOString()
}

function seedActions(now: number): Map<string, Action> {
  const common = {
    schema_version: '2.0',
    policy_rule: 'confidence below the auto-block threshold',
    auto_approved: false,
    ttl_seconds: 3600,
  }
  const list: Action[] = [
    {
      ...common,
      id: 'ACT-e2e-p1',
      timestamp: iso(now, -30),
      detection_id: 'DET-e2e-1',
      detection_summary: 'DNS query for a domain listed by ThreatFox',
      action_type: 'dns_sinkhole',
      state: 'pending',
      target_mac: 'aa:bb:cc:00:00:01',
      target_ip: '192.168.1.77',
      client_name: 'kids-tablet',
      blocked_domain: 'evil.example',
    },
    {
      ...common,
      id: 'ACT-e2e-p2',
      timestamp: iso(now, -20),
      detection_id: 'DET-e2e-2',
      detection_summary: 'Beaconing to a rare destination',
      action_type: 'dns_sinkhole',
      state: 'pending',
      target_mac: 'aa:bb:cc:00:00:02',
      target_ip: '192.168.1.78',
      blocked_domain: 'c2.bad.example',
    },
    {
      ...common,
      id: 'ACT-e2e-p3',
      timestamp: iso(now, -10),
      detection_id: 'DET-e2e-3',
      detection_summary: 'Suricata: ET MALWARE known C2 domain',
      action_type: 'dns_sinkhole',
      state: 'pending',
      target_mac: 'aa:bb:cc:00:00:03',
      target_ip: '192.168.1.79',
      client_name: 'printer',
      blocked_domain: 'update.malware.example',
    },
    {
      ...common,
      id: 'ACT-e2e-a1',
      timestamp: iso(now, -120),
      activated_at: iso(now, -119),
      expires_at: iso(now, 60),
      detection_id: 'DET-e2e-4',
      action_type: 'dns_sinkhole',
      state: 'active',
      target_mac: 'aa:bb:cc:00:00:04',
      target_ip: '192.168.1.80',
      client_name: 'laptop',
      blocked_domain: 'tracker.example',
      approved_by: 'Anna',
    },
    {
      ...common,
      id: 'ACT-e2e-f1',
      timestamp: iso(now, -240),
      detection_id: 'DET-e2e-5',
      action_type: 'dns_sinkhole',
      state: 'apply_failed',
      target_mac: 'aa:bb:cc:00:00:03',
      target_ip: '192.168.1.79',
      client_name: 'printer',
      blocked_domain: 'old.bad.example',
      approved_by: 'Anna',
      failure_reason: 'sinkhole: AdGuard returned 500',
    },
    {
      ...common,
      id: 'ACT-e2e-h1',
      timestamp: iso(now, -300),
      activated_at: iso(now, -299),
      reverted_at: iso(now, -200),
      detection_id: 'DET-e2e-6',
      action_type: 'dns_sinkhole',
      state: 'reverted',
      target_mac: 'aa:bb:cc:00:00:01',
      target_ip: '192.168.1.77',
      client_name: 'kids-tablet',
      blocked_domain: 'ads.example',
      approved_by: 'Anna',
      reverted_by: 'ttl',
    },
  ]
  return new Map(list.map((a) => [a.id, a]))
}

export const IDS_SUMMARY = 'Suricata: ET MALWARE Mozi botnet C2 traffic'

/**
 * GET /alerts in the contract v2 shape: seven DNS IoC alerts and, newest, an
 * IDS alert with no observed domain. The engine appends, so oldest first.
 */
function alertsV2(base: number) {
  const at = (i: number) => new Date(base - (8 - i) * 3600_000).toISOString()
  const dns = Array.from({ length: 7 }, (_, i) => ({
    id: `DET-e2e-${i + 1}`,
    timestamp: at(i),
    summary: `DNS query for d${i + 1}.example, listed by ThreatFox`,
    domain: `d${i + 1}.example`,
    matched_ioc: `d${i + 1}.example`,
    ioc_type: 'domain',
    client_ip: '192.168.1.77',
    client_mac: 'aa:bb:cc:00:00:01',
    client_name: 'kids-tablet',
    query_type: 'A',
    severity: 'high',
    source: 'threatfox',
    confidence: 80,
    mitre_id: 'T1071.004',
    mitre_name: 'Application Layer Protocol: DNS',
    threat: 'Mozi',
    tags: [],
    signal_class: 'ioc',
    signals: [
      {
        class: 'ioc',
        confidence: 80,
        indicator: `d${i + 1}.example`,
        indicator_type: 'domain',
        source: 'threatfox',
      },
    ],
    target: { type: 'domain', value: `d${i + 1}.example` },
  }))
  const ids = {
    id: 'DET-e2e-8',
    timestamp: at(7),
    summary: IDS_SUMMARY,
    domain: '',
    matched_ioc: '203.0.113.9',
    ioc_type: 'ip',
    client_ip: '192.168.1.78',
    client_mac: 'aa:bb:cc:00:00:02',
    client_name: 'living-room-tv',
    query_type: '',
    severity: 'high',
    source: 'suricata',
    confidence: 70,
    mitre_id: 'T1071',
    mitre_name: 'Application Layer Protocol',
    threat: 'Mozi',
    tags: ['ids'],
    signal_class: 'ids-signature',
    signals: [
      {
        class: 'ids-signature',
        confidence: 70,
        indicator: '2030919',
        indicator_type: 'sid',
        source: 'suricata',
      },
    ],
    target: { type: 'ip', value: '203.0.113.9' },
  }
  return [...dns, ids]
}

/** The shape engines sent before contract v2: no summary, signals as strings. */
function alertsV1(base: number) {
  return Array.from({ length: 8 }, (_, i) => ({
    id: `DET-${i + 1}`,
    timestamp: new Date(base - (8 - i) * 3600_000).toISOString(),
    domain: `d${i + 1}.example`,
    client_ip: '192.168.1.77',
    query_type: 'A',
    matched_ioc: `d${i + 1}.example`,
    severity: 'high',
    source: 'threatfox',
    confidence: 80,
    mitre_id: 'T1071.004',
    mitre_name: 'Application Layer Protocol: DNS',
    threat: 'Mozi',
    signals: ['ioc'],
  }))
}

class State {
  scenario: Scenario = { ...DEFAULT_SCENARIO }
  actions = seedActions(Date.now())
  base = Date.now()
  seen: Seen[] = []

  get alerts() {
    return this.scenario.alertsShape === 'v1' ? alertsV1(this.base) : alertsV2(this.base)
  }

  reset(s: Partial<Scenario> = {}) {
    this.scenario = { ...DEFAULT_SCENARIO, ...s }
    this.actions = seedActions(Date.now())
    this.base = Date.now()
    this.seen = []
  }
}

function send(res: http.ServerResponse, status: number, body: unknown, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type })
  res.end(typeof body === 'string' ? body : JSON.stringify(body))
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((ok) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => ok(body))
  })
}

let calls = 0

/**
 * Like Go map iteration, a different order on every call — but
 * deterministically so: rotate by the call count and reverse every other
 * call, so two consecutive calls never agree (for two or more items).
 */
function order<T>(items: T[], shuffle: boolean): T[] {
  if (!shuffle || items.length < 2) return items
  const k = calls++ % items.length
  const rotated = [...items.slice(k), ...items.slice(0, k)]
  return calls % 2 === 0 ? rotated.reverse() : rotated
}

const byTime = (dir: 1 | -1) => (a: Action, b: Action) =>
  dir * (Date.parse(a.timestamp) - Date.parse(b.timestamp)) || a.id.localeCompare(b.id)

function killswitch(state: State, method: string, path: string, body: string, actor: string) {
  const { legacy, shuffle } = state.scenario
  const all = [...state.actions.values()]
  const list = (items: Action[]) =>
    legacy && items.length === 0 ? null : order(items, shuffle || legacy)
  const reason = () => {
    try {
      return (JSON.parse(body || '{}') as { reason?: string }).reason ?? ''
    } catch {
      return ''
    }
  }

  if (method === 'GET' && path === '/actions/pending') {
    return [200, list(all.filter((a) => a.state === 'pending').sort(byTime(1)))] as const
  }
  if (method === 'GET' && path === '/actions/active') {
    const states = legacy ? ['active'] : ['active', 'revert_failed']
    return [200, list(all.filter((a) => states.includes(a.state)).sort(byTime(-1)))] as const
  }
  if (method === 'GET' && (path === '/actions/failed' || path === '/actions/history')) {
    if (legacy) return [404, { error: 'not found' }] as const
    const states =
      path === '/actions/failed'
        ? ['apply_failed', 'revert_failed']
        : ['reverted', 'rejected', 'expired', 'apply_failed']
    return [200, list(all.filter((a) => states.includes(a.state)).sort(byTime(-1)))] as const
  }
  if (method === 'GET' && path === '/policy') return [200, { auto_confidence: 90 }] as const

  const m = path.match(/^\/actions\/([^/]+)(?:\/(approve|reject|revert))?$/)
  const a = m ? state.actions.get(decodeURIComponent(m[1])) : undefined
  if (!m || !a) return [404, { error: 'not found' }] as const
  if (method === 'GET' && !m[2]) return [200, a] as const
  if (method !== 'POST' || !m[2]) return [405, { error: 'method not allowed' }] as const

  const now = new Date().toISOString()
  switch (m[2]) {
    case 'approve': {
      if (a.state !== 'pending')
        return [409, { error: `action is ${a.state}, not pending` }] as const
      a.approved_by = legacy ? 'operator' : actor
      if (state.scenario.failApply.includes(a.id)) {
        a.state = legacy ? 'failed' : 'apply_failed'
        a.failure_reason = 'sinkhole: AdGuard at 10.0.0.53 unreachable'
      } else {
        a.state = 'active'
        a.activated_at = now
        a.expires_at = new Date(Date.now() + Number(a.ttl_seconds) * 1000).toISOString()
      }
      return [200, a] as const
    }
    case 'reject': {
      if (a.state !== 'pending')
        return [409, { error: `action is ${a.state}, not pending` }] as const
      a.state = 'rejected'
      a.rejected_by = actor
      a.reason = reason()
      return [200, a] as const
    }
    case 'revert': {
      const revertable = legacy ? ['active'] : ['active', 'revert_failed']
      if (!revertable.includes(a.state)) {
        return [409, { error: `action is ${a.state}, cannot revert` }] as const
      }
      if (state.scenario.failRevert.includes(a.id)) {
        if (legacy) {
          a.state = 'failed'
          a.failure_reason = 'revert failed: adguard: connection refused'
          return [
            502,
            { error: 'revert failed, enforcement still active: adguard: connection refused' },
          ] as const
        }
        a.state = 'revert_failed'
        a.failure_reason = 'adguard: connection refused'
        return [502, a] as const
      }
      a.state = 'reverted'
      a.reverted_at = now
      a.reverted_by = actor
      a.reason = reason()
      return [200, a] as const
    }
  }
  return [404, { error: 'not found' }] as const
}

function deviceInventory(method: string, path: string) {
  if (method !== 'GET') return [405, { error: 'method not allowed' }] as const
  if (path === '/devices') return [200, DEVICES] as const
  if (path === '/topology') {
    return [
      200,
      {
        nodes: DEVICES.map((d) => ({
          id: d.ip,
          label: d.hostname,
          mac: d.mac,
          ip: d.ip,
          device_type: d.device_type,
          vendor: d.vendor,
          is_local: true,
          total_bytes: 1000,
          connection_count: 3,
        })),
        edges: [
          {
            source: '192.168.1.77',
            target: '192.168.1.78',
            total_bytes: 1000,
            total_packets: 10,
            flow_count: 1,
          },
        ],
      },
    ] as const
  }
  // Go's ServeMux hands handlers the decoded path value, as this does.
  const m = decodeURIComponent(path).match(/^\/devices\/([^/]+)(?:\/(connections|dns|alerts))?$/)
  const device = m && DEVICES.find((d) => d.mac === m[1])
  if (!device) return [404, '{"error":"not found"}\n', 'text/plain; charset=utf-8'] as const
  if (m[2] === 'alerts') {
    return [
      200,
      [1, 2, 3].map((i) => ({
        timestamp: new Date(Date.now() - (4 - i) * 3600_000).toISOString(),
        id: `DET-e2e-dev-${i}`,
        // The newest is an IDS alert: a summary and no observed domain.
        summary: i === 3 ? 'Suricata: ET POLICY outbound telnet' : `DNS query for dev${i}.example`,
        domain: i === 3 ? '' : `dev${i}.example`,
        query_type: i === 3 ? '' : 'A',
        matched_ioc: i === 3 ? '198.51.100.7' : `dev${i}.example`,
        severity: 'medium',
        source: i === 3 ? 'suricata' : 'threatfox',
      })),
    ] as const
  }
  if (m[2]) return [200, []] as const
  return [200, device] as const
}

function listen(server: http.Server): Promise<string> {
  return new Promise((ok) =>
    server.listen(0, '127.0.0.1', () => {
      ok(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)
    }),
  )
}

export interface Stubs {
  urls: Record<Service, string>
  control: string
  close(): Promise<void>
}

export async function startStubs(): Promise<Stubs> {
  const state = new State()

  const serve = (service: Service) =>
    http.createServer(async (req, res) => {
      const body = await readBody(req)
      const url = new URL(req.url ?? '/', 'http://stub')
      const authorization = req.headers.authorization ?? null
      const actor = (req.headers['x-netsoldier-actor'] as string | undefined) ?? null
      state.seen.push({
        service,
        method: req.method ?? '',
        path: url.pathname,
        authorization,
        actor,
        body,
      })

      if (
        authorization !== `Bearer ${KEYS[service]}` ||
        state.scenario.rejectKey.includes(service)
      ) {
        return send(res, 401, { error: 'unauthorized' })
      }
      if (state.scenario.down.includes(service)) return send(res, 503, { error: 'unavailable' })

      const method = req.method ?? 'GET'
      if (service === 'killswitch') {
        const [status, payload] = killswitch(state, method, url.pathname, body, actor ?? '')
        return send(res, status, payload)
      }
      if (service === 'device-inventory') {
        const [status, payload, type] = deviceInventory(method, url.pathname)
        return send(res, status, payload, type)
      }
      if (method === 'GET' && url.pathname === '/alerts') return send(res, 200, state.alerts)
      return send(res, 404, { error: 'not found' })
    })

  const control = http.createServer(async (req, res) => {
    const body = await readBody(req)
    const url = new URL(req.url ?? '/', 'http://stub')
    if (req.method === 'POST' && url.pathname === '/reset') {
      state.reset(body ? (JSON.parse(body) as Partial<Scenario>) : {})
      return send(res, 200, { ok: true })
    }
    if (req.method === 'POST' && url.pathname === '/scenario') {
      state.scenario = { ...state.scenario, ...(JSON.parse(body) as Partial<Scenario>) }
      return send(res, 200, state.scenario)
    }
    if (req.method === 'GET' && url.pathname === '/seen') return send(res, 200, state.seen)
    send(res, 404, { error: 'not found' })
  })

  const servers = {
    killswitch: serve('killswitch'),
    'device-inventory': serve('device-inventory'),
    'detection-engine': serve('detection-engine'),
  }
  const urls = {
    killswitch: await listen(servers.killswitch),
    'device-inventory': await listen(servers['device-inventory']),
    'detection-engine': await listen(servers['detection-engine']),
  }
  const controlUrl = await listen(control)

  return {
    urls,
    control: controlUrl,
    async close() {
      await Promise.all(
        [...Object.values(servers), control].map(
          (s) =>
            new Promise<void>((ok) => {
              s.closeAllConnections()
              s.close(() => ok())
            }),
        ),
      )
    },
  }
}
