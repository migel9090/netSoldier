import http from 'node:http'
import type { AddressInfo } from 'node:net'

/**
 * Stub backends for the browser tests: the killswitch-controller,
 * device-inventory and detection-engine HTTP APIs as the real services on
 * this branch serve them, each on its own 127.0.0.1 port and each demanding
 * its own bearer token, plus a control port the tests use to pick a
 * scenario. tests/browser/real-backends.spec.ts runs the same UI against the
 * real services; this stub exists for the cases those cannot be made to
 * produce on demand (a driver that fails or answers late, conflicts,
 * hundreds of finished actions).
 *
 * What it copies from the real services, and the UI depends on:
 *
 * - killswitch (cmd/killswitch-controller/api.go): every mutation needs
 *   exactly one X-Netsoldier-Actor that is printable ASCII and not one of the
 *   controller's own names (else 400); approve takes an optional
 *   `action_type`, refused with 422 + `available_action_types` when it
 *   cannot be carried out; a driver that has not answered gives 202 with the
 *   action still `approved` (or, for a revert, still `active`); a request the
 *   action's state does not allow gives 409 with the action and an `error`;
 *   a failed revert gives 502 with the action `revert_failed` and an
 *   `error`; `approved` actions are in no list; every transition is in
 *   GET /audit (newest first, `before`, `action_id`); every action carries
 *   `in_flight` (`apply` while approved, `revert` while a revert is under
 *   way, absent otherwise — or always absent, as from a controller that
 *   predates it); GET /policy says whether auto-block is allowed and why not.
 * - detection engine: GET /alerts newest first with ?limit=, `suppressed:
 *   true` on alerts recorded while silenced (a backend change in progress;
 *   the real engine does not send it yet); POST /feedback needs a signal
 *   class (or an alert id it holds) and answers 202 with `persisted`; a
 *   `confirmed` verdict ends the matching suppressions; POST /feedback/lift
 *   ends exactly one (200 with `persisted`, 404 when none is in force);
 *   GET /feedback lists them with `expires_at`.
 * - device inventory: provenance, binding state, `conflict_count` on lists,
 *   `conflicts` on single reads, X-Total-Count.
 */

export const KEYS = {
  killswitch: 'e2e-killswitch-operator-token',
  'device-inventory': 'e2e-device-inventory-key',
  'detection-engine': 'e2e-detection-engine-key',
} as const

export type Service = keyof typeof KEYS

export interface Scenario {
  /** Return list endpoints in a different order on every call. */
  shuffle: boolean
  /** Action ids whose driver apply fails. */
  failApply: string[]
  /** Action ids whose driver revert fails. */
  failRevert: string[]
  /** Action ids whose apply has no outcome until POST /settle (202). */
  slowApply: string[]
  /** Action ids whose revert has no outcome until POST /settle (202). */
  slowRevert: string[]
  /** GET /policy available_action_types. */
  available: string[]
  /** Extra finished actions, for the history and audit paging. */
  finished: number
  /** Services that refuse the web UI's key (401) whatever it sends. */
  rejectKey: Service[]
  /** Services answering 503. */
  down: Service[]
  /** GET /alerts shape: contract v2 (default) or the engine's older one. */
  alertsShape: 'v2' | 'v1'
  /** POST /feedback `persisted`: false when the engine's ClickHouse is down. */
  persistFeedback: boolean
  /** X-Total-Count of GET /devices; the list length when null. */
  deviceTotal: number | null
  /**
   * The printer has 15 recent conflicts: the list counts them all, a
   * single read attaches (and counts) the 10 most recent, as the inventory does.
   */
  manyConflicts: boolean
  /** GET /policy answers 500 (everything else works). */
  policyDown: boolean
  /** GET /policy auto_block_disabled_reason; empty: auto-block is allowed. */
  autoBlockReason: string
  /** Actions carry `in_flight`; false is a controller that predates it. */
  inFlight: boolean
  /** Alert ids the engine recorded while a suppression applied (`suppressed: true`). */
  silenced: string[]
  /** GET /feedback sends `expires_at`; false is an engine that predates it. */
  suppressionExpiry: boolean
  /** The engine's suppression TTL. */
  suppressionTtlDays: number
}

/** A suppression put in place through the control port, `ageMinutes` old. */
export interface SeededSuppression {
  matched_ioc: string
  client_ip?: string
  signal_class: string
  analyst?: string
  reason?: string
  ageMinutes?: number
}

export interface Seen {
  service: Service
  method: string
  path: string
  search: string
  authorization: string | null
  actor: string | null
  body: string
}

type Action = Record<string, unknown> & {
  id: string
  state: string
  timestamp: string
  action_type: string
}

interface AuditEntry {
  seq: number
  timestamp: string
  action_id: string
  from_state: string
  to_state: string
  actor: string
  reason: string
  detection_id: string
  detection_summary: string
  target_mac: string
  target_ip: string
  action_type: string
  blocked_domain: string
  policy_rule: string
}

interface Suppression {
  alert_id?: string
  matched_ioc: string
  client_ip?: string
  signal_class: string
  verdict: string
  reason?: string
  analyst: string
  timestamp: string
}

const DEFAULT_SCENARIO: Scenario = {
  shuffle: false,
  failApply: [],
  failRevert: [],
  slowApply: [],
  slowRevert: [],
  available: ['dns_sinkhole', 'arp_isolate'],
  finished: 0,
  rejectKey: [],
  down: [],
  alertsShape: 'v2',
  persistFeedback: true,
  deviceTotal: null,
  manyConflicts: false,
  policyDown: false,
  autoBlockReason: '',
  inFlight: true,
  silenced: [],
  suppressionExpiry: true,
  suppressionTtlDays: 30,
}

export const INTRUDER_MAC = '02:de:ad:be:ef:01'

export const DEVICES = [
  { mac: 'aa:bb:cc:00:00:01', ip: '192.168.1.77', hostname: 'kids-tablet' },
  { mac: 'aa:bb:cc:00:00:02', ip: '192.168.1.78', hostname: 'living-room-tv' },
  { mac: 'aa:bb:cc:00:00:03', ip: '192.168.1.79', hostname: 'printer' },
  { mac: 'aa:bb:cc:00:00:04', ip: '192.168.1.80', hostname: 'laptop' },
].map((d) => ({
  ...d,
  ip_source: 'dhcp',
  ip_state: d.hostname === 'laptop' ? 'tentative' : 'live',
  ip_since: '2026-11-01T10:00:00Z',
  ip_confirmed_at: '2026-11-16T10:00:00Z',
  hostname_source: 'dhcp',
  dhcp_fingerprint: '1,3,6,15,119,252',
  vendor_class: 'android-dhcp-14',
  vendor: 'Example Corp',
  os: 'Android',
  device_type: 'tablet',
  randomized_mac: false,
  labels: [] as string[],
  established: true,
  conflict_count: d.hostname === 'printer' ? 2 : 0,
  first_seen: '2026-11-01T10:00:00Z',
  last_seen: '2026-11-16T10:00:00Z',
}))

/** What GET /devices/{printer} attaches: something claiming to be the printer. */
export const PRINTER_CONFLICTS = [
  {
    kind: 'ip_taken',
    mac: 'aa:bb:cc:00:00:03',
    claimant: INTRUDER_MAC,
    ip: '192.168.1.79',
    source: 'arp',
    first_seen: '2026-11-16T09:00:00Z',
    last_seen: '2026-11-16T09:30:00Z',
    count: 14,
  },
  {
    kind: 'name',
    mac: 'aa:bb:cc:00:00:03',
    value: 'printer-setup',
    source: 'mdns',
    first_seen: '2026-11-16T09:10:00Z',
    last_seen: '2026-11-16T09:10:00Z',
    count: 1,
  },
]

const RESERVED = new Set(['auto-policy', 'ttl', 'reconcile', 'netagent', 'system'])
const TERMINAL = ['reverted', 'rejected', 'expired', 'apply_failed']

function iso(base: number, minutes: number): string {
  return new Date(base + minutes * 60_000).toISOString()
}

function seedActions(now: number, finished: number): Action[] {
  const common = {
    schema_version: '2.0',
    policy_rule: 'pending: confidence=80 severity=high signals=1',
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
      failure_reason: 'apply failed: sinkhole: AdGuard returned 500',
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
      reason: 'ttl expired',
    },
  ]
  for (let i = 1; i <= finished; i++) {
    list.push({
      ...common,
      id: `ACT-e2e-old-${i}`,
      timestamp: iso(now, -10_000 - i * 10),
      detection_id: `DET-e2e-old-${i}`,
      action_type: 'dns_sinkhole',
      state: i % 2 ? 'rejected' : 'reverted',
      target_mac: 'aa:bb:cc:00:00:02',
      target_ip: '192.168.1.78',
      blocked_domain: `old${i}.example`,
      ...(i % 2 ? { rejected_by: 'Anna', reason: 'False positive' } : { approved_by: 'Anna' }),
      ...(i % 2 ? {} : { reverted_by: 'ttl', reverted_at: iso(now, -9_000 - i * 10) }),
    })
  }
  return list
}

export const IDS_SUMMARY = 'Suricata: ET MALWARE Mozi botnet C2 traffic'

/** GET /alerts in the contract v2 shape, newest first: an IDS alert, then seven DNS IoC alerts. */
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
  return [ids, ...dns.reverse()]
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
  })).reverse()
}

class State {
  scenario: Scenario = { ...DEFAULT_SCENARIO }
  actions = new Map<string, Action>()
  /** Insertion order, like the controller's seq. */
  order: string[] = []
  /** Most recently finished last, like ORDER BY updated_at. */
  updated = new Map<string, number>()
  audit: AuditEntry[] = []
  /** Reverts answered with 202, by action id: who asked, and why. */
  reverting = new Map<string, { actor: string; reason: string }>()
  suppressions: Suppression[] = []
  base = Date.now()
  seen: Seen[] = []
  clock = 0

  constructor() {
    this.reset()
  }

  get alerts() {
    const list: Record<string, unknown>[] =
      this.scenario.alertsShape === 'v1' ? alertsV1(this.base) : alertsV2(this.base)
    const silenced = new Set(this.scenario.silenced)
    return list.map((a) => (silenced.has(String(a.id)) ? { ...a, suppressed: true } : a))
  }

  /** GET /feedback: each suppression with when it ends. */
  listedSuppressions() {
    const ttl = this.scenario.suppressionTtlDays * 24 * 3600_000
    return this.suppressions.map((s) =>
      this.scenario.suppressionExpiry
        ? { ...s, expires_at: new Date(Date.parse(s.timestamp) + ttl).toISOString() }
        : s,
    )
  }

  /** The wire form of an action: `in_flight` from what is outstanding on it. */
  wire(a: Action): Action {
    if (!this.scenario.inFlight) return a
    const op = a.state === 'approved' ? 'apply' : this.reverting.has(a.id) ? 'revert' : ''
    return op ? { ...a, in_flight: op } : a
  }

  reset(s: Partial<Scenario> = {}) {
    this.scenario = { ...DEFAULT_SCENARIO, ...s }
    this.base = Date.now()
    this.actions = new Map()
    this.order = []
    this.updated = new Map()
    this.audit = []
    this.reverting = new Map()
    this.suppressions = []
    this.seen = []
    this.clock = 0
    // Oldest first, so sequence numbers grow with time like the controller's.
    const seeded = seedActions(this.base, this.scenario.finished).sort(
      (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
    )
    for (const a of seeded) this.seed(a)
  }

  /** Stores a seeded action with the audit trail that would have led to its state. */
  private seed(a: Action) {
    this.actions.set(a.id, a)
    this.order.push(a.id)
    const at = Date.parse(a.timestamp)
    this.log(a, '', 'pending', 'auto-policy', String(a.policy_rule), at)
    const by = String(a.approved_by ?? '')
    if (a.state === 'pending') return
    if (a.state === 'rejected') {
      this.log(a, 'pending', 'rejected', String(a.rejected_by), String(a.reason ?? ''), at + 60_000)
    } else {
      this.log(a, 'pending', 'approved', by, 'approved', at + 30_000)
      if (a.state === 'apply_failed') {
        this.log(a, 'approved', 'apply_failed', by, String(a.failure_reason), at + 31_000)
      } else {
        this.log(a, 'approved', 'active', by, 'enforcement applied by dns_sinkhole', at + 31_000)
        if (a.state === 'reverted') {
          const end = Date.parse(String(a.reverted_at)) || at + 120_000
          this.log(a, 'active', 'reverted', String(a.reverted_by), String(a.reason ?? ''), end)
        }
      }
    }
    if (TERMINAL.includes(a.state)) this.updated.set(a.id, ++this.clock)
  }

  log(a: Action, from: string, to: string, actor: string, reason: string, at = Date.now()) {
    this.audit.push({
      seq: this.audit.length + 1,
      timestamp: new Date(at).toISOString(),
      action_id: a.id,
      from_state: from,
      to_state: to,
      actor,
      reason,
      detection_id: String(a.detection_id ?? ''),
      detection_summary: String(a.detection_summary ?? ''),
      target_mac: String(a.target_mac ?? ''),
      target_ip: String(a.target_ip ?? ''),
      action_type: a.action_type,
      blocked_domain: String(a.blocked_domain ?? ''),
      policy_rule: String(a.policy_rule ?? ''),
    })
  }

  move(a: Action, to: string, actor: string, reason: string) {
    this.log(a, a.state, to, actor, reason)
    a.state = to
    if (TERMINAL.includes(to)) this.updated.set(a.id, ++this.clock)
  }
}

function send(
  res: http.ServerResponse,
  status: number,
  body: unknown,
  type = 'application/json',
  headers: Record<string, string> = {},
) {
  res.writeHead(status, { 'Content-Type': type, ...headers })
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

type Reply = readonly [number, unknown] | readonly [number, unknown, string]

function limitOf(params: URLSearchParams, def: number, max: number): number | null {
  const v = params.get('limit')
  if (v === null || v === '') return def
  const n = Number(v)
  return Number.isInteger(n) && n >= 1 ? Math.min(n, max) : null
}

/** api.go actorFrom. */
function actorProblem(headers: http.IncomingHttpHeaders): string {
  const raw = headers['x-netsoldier-actor']
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw]
  if (values.length !== 1) {
    return 'exactly one X-Netsoldier-Actor header naming the operator is required'
  }
  const a = values[0]
  if (a.length < 1 || a.length > 64) return 'X-Netsoldier-Actor must be 1-64 characters'
  if (!/^[\x20-\x7e]+$/.test(a)) return 'X-Netsoldier-Actor must be printable ASCII'
  if (RESERVED.has(a.toLowerCase())) {
    return `X-Netsoldier-Actor "${a}" is reserved for the controller itself`
  }
  return ''
}

function killswitch(
  state: State,
  method: string,
  path: string,
  params: URLSearchParams,
  body: string,
  headers: http.IncomingHttpHeaders,
): Reply {
  const { shuffle } = state.scenario
  const inOrder = (states: string[], dir: 1 | -1) => {
    const ids = dir === 1 ? state.order : [...state.order].reverse()
    return order(
      ids.map((id) => state.actions.get(id)!).filter((a) => states.includes(a.state)),
      shuffle,
    )
  }

  if (method === 'GET' && path === '/actions/pending') return [200, inOrder(['pending'], 1)]
  // Not `approved`: an apply in progress is in no list (contract v2 §4).
  if (method === 'GET' && path === '/actions/active') {
    return [200, inOrder(['active', 'revert_failed'], -1)]
  }
  if (method === 'GET' && path === '/actions/failed') {
    return [200, inOrder(['apply_failed', 'revert_failed'], -1)]
  }
  if (method === 'GET' && path === '/actions/history') {
    const limit = limitOf(params, 100, 500)
    if (limit === null) return [400, { error: 'limit must be a positive integer' }]
    const done = [...state.actions.values()]
      .filter((a) => TERMINAL.includes(a.state))
      .sort((a, b) => (state.updated.get(b.id) ?? 0) - (state.updated.get(a.id) ?? 0))
    return [200, done.slice(0, limit)]
  }
  if (method === 'GET' && path === '/audit') {
    const limit = limitOf(params, 100, 500)
    if (limit === null) return [400, { error: 'limit must be a positive integer' }]
    const before = Number(params.get('before') ?? 0)
    const id = params.get('action_id') ?? ''
    const entries = [...state.audit]
      .reverse()
      .filter((e) => (!before || e.seq < before) && (!id || e.action_id === id))
    return [200, entries.slice(0, limit)]
  }
  if (method === 'GET' && path === '/policy' && state.scenario.policyDown) {
    return [500, { error: 'internal error' }]
  }
  if (method === 'GET' && path === '/policy') {
    return [
      200,
      {
        auto_min_confidence: 90,
        auto_min_severity: 'critical',
        default_action: 'dns_sinkhole',
        default_ttl: 3600,
        auto_block_allowed: state.scenario.autoBlockReason === '',
        auto_block_disabled_reason: state.scenario.autoBlockReason,
        available_action_types: state.scenario.available,
        pending_ttl_seconds: 86400,
      },
    ]
  }

  const m = path.match(/^\/actions\/([^/]+)(?:\/(approve|reject|revert))?$/)
  if (!m) return [404, { error: 'not found' }]
  const verb = m[2]
  if (method === 'POST' && verb) {
    const problem = actorProblem(headers)
    if (problem) return [400, { error: problem }]
  }
  const a = state.actions.get(decodeURIComponent(m[1]))
  if (!a) return [404, { error: 'not found' }]
  if (method === 'GET' && !verb) return [200, a]
  if (method !== 'POST' || !verb) return [405, { error: 'method not allowed' }]

  let req: { action_type?: string; reason?: string } = {}
  try {
    req = JSON.parse(body || '{}')
  } catch {
    return [400, { error: 'invalid body' }]
  }
  const actor = String(headers['x-netsoldier-actor'])
  const conflict = (msg: string): Reply => [409, { ...a, error: msg }]
  const now = new Date().toISOString()
  const { scenario } = state

  switch (verb) {
    case 'approve': {
      if (a.state === 'approved' || a.state === 'active') {
        if (req.action_type && req.action_type !== a.action_type) {
          return conflict(`action ${a.id} was already approved as ${a.action_type}`)
        }
        return [a.state === 'approved' ? 202 : 200, a]
      }
      if (a.state !== 'pending') return conflict(`action ${a.id} is ${a.state}, not pending`)
      const type = req.action_type || a.action_type
      if (!scenario.available.includes(type)) {
        return [
          422,
          {
            error: `action type "${type}" is not available: no driver is configured for it`,
            available_action_types: scenario.available,
          },
        ]
      }
      const reason =
        type !== a.action_type ? `approved as ${type} (proposed ${a.action_type})` : 'approved'
      a.action_type = type
      a.approved_by = actor
      state.move(a, 'approved', actor, reason)
      if (scenario.slowApply.includes(a.id)) return [202, a]
      if (scenario.failApply.includes(a.id)) {
        a.failure_reason = 'apply failed: sinkhole: AdGuard at 10.0.0.53 unreachable'
        state.move(a, 'apply_failed', actor, String(a.failure_reason))
      } else {
        a.activated_at = now
        a.expires_at = new Date(Date.now() + Number(a.ttl_seconds) * 1000).toISOString()
        state.move(a, 'active', actor, `enforcement applied by ${type}`)
      }
      return [200, a]
    }
    case 'reject': {
      if (a.state !== 'pending') return conflict(`action ${a.id} is ${a.state}, not pending`)
      a.rejected_by = actor
      a.reason = req.reason || `rejected by ${actor}`
      state.move(a, 'rejected', actor, String(a.reason))
      return [200, a]
    }
    case 'revert': {
      if (a.state === 'reverted') return [200, a]
      if (a.state === 'approved') {
        return conflict(`action ${a.id} is still being applied; revert it once it is active`)
      }
      if (a.state !== 'active' && a.state !== 'revert_failed') {
        return conflict(`action ${a.id} is ${a.state}: nothing is enforced`)
      }
      const reason = req.reason || `reverted by ${actor}`
      if (scenario.failRevert.includes(a.id)) {
        a.failure_reason = 'revert failed: adguard: connection refused'
        if (a.state !== 'revert_failed') {
          state.move(a, 'revert_failed', actor, String(a.failure_reason))
        }
        return [
          502,
          {
            ...a,
            error: `revert failed, the enforcement is STILL IN FORCE and is being retried: ${a.failure_reason}`,
          },
        ]
      }
      if (scenario.slowRevert.includes(a.id)) {
        state.reverting.set(a.id, { actor, reason })
        return [202, a]
      }
      a.reverted_at = now
      a.reverted_by = actor
      a.reason = reason
      state.move(a, 'reverted', actor, reason)
      return [200, a]
    }
  }
  return [404, { error: 'not found' }]
}

/**
 * Every action in a killswitch reply in its wire form (with `in_flight`).
 * Audit entries name theirs by `action_id`, the policy has no `id`: both
 * are left alone.
 */
function wireReply(state: State, payload: unknown): unknown {
  const isAction = (v: unknown): v is Action =>
    typeof v === 'object' && v !== null && 'id' in v && 'state' in v && 'action_type' in v
  if (Array.isArray(payload)) return payload.map((v) => (isAction(v) ? state.wire(v) : v))
  return isAction(payload) ? state.wire(payload) : payload
}

/**
 * A revert started somewhere else — another operator, the TTL reaper, a
 * retry of a failed revert — and not answered yet: POST /begin-revert {id}.
 */
function beginRevert(state: State, id: string, actor = 'ttl'): boolean {
  const a = state.actions.get(id)
  if (!a || (a.state !== 'active' && a.state !== 'revert_failed')) return false
  state.reverting.set(id, { actor, reason: `reverted by ${actor}` })
  return true
}

/** What a 202 was waiting for arrives: POST /settle {id, state?}. */
function settle(state: State, id: string, to?: string): boolean {
  const a = state.actions.get(id)
  if (!a) return false
  const now = new Date().toISOString()
  if (a.state === 'approved') {
    const target = to ?? 'active'
    const by = a.action_type === 'arp_isolate' ? 'netagent' : String(a.approved_by)
    if (target === 'active') {
      a.activated_at = now
      a.expires_at = new Date(Date.now() + Number(a.ttl_seconds) * 1000).toISOString()
    } else {
      a.failure_reason = 'the netagent refused the isolation: target is the gateway'
    }
    state.move(
      a,
      target,
      by,
      target === 'active' ? 'the netagent confirmed the isolation' : String(a.failure_reason),
    )
    return true
  }
  const pending = state.reverting.get(id)
  if ((a.state === 'active' || a.state === 'revert_failed') && pending) {
    state.reverting.delete(id)
    const target = to ?? 'reverted'
    if (target === 'reverted') {
      a.reverted_at = now
      a.reverted_by = pending.actor
      a.reason = pending.reason
    } else {
      a.failure_reason = 'revert failed: adguard: connection refused'
    }
    if (target !== a.state) state.move(a, target, pending.actor, pending.reason)
    return true
  }
  return false
}

function deviceInventory(method: string, path: string, state: State): Reply {
  if (method !== 'GET') return [405, { error: 'method not allowed' }]
  if (path === '/devices') {
    const many = state.scenario.manyConflicts
    return [200, DEVICES.map((d) => (many && d.conflict_count ? { ...d, conflict_count: 15 } : d))]
  }
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
    ]
  }
  // Go's ServeMux hands handlers the decoded path value, as this does.
  const m = decodeURIComponent(path).match(/^\/devices\/([^/]+)(?:\/(connections|dns|alerts))?$/)
  const device = m && DEVICES.find((d) => d.mac === m[1])
  if (!device) return [404, '{"error":"not found"}\n', 'text/plain; charset=utf-8']
  if (m[2] === 'alerts') {
    return [
      200,
      [1, 2, 3].map((i) => ({
        timestamp: new Date(state.base - (4 - i) * 3600_000).toISOString(),
        id: `DET-e2e-dev-${i}`,
        // The newest is an IDS alert: a summary and no observed domain.
        summary: i === 3 ? 'Suricata: ET POLICY outbound telnet' : `DNS query for dev${i}.example`,
        domain: i === 3 ? '' : `dev${i}.example`,
        query_type: i === 3 ? '' : 'A',
        matched_ioc: i === 3 ? '198.51.100.7' : `dev${i}.example`,
        severity: 'medium',
        source: i === 3 ? 'suricata' : 'threatfox',
      })),
    ]
  }
  if (m[2]) return [200, []]
  let conflicts = device.mac === 'aa:bb:cc:00:00:03' ? PRINTER_CONFLICTS : undefined
  if (conflicts && state.scenario.manyConflicts) {
    conflicts = Array.from({ length: 10 }, () => PRINTER_CONFLICTS[0])
  }
  return [200, { ...device, conflicts, conflict_count: conflicts?.length ?? 0 }]
}

/** feedback.go HandleFeedback, without persistence. */
function feedback(state: State, body: string, headers: http.IncomingHttpHeaders): Reply {
  let v: Record<string, unknown>
  try {
    v = JSON.parse(body)
  } catch {
    return [400, { error: 'invalid body' }]
  }
  const str = (k: string) => (typeof v[k] === 'string' ? (v[k] as string).trim() : '')
  const analyst = String(headers['x-netsoldier-actor'] ?? '') || str('analyst')
  let signalClass = str('signal_class')
  if (!signalClass && str('alert_id')) {
    const alert = state.alerts.find((a) => a.id === str('alert_id')) as { signal_class?: string }
    signalClass = alert?.signal_class ?? ''
  }
  const verdict = str('verdict')
  if (!str('matched_ioc')) return [400, { error: 'matched_ioc required' }]
  if (verdict !== 'false_positive' && verdict !== 'confirmed') {
    return [400, { error: 'verdict must be false_positive or confirmed' }]
  }
  if (!signalClass) {
    return [
      400,
      { error: 'signal_class required (or the alert_id of an alert this service still holds)' },
    ]
  }
  if (!analyst) return [400, { error: 'analyst required' }]
  const key = (ioc: string, client: string, cls: string) =>
    `${ioc.toLowerCase()}|${client.toLowerCase()}|${cls}`
  const ioc = str('matched_ioc')
  const client = str('client_ip')
  if (verdict === 'false_positive') {
    state.suppressions = state.suppressions.filter(
      (s) =>
        key(s.matched_ioc, s.client_ip ?? '', s.signal_class) !== key(ioc, client, signalClass),
    )
    state.suppressions.push({
      ...(str('alert_id') ? { alert_id: str('alert_id') } : {}),
      matched_ioc: ioc,
      ...(client ? { client_ip: client } : {}),
      signal_class: signalClass,
      verdict,
      ...(str('reason') ? { reason: str('reason') } : {}),
      analyst,
      timestamp: new Date().toISOString(),
    })
  } else {
    state.suppressions = state.suppressions.filter((s) => {
      if (s.signal_class !== signalClass || s.matched_ioc.toLowerCase() !== ioc.toLowerCase()) {
        return true
      }
      return client ? !!s.client_ip && s.client_ip !== client : false
    })
  }
  return [202, { status: 'recorded', persisted: state.scenario.persistFeedback }]
}

const SIGNAL_CLASSES = new Set(['ioc', 'ids-signature', 'tls', 'beacon', 'volumetric', 'composite'])

/** feedback.go HandleLift: ends exactly the one suppression named, 404 when none is in force. */
function lift(state: State, body: string, headers: http.IncomingHttpHeaders): Reply {
  let v: Record<string, unknown>
  try {
    v = JSON.parse(body)
  } catch {
    return [400, { error: 'invalid body' }]
  }
  const str = (k: string) => (typeof v[k] === 'string' ? (v[k] as string).trim() : '')
  const analyst = String(headers['x-netsoldier-actor'] ?? '') || str('analyst')
  const ioc = str('matched_ioc')
  const cls = str('signal_class')
  if (!ioc) return [400, { error: 'matched_ioc required' }]
  if (!cls) {
    return [
      400,
      { error: 'signal_class required (or the alert_id of an alert this service still holds)' },
    ]
  }
  if (!SIGNAL_CLASSES.has(cls))
    return [400, { error: `signal_class "${cls}" is not a signal class` }]
  if (!analyst) return [400, { error: 'analyst required' }]
  const key = (i: string, c: string, k: string) => `${i.toLowerCase()}|${c.toLowerCase()}|${k}`
  const want = key(ioc, str('client_ip'), cls)
  const before = state.suppressions.length
  state.suppressions = state.suppressions.filter(
    (s) => key(s.matched_ioc, s.client_ip ?? '', s.signal_class) !== want,
  )
  if (state.suppressions.length === before) {
    return [404, { error: 'no such suppression is in force' }]
  }
  return [200, { status: 'lifted', persisted: state.scenario.persistFeedback }]
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
        search: url.search,
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
        const [status, payload, type] = killswitch(
          state,
          method,
          url.pathname,
          url.searchParams,
          body,
          req.headers,
        )
        return send(res, status, wireReply(state, payload), type)
      }
      if (service === 'device-inventory') {
        const [status, payload, type] = deviceInventory(method, url.pathname, state)
        const total = String(state.scenario.deviceTotal ?? DEVICES.length)
        const headers: Record<string, string> =
          url.pathname === '/devices' ? { 'X-Total-Count': total } : {}
        return send(res, status, payload, type, headers)
      }
      if (method === 'GET' && url.pathname === '/alerts') {
        const limit = limitOf(url.searchParams, 1000, 5000)
        if (limit === null) return send(res, 400, { error: 'limit must be a positive integer' })
        return send(res, 200, state.alerts.slice(0, limit))
      }
      if (method === 'GET' && url.pathname === '/feedback') {
        return send(res, 200, state.listedSuppressions())
      }
      if (method === 'POST' && url.pathname === '/feedback') {
        const [status, payload] = feedback(state, body, req.headers)
        return send(res, status, payload)
      }
      if (method === 'POST' && url.pathname === '/feedback/lift') {
        const [status, payload] = lift(state, body, req.headers)
        return send(res, status, payload)
      }
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
    if (req.method === 'POST' && url.pathname === '/settle') {
      const { id, state: to } = JSON.parse(body) as { id: string; state?: string }
      return settle(state, id, to)
        ? send(res, 200, state.actions.get(id))
        : send(res, 409, { error: `${id} has nothing outstanding` })
    }
    if (req.method === 'POST' && url.pathname === '/begin-revert') {
      const { id, actor } = JSON.parse(body) as { id: string; actor?: string }
      return beginRevert(state, id, actor)
        ? send(res, 200, state.wire(state.actions.get(id)!))
        : send(res, 409, { error: `${id} is not enforced` })
    }
    // Replaces the suppressions in force, as if they had been made earlier
    // (or lifted behind the page's back, with an empty list).
    if (req.method === 'POST' && url.pathname === '/suppressions') {
      const seeded = JSON.parse(body) as SeededSuppression[]
      state.suppressions = seeded.map((s) => ({
        matched_ioc: s.matched_ioc,
        ...(s.client_ip ? { client_ip: s.client_ip } : {}),
        signal_class: s.signal_class,
        verdict: 'false_positive',
        ...(s.reason ? { reason: s.reason } : {}),
        analyst: s.analyst ?? 'Anna',
        timestamp: new Date(Date.now() - (s.ageMinutes ?? 60) * 60_000).toISOString(),
      }))
      return send(res, 200, state.listedSuppressions())
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
