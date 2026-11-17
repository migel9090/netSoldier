import type {
  CaptureStatus,
  DetectionHealth,
  DnsStatus,
  EngineIntel,
  EnforcementHealth,
  FeedSource,
  Recent,
  SensorSource,
  ServiceProbe,
  StatusService,
  SystemStatus,
  ThreatIntelStatus,
} from '#lib/status.ts'
import type { Config } from './config'
import { MAX_METRICS_BYTES, byLabel, parseMetrics, single, type Series } from './promtext'
import { callUpstream } from './upstream'

/**
 * GET /api/status, composed on the server from what each service exposes
 * about itself: /healthz, /readyz and a handful of /metrics series. None of
 * the services has a status endpoint, so this is the only way an operator
 * without Grafana learns whether the sensors and feeds are delivering. The
 * browser gets the curated result only — never a key, never raw metrics.
 *
 * Read: killswitch /healthz and /metrics; detection-engine /healthz and
 * /metrics; device-inventory /readyz and /metrics; threat-intel-sync (only
 * when THREAT_INTEL_URL is set) /readyz and /metrics. The metric names are
 * the services' own (see each service's metrics declarations); a series a
 * service does not export comes back as null.
 *
 * A failed read here is shown on the page and not counted in
 * netsoldier_webui_upstream_errors_total: that counter is about the proxy
 * the approval pages depend on, and an optional service being down must not
 * look like the killswitch refusing the UI.
 */

/** Per call; the page refreshes every 30 s and must not hang on one service. */
export const STATUS_TIMEOUT_MS = 5_000
const MAX_PROBE_BYTES = 64 * 1024

type Got = { ok: true; status: number; text: string } | { ok: false; error: string }

async function get(
  url: string,
  headers: Record<string, string>,
  maxBytes: number,
  fetchImpl: typeof callUpstream,
): Promise<Got> {
  let res: Response
  try {
    res = await fetchImpl(url, { headers, timeoutMs: STATUS_TIMEOUT_MS })
  } catch (err) {
    const timedOut = err instanceof Error && err.name === 'AbortError'
    return { ok: false, error: timedOut ? 'timed out' : 'unreachable' }
  }
  const length = Number(res.headers.get('content-length') ?? 0)
  if (length > maxBytes) {
    await res.body?.cancel()
    return { ok: false, error: 'answered with too much data' }
  }
  const reader = res.body?.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > maxBytes) {
        await reader.cancel()
        return { ok: false, error: 'answered with too much data' }
      }
      chunks.push(value)
    }
  }
  return { ok: true, status: res.status, text: Buffer.concat(chunks).toString('utf8') }
}

function refusal(status: number, keyVar?: string): string {
  if ((status === 401 || status === 403) && keyVar) {
    return `refused the web UI's credentials (HTTP ${status}); check ${keyVar}`
  }
  return `answered HTTP ${status}`
}

// ── Counters over a recent stretch ────────────────────────────────────

interface Point {
  at: number
  value: number
}

/**
 * The services' counters only count since they started. To say "in the
 * last few minutes", the UI keeps the values it read before and takes the
 * difference: against the oldest read in the last five minutes that is at
 * least 20 s old. A counter that went down was reset by a restart; the new
 * value is then all there is.
 */
export class RecentCounters {
  private readonly points = new Map<string, Point[]>()

  constructor(
    readonly windowMs = 5 * 60_000,
    readonly minSpanMs = 20_000,
    readonly maxPoints = 120,
  ) {}

  observe(key: string, value: number | null, now: number): Recent | null {
    if (value === null || !Number.isFinite(value)) return null
    const kept = (this.points.get(key) ?? []).filter((p) => now - p.at <= this.windowMs)
    const base = kept.find((p) => now - p.at >= this.minSpanMs)
    // Reads closer together than a few seconds (several tabs) add nothing.
    const last = kept.at(-1)
    if (last && now - last.at < 5_000) kept[kept.length - 1] = { at: now, value }
    else kept.push({ at: now, value })
    this.points.set(key, kept.slice(-this.maxPoints))
    if (!base) return null
    const delta = value >= base.value ? value - base.value : value
    return { seconds: Math.round((now - base.at) / 1000), value: delta }
  }

  reset(): void {
    this.points.clear()
  }
}

export const recentCounters = new RecentCounters()

// ── From what each service reports ────────────────────────────────────

const unixToISO = (v: number | null): string | null =>
  v === null || v <= 0 ? null : new Date(v * 1000).toISOString()

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const str = (v: unknown): string => (typeof v === 'string' ? v : '')

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v)

const sum = (m: Map<string, number>): number | null =>
  m.size === 0 ? null : [...m.values()].reduce((a, b) => a + b, 0)

export const DEVICE_INVENTORY_METRICS = new Set([
  'device_inventory_capture_up',
  'device_inventory_known_devices',
  'device_inventory_last_device_event_timestamp_seconds',
  'device_inventory_agent_frames_dropped',
  'device_inventory_frames_received_total',
])

/** device-inventory /readyz ({status, agent}) and its metrics. */
export function captureFrom(
  readyz: unknown,
  metrics: Series | null,
  recent: RecentCounters,
  now: number,
): CaptureStatus | null {
  if (!isObject(readyz)) return null
  const body = readyz as { status?: unknown; agent?: unknown }
  const agent = (typeof body.agent === 'object' && body.agent !== null ? body.agent : {}) as Record<
    string,
    unknown
  >
  const ready = body.status === 'ready'
  const agentReady = agent.ready === true
  const capture: Record<string, boolean> = {}
  if (typeof agent.capture === 'object' && agent.capture !== null) {
    for (const [k, v] of Object.entries(agent.capture as Record<string, unknown>)) {
      if (typeof v === 'boolean') capture[k] = v
    }
  }
  const lastSeen = str(agent.last_seen) && !Number.isNaN(Date.parse(str(agent.last_seen)))
  const frames = metrics
    ? sum(byLabel(metrics, 'device_inventory_frames_received_total', 'proto'))
    : null
  return {
    ready,
    agentReady,
    agent: str(agent.agent),
    interface: str(agent.interface),
    lastSeen: lastSeen ? str(agent.last_seen) : null,
    ageSeconds: lastSeen ? num(agent.age_seconds) : null,
    capture,
    expected: metrics
      ? [...byLabel(metrics, 'device_inventory_capture_up', 'proto').keys()].sort()
      : [],
    dropped: num(agent.dropped),
    reason: str(agent.reason),
    // Ready while the agent is not: readiness does not wait for an agent,
    // which device-inventory does only with NETAGENT_EXPECT_CAPTURE=none.
    required: ready && !agentReady ? false : !ready ? true : null,
    knownDevices: metrics ? single(metrics, 'device_inventory_known_devices') : null,
    lastSighting: metrics
      ? unixToISO(single(metrics, 'device_inventory_last_device_event_timestamp_seconds'))
      : null,
    framesRecent: recent.observe('device-inventory:frames', frames, now),
  }
}

export const DETECTION_ENGINE_METRICS = new Set([
  'detection_engine_querylog_pages_total',
  'detection_engine_poll_errors_total',
  'detection_engine_querylog_gaps_total',
  'detection_engine_queries_checked_total',
  'detection_engine_threatlist_domains_total',
  'detection_engine_sensor_cursor_lag_seconds',
  'detection_engine_sensor_rows_ingested_total',
  'detection_engine_sensor_ingest_errors_total',
  'detection_engine_ioc_sync_last_success_timestamp_seconds',
  'detection_engine_ioc_sync_indicators',
  'detection_engine_ioc_sync_failures_total',
  'detection_engine_store_durable',
  'detection_engine_outbox_backlog',
  'detection_engine_outbox_oldest_age_seconds',
  'detection_engine_active_suppressions',
])

export function dnsFrom(m: Series, recent: RecentCounters, now: number): DnsStatus {
  const pages = single(m, 'detection_engine_querylog_pages_total')
  const errors = single(m, 'detection_engine_poll_errors_total')
  const queries = single(m, 'detection_engine_queries_checked_total')
  return {
    pagesRead: pages,
    pollErrors: errors,
    gaps: single(m, 'detection_engine_querylog_gaps_total'),
    queriesChecked: queries,
    threatlistSize: single(m, 'detection_engine_threatlist_domains_total'),
    pagesRecent: recent.observe('detection-engine:querylog_pages', pages, now),
    errorsRecent: recent.observe('detection-engine:poll_errors', errors, now),
    queriesRecent: recent.observe('detection-engine:queries_checked', queries, now),
  }
}

/** One entry per source the engine reports a cursor lag for (only polled sources have one). */
export function sensorsFrom(m: Series, recent: RecentCounters, now: number): SensorSource[] {
  const lag = byLabel(m, 'detection_engine_sensor_cursor_lag_seconds', 'source')
  const rows = byLabel(m, 'detection_engine_sensor_rows_ingested_total', 'source')
  const errors = byLabel(m, 'detection_engine_sensor_ingest_errors_total', 'source')
  const names = [...new Set([...lag.keys(), ...rows.keys(), ...errors.keys()])].sort()
  return names.map((source) => ({
    source,
    lagSeconds: lag.get(source) ?? null,
    rows: rows.get(source) ?? null,
    errors: errors.get(source) ?? 0,
    rowsRecent: recent.observe(`detection-engine:rows:${source}`, rows.get(source) ?? null, now),
    errorsRecent: recent.observe(`detection-engine:errors:${source}`, errors.get(source) ?? 0, now),
  }))
}

export function detectionFrom(m: Series): DetectionHealth {
  const durable = single(m, 'detection_engine_store_durable')
  return {
    durable: durable === null ? null : durable === 1,
    backlog: single(m, 'detection_engine_outbox_backlog'),
    backlogOldestSeconds: single(m, 'detection_engine_outbox_oldest_age_seconds'),
    activeSuppressions: single(m, 'detection_engine_active_suppressions'),
  }
}

export function engineIntelFrom(m: Series): EngineIntel {
  return {
    lastSuccess: unixToISO(single(m, 'detection_engine_ioc_sync_last_success_timestamp_seconds')),
    indicators: single(m, 'detection_engine_ioc_sync_indicators'),
    failures: Object.fromEntries(byLabel(m, 'detection_engine_ioc_sync_failures_total', 'reason')),
  }
}

export const THREAT_INTEL_METRICS = new Set([
  'threat_intel_source_enabled',
  'threat_intel_source_last_success_timestamp_seconds',
  'threat_intel_source_indicators',
  'threat_intel_source_failures_total',
  'threat_intel_store_indicators',
  'threat_intel_store_capacity',
  'threat_intel_store_persistent',
  'threat_intel_sync_cycle_last_complete_timestamp_seconds',
  'threat_intel_ready',
])

/** threat-intel-sync /readyz ({status, indicators, reason}) and its metrics; either may be missing. */
export function threatIntelFrom(readyz: unknown, m: Series | null): ThreatIntelStatus {
  const body = (isObject(readyz) ? readyz : {}) as Record<string, unknown>
  const enabled = m ? byLabel(m, 'threat_intel_source_enabled', 'source') : new Map()
  const last = m
    ? byLabel(m, 'threat_intel_source_last_success_timestamp_seconds', 'source')
    : new Map()
  const indicators = m ? byLabel(m, 'threat_intel_source_indicators', 'source') : new Map()
  const failures = m ? byLabel(m, 'threat_intel_source_failures_total', 'source') : new Map()
  const sources: FeedSource[] = [...enabled.keys()].sort().map((source) => ({
    source,
    enabled: enabled.get(source) === 1,
    lastSuccess: unixToISO(last.get(source) ?? null),
    indicators: indicators.get(source) ?? null,
    failures: failures.get(source) ?? null,
  }))
  const readyMetric = m ? single(m, 'threat_intel_ready') : null
  const persistent = m ? single(m, 'threat_intel_store_persistent') : null
  return {
    ready:
      body.status === 'ready'
        ? true
        : body.status === 'not ready'
          ? false
          : readyMetric === null
            ? null
            : readyMetric === 1,
    reason: str(body.reason),
    indicators: num(body.indicators) ?? (m ? single(m, 'threat_intel_store_indicators') : null),
    capacity: m ? single(m, 'threat_intel_store_capacity') : null,
    persistent: persistent === null ? null : persistent === 1,
    lastCycle: m
      ? unixToISO(single(m, 'threat_intel_sync_cycle_last_complete_timestamp_seconds'))
      : null,
    sources,
  }
}

export const KILLSWITCH_METRICS = new Set([
  'killswitch_actions_pending',
  'killswitch_actions_active',
  'killswitch_actions_revert_failed',
  'killswitch_actions_awaiting_confirmation',
  'killswitch_agent_last_poll_timestamp_seconds',
  'killswitch_audit_outbox_pending',
  'killswitch_audit_outbox_oldest_age_seconds',
])

export function enforcementFrom(m: Series): EnforcementHealth {
  return {
    pending: single(m, 'killswitch_actions_pending'),
    active: single(m, 'killswitch_actions_active'),
    revertFailed: single(m, 'killswitch_actions_revert_failed'),
    awaitingConfirmation: single(m, 'killswitch_actions_awaiting_confirmation'),
    agentLastPoll: unixToISO(single(m, 'killswitch_agent_last_poll_timestamp_seconds')),
    auditOutboxPending: single(m, 'killswitch_audit_outbox_pending'),
    auditOutboxOldestSeconds: single(m, 'killswitch_audit_outbox_oldest_age_seconds'),
  }
}

// ── Gathering ─────────────────────────────────────────────────────────

interface Target {
  service: StatusService
  url: string
  urlVar: string
  key?: string
  keyVar?: string
  /** /healthz for liveness, or /readyz when its body says more. */
  probe: '/healthz' | '/readyz'
  wanted: ReadonlySet<string>
}

interface Read {
  probe: ServiceProbe
  /** The probe's JSON body, when it had one. */
  body: unknown
  metrics: Series | null
}

function parseJSON(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

async function read(t: Target, actor: string, fetchImpl: typeof callUpstream): Promise<Read> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (t.key) {
    headers.Authorization = `Bearer ${t.key}`
    headers['X-Netsoldier-Actor'] = actor
  }
  const [probe, metrics] = await Promise.all([
    get(`${t.url}${t.probe}`, headers, MAX_PROBE_BYTES, fetchImpl),
    get(`${t.url}/metrics`, { ...headers, Accept: 'text/plain' }, MAX_METRICS_BYTES, fetchImpl),
  ])
  const problems: string[] = []
  let up: boolean | null = null
  let body: unknown = null
  if (!probe.ok) {
    problems.push(`${t.probe}: ${probe.error}`)
    up = false
  } else {
    body = parseJSON(probe.text)
    // /readyz answers 503 with its readiness body while not ready: the
    // service is up, and the body says why it is not ready. Any other
    // answer is not one to read anything from.
    const readiness = isObject(body) && typeof body.status === 'string'
    up = probe.status < 300 || (t.probe === '/readyz' && probe.status === 503 && readiness)
    if (!up) {
      problems.push(`${t.probe}: ${refusal(probe.status, t.keyVar)}`)
      body = null
    }
  }
  let series: Series | null = null
  if (!metrics.ok) problems.push(`/metrics: ${metrics.error}`)
  else if (metrics.status >= 300) problems.push(`/metrics: ${refusal(metrics.status, t.keyVar)}`)
  else series = parseMetrics(metrics.text, t.wanted)
  return {
    probe: {
      service: t.service,
      configured: true,
      urlVar: t.urlVar,
      up,
      metrics: series !== null,
      error: problems.join('; '),
    },
    body,
    metrics: series,
  }
}

export interface GatherOptions {
  fetchImpl?: typeof callUpstream
  recent?: RecentCounters
  now?: () => number
}

export async function gatherStatus(
  config: Config,
  actor: string,
  opts: GatherOptions = {},
): Promise<SystemStatus> {
  const fetchImpl = opts.fetchImpl ?? callUpstream
  const recent = opts.recent ?? recentCounters
  const now = opts.now ?? Date.now
  const u = config.upstreams
  const target = (
    service: 'killswitch' | 'detection-engine' | 'device-inventory',
    probe: Target['probe'],
    wanted: ReadonlySet<string>,
  ): Target => ({
    service,
    url: u[service].url,
    urlVar: u[service].urlVar,
    key: u[service].key,
    keyVar: u[service].keyVar,
    probe,
    wanted,
  })

  const ti = config.threatIntel
  const [ks, de, di, tis] = await Promise.all([
    read(target('killswitch', '/healthz', KILLSWITCH_METRICS), actor, fetchImpl),
    read(target('detection-engine', '/healthz', DETECTION_ENGINE_METRICS), actor, fetchImpl),
    read(target('device-inventory', '/readyz', DEVICE_INVENTORY_METRICS), actor, fetchImpl),
    ti
      ? read(
          {
            service: 'threat-intel-sync',
            url: ti.url,
            urlVar: ti.urlVar,
            probe: '/readyz',
            wanted: THREAT_INTEL_METRICS,
          },
          actor,
          fetchImpl,
        )
      : null,
  ])

  const at = now()
  const tiProbe: ServiceProbe = tis?.probe ?? {
    service: 'threat-intel-sync',
    configured: false,
    urlVar: 'THREAT_INTEL_URL',
    up: null,
    metrics: false,
    error: '',
  }
  return {
    generatedAt: new Date(at).toISOString(),
    services: [ks.probe, de.probe, di.probe, tiProbe],
    capture: di.body !== null ? captureFrom(di.body, di.metrics, recent, at) : null,
    dns: de.metrics ? dnsFrom(de.metrics, recent, at) : null,
    sensors: de.metrics ? sensorsFrom(de.metrics, recent, at) : null,
    detection: de.metrics ? detectionFrom(de.metrics) : null,
    engineIntel: de.metrics ? engineIntelFrom(de.metrics) : null,
    threatIntel:
      tis && (tis.body !== null || tis.metrics !== null)
        ? threatIntelFrom(tis.body, tis.metrics)
        : null,
    enforcement: ks.metrics ? enforcementFrom(ks.metrics) : null,
    notes: config.notes,
  }
}
