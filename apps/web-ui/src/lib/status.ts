/**
 * GET /api/status: what the services report about themselves, gathered by
 * the web UI's server (src/lib/server/status.ts) from their probes and
 * /metrics, which the browser never reaches. Every value a service did not
 * report is null, never 0: "no heartbeat" and "unknown" must not look alike.
 */

export type StatusService =
  'killswitch' | 'detection-engine' | 'device-inventory' | 'threat-intel-sync'

export interface ServiceProbe {
  service: StatusService
  /** False only for threat-intel-sync, which the UI can run without. */
  configured: boolean
  /** The env var that names it, for messages. */
  urlVar: string
  /** Its liveness (or readiness) probe answered 2xx; null when not asked. */
  up: boolean | null
  /** Its /metrics could be read. */
  metrics: boolean
  /** Why something could not be read; '' when all was. */
  error: string
}

/** Counts over a recent stretch, measured by the UI between two reads of a counter. */
export interface Recent {
  /** How long the stretch was. */
  seconds: number
  value: number
}

export interface CaptureStatus {
  /** device-inventory's readiness (/readyz). */
  ready: boolean
  agentReady: boolean
  agent: string
  interface: string
  lastSeen: string | null
  ageSeconds: number | null
  /** What the agent says it captures, by protocol. */
  capture: Record<string, boolean>
  /** Protocols device-inventory expects (from capture_up); empty when unknown. */
  expected: string[]
  dropped: number | null
  /** device-inventory's reason when the agent is not healthy. */
  reason: string
  /**
   * False: device-inventory is ready without an agent
   * (NETAGENT_EXPECT_CAPTURE=none). Null: cannot be told.
   */
  required: boolean | null
  knownDevices: number | null
  /** The newest sighting the inventory accepted. */
  lastSighting: string | null
  framesRecent: Recent | null
}

export interface DnsStatus {
  pagesRead: number | null
  pollErrors: number | null
  gaps: number | null
  queriesChecked: number | null
  /** Indicators the engine matches DNS names against. */
  threatlistSize: number | null
  pagesRecent: Recent | null
  errorsRecent: Recent | null
  queriesRecent: Recent | null
}

export interface SensorSource {
  /** The ClickHouse table: suricata_alerts, zeek_intel, zeek_ssl, ml_beacons, ml_anomalies. */
  source: string
  lagSeconds: number | null
  rows: number | null
  errors: number | null
  rowsRecent: Recent | null
  errorsRecent: Recent | null
}

export interface EngineIntel {
  /** Last successful sync from threat-intel-sync; null when none since the engine started. */
  lastSuccess: string | null
  indicators: number | null
  failures: Record<string, number>
}

export interface FeedSource {
  source: string
  enabled: boolean
  lastSuccess: string | null
  indicators: number | null
  failures: number | null
}

export interface ThreatIntelStatus {
  ready: boolean | null
  reason: string
  indicators: number | null
  capacity: number | null
  persistent: boolean | null
  lastCycle: string | null
  sources: FeedSource[]
}

export interface DetectionHealth {
  /** 1: alerts, the outbox and verdicts are on disk; 0: in memory only. */
  durable: boolean | null
  /** Detections not yet acknowledged by the killswitch. */
  backlog: number | null
  backlogOldestSeconds: number | null
  activeSuppressions: number | null
}

export interface EnforcementHealth {
  pending: number | null
  active: number | null
  revertFailed: number | null
  awaitingConfirmation: number | null
  /** The netagent's last poll for isolations; null when never since the killswitch started. */
  agentLastPoll: string | null
  auditOutboxPending: number | null
  auditOutboxOldestSeconds: number | null
}

export interface SystemStatus {
  generatedAt: string
  services: ServiceProbe[]
  capture: CaptureStatus | null
  dns: DnsStatus | null
  /** Null when the detection engine's metrics could not be read. */
  sensors: SensorSource[] | null
  detection: DetectionHealth | null
  engineIntel: EngineIntel | null
  /** Null when threat-intel-sync is not configured or could not be read. */
  threatIntel: ThreatIntelStatus | null
  enforcement: EnforcementHealth | null
  /** Problems with optional web UI settings. */
  notes: string[]
}

// ── In words ──────────────────────────────────────────────────────────

/** "4 s", "3 min", "2 h", "5 days". */
export function durationWords(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 90) return `${s} s`
  const min = Math.round(s / 60)
  if (min < 90) return `${min} min`
  const h = Math.round(s / 3600)
  if (h < 36) return `${h} h`
  return `${Math.round(s / 86400)} days`
}

/** Seconds from `iso` to `now`; null when there is no time. */
export function ageOf(iso: string | null, now = Date.now()): number | null {
  const t = iso ? Date.parse(iso) : NaN
  return Number.isNaN(t) ? null : Math.max(0, (now - t) / 1000)
}

export function agoWords(iso: string | null, now = Date.now()): string {
  const age = ageOf(iso, now)
  return age === null ? 'never' : `${durationWords(age)} ago`
}

/** "1 page", "3 pages". */
export function countWords(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? '' : 's'}`
}

/** "12 frames in the last 2 min"; '' when nothing was measured. */
export function recentWords(r: Recent | null, unit: string): string {
  if (!r) return ''
  return `${countWords(r.value, unit)} in the last ${durationWords(r.seconds)}`
}

export type Verdict = 'ok' | 'warn' | 'fail' | 'unknown' | 'off'

export interface Finding {
  verdict: Verdict
  /** One line for the summary. */
  text: string
}

/**
 * How far behind a sensor source may be before it is called behind: the
 * engine polls every 30 s by default (SENSOR_POLL_INTERVAL), and the lag is
 * about one interval while it keeps up.
 */
export const SENSOR_LAG_WARN_SECONDS = 300
/** threat-intel-sync fetches every 6 h by default (SYNC_INTERVAL); two missed cycles are stale. */
export const FEED_STALE_SECONDS = 12 * 3600
/** The engine pulls threat-intel-sync's export every 5 min by default (IOC_SYNC_INTERVAL). */
export const ENGINE_INTEL_STALE_SECONDS = 30 * 60

/** Does the system see the network? Device discovery through the network agent. */
export function captureFinding(c: CaptureStatus | null, probe?: ServiceProbe): Finding {
  if (!c) {
    return {
      verdict: 'unknown',
      text: `Unknown: device-inventory could not be read${probe?.error ? ` (${probe.error})` : ''}.`,
    }
  }
  const protocols = Object.entries(c.capture)
    .filter(([, up]) => up)
    .map(([p]) => p)
    .sort()
  if (c.agentReady) {
    const where = c.interface ? ` on ${c.interface}` : ''
    const age = c.ageSeconds === null ? '' : `, last heard ${durationWords(c.ageSeconds)} ago`
    return {
      verdict: 'ok',
      text:
        `Seeing the network: the network agent${c.agent ? ` ${c.agent}` : ''}${where} is reporting${age}` +
        (protocols.length ? `, capturing ${protocols.join(', ')}.` : '.'),
    }
  }
  if (c.required === false) {
    return {
      verdict: 'off',
      text:
        'No network agent is expected in this installation (NETAGENT_EXPECT_CAPTURE=none): ' +
        'devices are only seen through other sources.' +
        (c.reason ? ` device-inventory says: ${c.reason}.` : ''),
    }
  }
  return {
    verdict: 'fail',
    text: `NOT seeing the network: ${c.reason || 'the network agent is not healthy'}.`,
  }
}

/** Is AdGuard's query log being read? */
export function dnsFinding(d: DnsStatus | null, probe?: ServiceProbe): Finding {
  if (!d) {
    return {
      verdict: 'unknown',
      text: `Unknown: the detection engine's metrics could not be read${probe?.error ? ` (${probe.error})` : ''}.`,
    }
  }
  if (d.pagesRecent && d.errorsRecent) {
    if (d.pagesRecent.value > 0) {
      return {
        verdict: d.errorsRecent.value > 0 ? 'warn' : 'ok',
        text:
          `DNS lookups are being checked: ${countWords(d.pagesRecent.value, 'query-log page')} read ` +
          `in the last ${durationWords(d.pagesRecent.seconds)}` +
          (d.errorsRecent.value > 0
            ? `, ${countWords(d.errorsRecent.value, 'failed poll')}.`
            : '.'),
      }
    }
    if (d.errorsRecent.value > 0) {
      return {
        verdict: 'fail',
        text: `NOT reading DNS: every poll of AdGuard's query log failed in the last ${durationWords(d.errorsRecent.seconds)}.`,
      }
    }
    return {
      verdict: 'warn',
      text: `No query-log page read in the last ${durationWords(d.pagesRecent.seconds)} (no AdGuard configured, or the engine is stuck).`,
    }
  }
  // Only the totals since the engine started: no stretch measured yet.
  if (d.pagesRead === null) {
    return { verdict: 'unknown', text: 'The detection engine does not report its query-log reads.' }
  }
  if (d.pagesRead === 0) {
    return {
      verdict: (d.pollErrors ?? 0) > 0 ? 'fail' : 'warn',
      text:
        (d.pollErrors ?? 0) > 0
          ? `NOT reading DNS: no query-log page read since the engine started, ${d.pollErrors} failed polls.`
          : 'No query-log page read since the engine started (no AdGuard configured, or it has only just started).',
    }
  }
  return {
    verdict: (d.pollErrors ?? 0) > 0 ? 'warn' : 'ok',
    text:
      `${d.pagesRead} query-log pages read since the engine started` +
      ((d.pollErrors ?? 0) > 0 ? `, ${d.pollErrors} failed polls.` : '.') +
      ' Recent activity shows on the next refresh.',
  }
}

export function sensorVerdict(s: SensorSource): Verdict {
  if (s.lagSeconds === null) return 'unknown'
  if ((s.errorsRecent?.value ?? 0) > 0) return 'warn'
  return s.lagSeconds > SENSOR_LAG_WARN_SECONDS ? 'warn' : 'ok'
}

export function sensorsFinding(sensors: SensorSource[] | null, probe?: ServiceProbe): Finding {
  if (!sensors) {
    return {
      verdict: 'unknown',
      text: `Unknown: the detection engine's metrics could not be read${probe?.error ? ` (${probe.error})` : ''}.`,
    }
  }
  if (sensors.length === 0) {
    return {
      verdict: 'off',
      text:
        'No packet sensor is read: the detection engine reports no sensor source (no ClickHouse in ' +
        'this installation, or it has not polled yet).',
    }
  }
  const behind = sensors.filter((s) => sensorVerdict(s) !== 'ok').map((s) => s.source)
  return behind.length === 0
    ? { verdict: 'ok', text: `All ${sensors.length} sensor sources are keeping up.` }
    : { verdict: 'warn', text: `Behind or failing: ${behind.join(', ')}.` }
}

export function feedVerdict(f: FeedSource, now = Date.now()): Verdict {
  if (!f.enabled) return 'off'
  const age = ageOf(f.lastSuccess, now)
  if (age === null) return 'fail'
  return age > FEED_STALE_SECONDS ? 'warn' : 'ok'
}

export function intelFinding(
  engine: EngineIntel | null,
  ti: ThreatIntelStatus | null,
  tiProbe?: ServiceProbe,
  now = Date.now(),
): Finding {
  const engineAge = ageOf(engine?.lastSuccess ?? null, now)
  const engineWords = engine
    ? engineAge === null
      ? 'the detection engine has not loaded a feed set since it started'
      : `the detection engine loaded ${engine.indicators ?? '?'} indicators ${durationWords(engineAge)} ago`
    : "the detection engine's metrics could not be read"
  if (tiProbe && !tiProbe.configured) {
    return {
      verdict: engineAge === null ? 'warn' : engineAge > ENGINE_INTEL_STALE_SECONDS ? 'warn' : 'ok',
      text: `Feeds: ${engineWords}. threat-intel-sync is not read by the web UI (${tiProbe.urlVar} is not set).`,
    }
  }
  if (!ti) {
    return {
      verdict: 'unknown',
      text: `Feeds: threat-intel-sync could not be read${tiProbe?.error ? ` (${tiProbe.error})` : ''}; ${engineWords}.`,
    }
  }
  const failing = ti.sources.filter(
    (s) => feedVerdict(s, now) === 'fail' || feedVerdict(s, now) === 'warn',
  )
  const verdict: Verdict =
    ti.ready === false ? 'fail' : failing.length > 0 || engineAge === null ? 'warn' : 'ok'
  const head =
    ti.ready === false
      ? `threat-intel-sync is NOT ready${ti.reason ? `: ${ti.reason}` : ''}`
      : `threat-intel-sync holds ${ti.indicators ?? '?'} indicators`
  return {
    verdict,
    text:
      `Feeds: ${head}` +
      (failing.length
        ? `; stale or never synced: ${failing.map((s) => s.source).join(', ')}`
        : '') +
      `; ${engineWords}.`,
  }
}
