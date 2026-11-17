import { formatTime, type FeedbackVerdict, type LiftRequest, type LiftResult } from './api'
import type { Alert, AlertSignal, DeviceAlert, Suppression } from './types'

/**
 * How an alert is shown, for both shapes of GET /alerts during the contract
 * v2 rollout. v2 alerts carry `summary`, the only field meant for display;
 * `domain` is the observed DNS name and is empty for IDS alerts, volumetric
 * anomalies and IP-only detections — showing `domain` as the headline left
 * those rows blank. Older engines send no summary, so the domain is the best
 * headline they offer.
 */

type Displayable = Pick<Alert, 'id' | 'summary' | 'domain' | 'matched_ioc' | 'threat'>

const text = (v: unknown): string => (typeof v === 'string' ? v.trim() : '')

/** Never empty. */
export function alertHeadline(a: Displayable | DeviceAlert): string {
  const d = a as Displayable
  return (
    text(d.summary) || text(d.domain) || text(d.matched_ioc) || text(d.threat) || `Alert ${a.id}`
  )
}

/** The observed domain when it adds to the headline, else ''. */
export function alertObservedDomain(a: Displayable | DeviceAlert): string {
  const domain = text(a.domain)
  return domain && alertHeadline(a) !== domain ? domain : ''
}

export interface AlertClient {
  name: string
  mac: string
  ip: string
}

export function alertClient(a: Alert): AlertClient {
  return { name: text(a.client_name), mac: text(a.client_mac), ip: text(a.client_ip) }
}

/** Text the device filter matches against: name, MAC and IP. */
export function alertClientText(a: Alert): string {
  const c = alertClient(a)
  return [c.name, c.mac, c.ip].join(' ').toLowerCase()
}

/** Signal classes, from v2 objects or the older plain strings. */
export function signalClasses(a: Alert): string[] {
  const raw: (AlertSignal | string)[] = Array.isArray(a.signals) ? a.signals : []
  const classes = raw
    .map((s) => (typeof s === 'string' ? s : s && typeof s === 'object' ? text(s.class) : ''))
    .filter(Boolean)
  if (classes.length === 0 && text(a.signal_class)) classes.push(text(a.signal_class))
  return [...new Set(classes)]
}

/** One signal of a detection, as the breakdown shows it; '' and null where it says nothing. */
export interface SignalRow {
  class: string
  confidence: number | null
  indicator: string
  indicatorType: string
  source: string
}

/**
 * What a detection is made of: each signal with its own class, confidence,
 * indicator and source. A composite (signal_class `composite`) combines
 * corroborating signals about one device, and its confidence is the
 * combination's, not any one signal's. Older engines send the classes as
 * plain strings, which give the class alone.
 */
export function signalBreakdown(a: Pick<Alert, 'signals' | 'signal_class'>): SignalRow[] {
  const raw: (AlertSignal | string)[] = Array.isArray(a.signals) ? a.signals : []
  const rows: SignalRow[] = []
  for (const s of raw) {
    if (typeof s === 'string') {
      if (text(s))
        rows.push({
          class: text(s),
          confidence: null,
          indicator: '',
          indicatorType: '',
          source: '',
        })
      continue
    }
    if (!s || typeof s !== 'object' || !text(s.class)) continue
    rows.push({
      class: text(s.class),
      confidence:
        typeof s.confidence === 'number' && Number.isFinite(s.confidence) ? s.confidence : null,
      indicator: text(s.indicator),
      indicatorType: text(s.indicator_type),
      source: text(s.source),
    })
  }
  return rows
}

export function isComposite(a: Pick<Alert, 'signal_class'>): boolean {
  return text(a.signal_class) === 'composite'
}

/** The alert with this id among `alerts`, if it is there. */
export function alertById<T extends Pick<Alert, 'id'>>(
  alerts: readonly T[],
  id: string,
): T | undefined {
  return id ? alerts.find((a) => a.id === id) : undefined
}

// ── False-positive feedback (detection-engine internal/feedback) ──────

/**
 * How long a false-positive verdict suppresses unless the engine was started
 * with another FEEDBACK_SUPPRESSION_TTL. Only used when nothing better is
 * known: GET /feedback gives each suppression's `expires_at`.
 */
export const SUPPRESSION_DAYS = 30

const DAY_MS = 24 * 3600_000

/** The signal class a verdict on this alert is scoped to: the alert's own. */
export function alertSignalClass(a: Alert): string {
  return text(a.signal_class) || signalClasses(a)[0] || ''
}

/** The engine's suppression key: indicator, client and class, case-folded. */
function key(ioc: string | undefined, client: string | undefined, cls: string): string {
  return `${text(ioc).toLowerCase()}|${text(client).toLowerCase()}|${cls}`
}

/**
 * True when the engine recorded this alert while a suppression applied: it
 * is in the history but never reached the killswitch. Only `true` counts;
 * engines that do not send the field mean "not suppressed".
 */
export function isSilenced(a: Pick<Alert, 'suppressed'>): boolean {
  return a.suppressed === true
}

/** When a suppression stops silencing, and whether that is only an estimate. */
export interface SuppressionEnd {
  at: string
  /** The engine sent no `expires_at` (it predates it): from the default TTL. */
  estimated: boolean
}

export function suppressionEnds(s: Suppression): SuppressionEnd | null {
  if (s.expires_at && !Number.isNaN(Date.parse(s.expires_at))) {
    return { at: s.expires_at, estimated: false }
  }
  const made = Date.parse(s.timestamp)
  if (Number.isNaN(made)) return null
  return { at: new Date(made + SUPPRESSION_DAYS * DAY_MS).toISOString(), estimated: true }
}

/**
 * How many days a new verdict will suppress for: the engine's TTL, read off
 * a suppression it reported (expires_at − timestamp), or null when none
 * says.
 */
export function suppressionDays(suppressions: readonly Suppression[]): number | null {
  for (const s of suppressions) {
    const ttl = Date.parse(s.expires_at ?? '') - Date.parse(s.timestamp)
    if (ttl > 0) return Math.max(1, Math.round(ttl / DAY_MS))
  }
  return null
}

/** "30 days", or "30 days (the detection engine's default)" when it is a guess. */
export function suppressionPeriod(days: number | null): string {
  return days === null
    ? `${SUPPRESSION_DAYS} days (the detection engine's default)`
    : `${days} day${days === 1 ? '' : 's'}`
}

/** FNV-1a: a short, stable, id-safe name for an anchor. */
function anchorHash(s: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

/** The element id of a suppression's row, for links to it. */
export function suppressionAnchor(s: Suppression): string {
  return `suppression-${anchorHash(key(s.matched_ioc, s.client_ip, s.signal_class))}`
}

/** The element id of an alert's row on the alerts page. */
export function alertAnchor(a: Pick<Alert, 'id'>): string {
  return `alert-${anchorHash(a.id)}`
}

/**
 * The suppression silencing this alert, if any: one for its client, else
 * one for the indicator on every device — the order the engine checks them.
 */
export function suppressionFor(
  a: Alert,
  suppressions: readonly Suppression[],
): Suppression | undefined {
  const cls = alertSignalClass(a)
  if (!text(a.matched_ioc) || !cls) return undefined
  const byKey = new Map(
    suppressions.map((s) => [key(s.matched_ioc, s.client_ip, s.signal_class), s]),
  )
  return byKey.get(key(a.matched_ioc, a.client_ip, cls)) ?? byKey.get(key(a.matched_ioc, '', cls))
}

/** The verdict "Mark FP" sends: this alert's indicator, device and signal class. */
export function falsePositiveVerdict(a: Alert): FeedbackVerdict {
  const cls = alertSignalClass(a)
  return {
    alert_id: a.id,
    matched_ioc: text(a.matched_ioc),
    ...(text(a.client_ip) ? { client_ip: text(a.client_ip) } : {}),
    ...(cls ? { signal_class: cls } : {}),
    verdict: 'false_positive',
  }
}

function deviceWords(name: string, ip: string): string {
  if (name) return ip ? `${name} (${ip})` : name
  return ip || 'every device'
}

/**
 * The confirmation asked before a false-positive verdict. `days`: how long
 * the engine suppresses (see suppressionDays), null when unknown.
 */
export function falsePositiveQuestion(a: Alert, days: number | null = null): string {
  const c = alertClient(a)
  const device = deviceWords(c.name, c.ip)
  const cls = alertSignalClass(a)
  const lines = [
    'Mark this detection as a false positive?',
    '',
    `Alert: ${alertHeadline(a)}`,
    `Indicator: ${text(a.matched_ioc) || '—'}`,
    `Signal: ${cls || 'unknown'}`,
    `Device: ${device}`,
    '',
    `For ${suppressionPeriod(days)}, detections of this indicator (${cls || 'this signal'}) on ` +
      `${device} are still listed here but no longer reach the killswitch: nothing will be ` +
      'blocked for them, even if the indicator turns out to be malicious after all.',
  ]
  if (cls === 'composite') {
    lines.push(
      '',
      'This is a combined detection: the verdict covers the combination only, and each of its ' +
        'signals is still judged on its own.',
    )
  }
  return lines.join('\n')
}

/** What "Lift" sends to POST /feedback/lift: exactly this suppression's key. */
export function liftRequest(s: Suppression): LiftRequest {
  return {
    matched_ioc: s.matched_ioc,
    ...(s.client_ip ? { client_ip: s.client_ip } : {}),
    signal_class: s.signal_class,
    reason: 'suppression lifted in the web UI',
  }
}

export interface Note {
  tone: 'ok' | 'warn' | 'fail'
  text: string
}

/** What a lift did, in words: ended, ended but not saved, or nothing to end. */
export function liftNote(s: Suppression, r: LiftResult): Note {
  const what = `the suppression of ${s.matched_ioc} (${s.signal_class}) ${suppressionScope(s)}`
  if (!r.inForce) {
    return {
      tone: 'warn',
      text: `Nothing to lift: ${what} was no longer in force (lifted already, or it expired).`,
    }
  }
  if (r.persisted === false) {
    const end = suppressionEnds(s)
    return {
      tone: 'warn',
      text:
        `Lifted ${what}. It applies now but was NOT saved: when the detection engine restarts, ` +
        `the suppression comes back${end ? ` (until ${formatTime(end.at)})` : ''}.`,
    }
  }
  return { tone: 'ok', text: `Lifted ${what}.${r.persisted ? ' Saved.' : ''}` }
}

/** GET /feedback comes in map order: newest first, stably. */
export function sortSuppressions(list: readonly Suppression[]): Suppression[] {
  return [...list].sort(
    (x, y) =>
      Date.parse(y.timestamp) - Date.parse(x.timestamp) ||
      x.matched_ioc.localeCompare(y.matched_ioc) ||
      (x.client_ip ?? '').localeCompare(y.client_ip ?? ''),
  )
}

/** Where a suppression applies, in words. */
export function suppressionScope(s: Pick<Suppression, 'client_ip'>): string {
  return s.client_ip ? `on ${s.client_ip}` : 'on every device'
}

/**
 * The confirmation asked before lifting. Lifting ends this one suppression
 * and says nothing about the indicator; `all` (the suppressions in force)
 * tells whether another one keeps silencing the same detections.
 */
export function liftQuestion(s: Suppression, all: readonly Suppression[] = []): string {
  const same = (o: Suppression) =>
    o !== s &&
    o.signal_class === s.signal_class &&
    text(o.matched_ioc).toLowerCase() === text(s.matched_ioc).toLowerCase()
  const end = suppressionEnds(s)
  const lines = [
    `Lift the suppression of ${s.matched_ioc} (${s.signal_class}) ${suppressionScope(s)}?`,
    '',
  ]
  const wide = s.client_ip ? all.find((o) => same(o) && !o.client_ip) : undefined
  if (wide) {
    lines.push(
      `${s.matched_ioc} is also suppressed on every device, and that suppression stays: ` +
        `detections of it on ${s.client_ip} keep being silenced until it ends too.`,
    )
  } else {
    lines.push(
      `Detections of it ${suppressionScope(s)} reach the killswitch again from now on, and can ` +
        'be blocked.',
    )
  }
  const narrow = s.client_ip ? [] : all.filter((o) => same(o) && o.client_ip)
  if (narrow.length > 0) {
    lines.push(
      `Its suppressions on single devices (${narrow.map((o) => o.client_ip).join(', ')}) stay ` +
        'in force: detections there stay silenced.',
    )
  }
  lines.push(
    'This ends only this suppression; it does not record the indicator as malicious.' +
      (end ? ` Otherwise it would end on ${formatTime(end.at)}.` : ''),
  )
  return lines.join('\n')
}
