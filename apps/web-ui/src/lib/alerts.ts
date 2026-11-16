import type { FeedbackVerdict } from './api'
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

// ── False-positive feedback (detection-engine internal/feedback) ──────

/**
 * How long a false-positive verdict suppresses, unless the engine was
 * started with another FEEDBACK_SUPPRESSION_TTL. The engine does not report
 * it, so this is the default, and the page says so.
 */
export const SUPPRESSION_DAYS = 30

/** The signal class a verdict on this alert is scoped to: the alert's own. */
export function alertSignalClass(a: Alert): string {
  return text(a.signal_class) || signalClasses(a)[0] || ''
}

/** The engine's suppression key: indicator, client and class, case-folded. */
function key(ioc: string | undefined, client: string | undefined, cls: string): string {
  return `${text(ioc).toLowerCase()}|${text(client).toLowerCase()}|${cls}`
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

/** The confirmation asked before a false-positive verdict. */
export function falsePositiveQuestion(a: Alert): string {
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
    `For ${SUPPRESSION_DAYS} days, detections of this indicator (${cls || 'this signal'}) on ` +
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

/** The verdict that lifts a suppression: the engine's "confirmed", which ends it. */
export function liftVerdict(s: Suppression): FeedbackVerdict {
  return {
    matched_ioc: s.matched_ioc,
    ...(s.client_ip ? { client_ip: s.client_ip } : {}),
    signal_class: s.signal_class,
    verdict: 'confirmed',
    reason: 'suppression lifted in the web UI',
  }
}

export function liftQuestion(s: Suppression): string {
  const where = s.client_ip ? `on ${s.client_ip}` : 'on every device'
  return [
    `Lift the suppression of ${s.matched_ioc} (${s.signal_class}) ${where}?`,
    '',
    'Detections of it reach the killswitch again from now on.',
    'The engine records this as a "confirmed" verdict, which ends this suppression' +
      (s.client_ip
        ? ' and any for the same indicator and signal on every device.'
        : ' and every one for the same indicator and signal on a single device.'),
  ].join('\n')
}
