import type { Alert, AlertSignal, DeviceAlert } from './types'

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
