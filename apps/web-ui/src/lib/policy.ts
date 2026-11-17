import { formatActionType } from './api'
import { ACTION_TYPE_ORDER } from './killswitch'
import type { Allowlist, Device, KillswitchPolicy } from './types'

/**
 * The killswitch policy (GET /policy, GET /allowlist) in words, for the
 * policy page: when it blocks on its own, when it asks, with what, and whom
 * it never touches.
 */

export interface PolicyRow {
  /** Stable key for tests and the table. */
  key: string
  label: string
  /** 'not reported' when the controller did not send it. */
  value: string
  detail: string
}

const NOT_REPORTED = 'not reported'

function isNum(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

/** "1 h", "24 h", "2 days", "90 s"; null for no value. */
export function secondsWords(s: unknown): string | null {
  if (!isNum(s) || s <= 0) return null
  if (s % 86400 === 0 && s >= 2 * 86400) return `${s / 86400} days`
  if (s % 3600 === 0) return `${s / 3600} h`
  if (s % 60 === 0) return `${s / 60} min`
  return `${s} s`
}

function bar(confidence: unknown, severity: unknown): string | null {
  if (!isNum(confidence) && typeof severity !== 'string') return null
  return `confidence ≥ ${isNum(confidence) ? confidence : '?'}, severity ≥ ${typeof severity === 'string' && severity ? severity : '?'}`
}

/** The thresholds and timings, in the order a detection meets them. */
export function policyRows(p: KillswitchPolicy): PolicyRow[] {
  const row = (key: string, label: string, value: string | null, detail: string): PolicyRow => ({
    key,
    label,
    value: value ?? NOT_REPORTED,
    detail,
  })
  return [
    row(
      'pend_min',
      'Proposed for approval at',
      bar(p.pend_min_confidence, p.pend_min_severity),
      'A detection below this is kept as an alert only; nothing is proposed.',
    ),
    row(
      'auto_min',
      'Blocked automatically at',
      bar(p.auto_min_confidence, p.auto_min_severity),
      'Only while automatic blocking is on and in effect. Everything else that is proposed waits for a person.',
    ),
    row(
      'auto_min_signals',
      'Combined detections need',
      isNum(p.auto_min_signals)
        ? `${p.auto_min_signals} signal class${p.auto_min_signals === 1 ? '' : 'es'}`
        : null,
      'A combined (composite) detection is blocked automatically only when this many different kinds of signal agree.',
    ),
    row(
      'auto_require_known_bad',
      'Automatic blocks need a known-bad indicator',
      typeof p.auto_require_known_bad === 'boolean'
        ? p.auto_require_known_bad
          ? 'yes'
          : 'no'
        : null,
      'A threat feed must vouch for the exact domain that is blocked; a heuristic alone never blocks on its own.',
    ),
    row(
      'auto_action_type',
      'Automatic blocks use',
      p.auto_action_type ? formatActionType(p.auto_action_type) : null,
      'The automatic path never takes a device off the network.',
    ),
    row(
      'default_action',
      'Proposals are made as',
      p.default_action ? formatActionType(p.default_action) : null,
      'Whoever approves can choose another available enforcement.',
    ),
    row(
      'default_ttl',
      'A block is lifted after',
      secondsWords(p.default_ttl),
      'Unless someone lifts it earlier.',
    ),
    row(
      'pending_ttl',
      'A proposal expires after',
      secondsWords(p.pending_ttl_seconds),
      'If nobody approves or rejects it by then.',
    ),
  ]
}

export interface ActionTypeRow {
  type: string
  name: string
  available: boolean
  /** The controller's reason when it is not available. */
  reason: string
  isDefault: boolean
}

/** Every action type the controller knows of, available or not, in order of strength. */
export function actionTypeRows(p: KillswitchPolicy): ActionTypeRow[] {
  const types = new Set<string>([
    ...ACTION_TYPE_ORDER,
    ...p.available_action_types,
    ...Object.keys(p.unavailable_action_types),
  ])
  const rank = (t: string) => {
    const i = (ACTION_TYPE_ORDER as readonly string[]).indexOf(t)
    return i < 0 ? ACTION_TYPE_ORDER.length : i
  }
  return [...types]
    .sort((x, y) => rank(x) - rank(y) || x.localeCompare(y))
    .map((type) => {
      const available = p.available_action_types.includes(type)
      return {
        type,
        name: formatActionType(type),
        available,
        reason: available
          ? ''
          : (p.unavailable_action_types[type] ?? 'not reported by the controller'),
        isDefault: p.default_action === type,
      }
    })
}

export interface ProtectedRow {
  kind: 'MAC' | 'IP' | 'network'
  value: string
  /** Device name from the inventory, '' when it has none. */
  name: string
}

/** The never-enforce list, with names from the inventory where an entry is a known device. */
export function protectedRows(list: Allowlist, devices: readonly Device[] = []): ProtectedRow[] {
  const byMac = new Map(devices.map((d) => [d.mac.toLowerCase(), d.hostname]))
  const byIp = new Map(devices.filter((d) => d.ip).map((d) => [d.ip, d.hostname]))
  const macs: ProtectedRow[] = list.macs.map((m) => ({
    kind: 'MAC',
    value: m,
    name: byMac.get(m.toLowerCase()) ?? '',
  }))
  const ips: ProtectedRow[] = list.ips.map((ip) =>
    ip.includes('/')
      ? { kind: 'network', value: ip, name: '' }
      : { kind: 'IP', value: ip, name: byIp.get(ip) ?? '' },
  )
  return [...macs, ...ips]
}

/** POLICY_AUTO_BLOCK as configured, in words; null when the controller does not say. */
export function autoBlockSettingWords(p: Pick<KillswitchPolicy, 'auto_block'>): string | null {
  if (p.auto_block === 'on') return 'on (POLICY_AUTO_BLOCK=on)'
  if (p.auto_block === 'off') return 'off (POLICY_AUTO_BLOCK=off)'
  return null
}
