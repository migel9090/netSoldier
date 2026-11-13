import type { ActionResult } from './api'
import { formatActionType } from './api'
import type { EnforcementAction } from './types'

/**
 * What an enforcement action means for the household, independent of which
 * controller version reported it (contract v2 §3 states, plus the legacy
 * single `failed` state).
 */

/**
 * The legacy controller records a failed revert as `failed` with a reason
 * starting "revert failed"; the block is still in place in that case.
 */
function isLegacyRevertFailure(a: EnforcementAction): boolean {
  return a.state === 'failed' && /^revert failed/i.test(a.failure_reason ?? '')
}

export type FailureKind = 'apply' | 'revert'

export function failureKind(a: EnforcementAction): FailureKind | null {
  if (a.state === 'revert_failed' || isLegacyRevertFailure(a)) return 'revert'
  if (a.state === 'apply_failed' || a.state === 'failed') return 'apply'
  return null
}

/** True while the block is in force: active, or a revert that did not lift it. */
export function isStillEnforced(a: EnforcementAction): boolean {
  return a.state === 'active' || failureKind(a) === 'revert'
}

export function isFailure(a: EnforcementAction): boolean {
  return failureKind(a) !== null
}

export function enforcedSince(a: EnforcementAction): string {
  return a.activated_at || a.timestamp
}

export function endedAt(a: EnforcementAction): string {
  return a.reverted_at || a.timestamp
}

export interface DeviceRef {
  name: string
  mac: string
  ip: string
}

/** Name from the action (v2) or, failing that, from the device inventory. */
export function deviceOf(a: EnforcementAction, names: ReadonlyMap<string, string>): DeviceRef {
  const mac = (a.target_mac ?? '').toLowerCase()
  return {
    name: a.client_name || names.get(mac) || '',
    mac: a.target_mac || '',
    ip: a.target_ip || '',
  }
}

export function describeDevice(d: DeviceRef): string {
  const ids = [d.mac, d.ip].filter(Boolean).join(', ')
  if (d.name) return ids ? `${d.name} (${ids})` : d.name
  return ids || 'an unidentified device'
}

/** What the block actually stops, in words, per action type. */
export function describeBlock(a: EnforcementAction): string {
  switch (a.action_type) {
    case 'dns_sinkhole':
      return a.blocked_domain
        ? `DNS lookups of ${a.blocked_domain} and its subdomains`
        : 'DNS lookups (no domain recorded on the action)'
    case 'arp_isolate':
      return "all of the device's traffic through the gateway (ARP isolation)"
    case 'switch_acl':
      return "the device's traffic at its switch port (switch ACL)"
    default:
      return a.action_type || 'unknown action type'
  }
}

/** The text of the approval confirmation: device, action and what it blocks. */
export function approveConfirmText(a: EnforcementAction, device: DeviceRef): string {
  const lines = [
    'Approve this enforcement action?',
    '',
    `Device: ${device.name || 'unknown name'}`,
    `MAC: ${device.mac || 'unknown'}`,
    `IP: ${device.ip || 'unknown'}`,
    `Action: ${formatActionType(a.action_type)}`,
    `Will block: ${describeBlock(a)}`,
  ]
  if (a.detection_summary) lines.push(`Detection: ${a.detection_summary}`)
  if (a.ttl_seconds) {
    lines.push(`Lifted automatically after: ${Math.round(a.ttl_seconds / 60)} min`)
  }
  lines.push('', `The block is applied immediately. (Action ${a.id})`)
  return lines.join('\n')
}

export type Verb = 'approve' | 'reject' | 'revert'
export type Tone = 'ok' | 'warn' | 'fail'

export interface Outcome {
  tone: Tone
  /** The state the controller reported, or "error" when it reported none. */
  state: string
  text: string
}

/**
 * What just happened, from the controller's answer — the state in the
 * response body, never the HTTP status alone.
 */
export function describeOutcome(
  verb: Verb,
  a: EnforcementAction,
  device: DeviceRef,
  result: ActionResult,
): Outcome {
  const who = describeDevice(device)
  const reported = result.action
  if (reported) {
    const reason = reported.failure_reason ? ` Reason: ${reported.failure_reason}` : ''
    const state = reported.state
    if (verb === 'approve') {
      if (state === 'active') {
        return {
          tone: 'ok',
          state,
          text: `Approved ${a.id}: ${describeBlock(reported)} is now blocked for ${who}.`,
        }
      }
      if (failureKind(reported) === 'apply') {
        return {
          tone: 'fail',
          state,
          text: `Approved ${a.id}, but the block could NOT be applied — nothing is enforced on ${who}.${reason}`,
        }
      }
      if (state === 'approved') {
        return {
          tone: 'warn',
          state,
          text: `Approved ${a.id}; the controller has not confirmed the block on ${who} yet.`,
        }
      }
    }
    if (verb === 'reject' && state === 'rejected') {
      return { tone: 'ok', state, text: `Rejected ${a.id}: nothing will be blocked on ${who}.` }
    }
    if (verb === 'revert') {
      if (state === 'reverted') {
        return { tone: 'ok', state, text: `Reverted ${a.id}: the block on ${who} is lifted.` }
      }
      if (isStillEnforced(reported)) {
        return {
          tone: 'fail',
          state,
          text: `Revert of ${a.id} FAILED — the block on ${who} is still in force.${reason}`,
        }
      }
    }
    return {
      tone: result.ok ? 'warn' : 'fail',
      state,
      text: `${capitalise(verb)} ${a.id}: the controller reports state "${state}".${reason}`,
    }
  }

  const detail = result.error || `HTTP ${result.status}`
  if (verb === 'revert' && revertLeftEnforced(result)) {
    return {
      tone: 'fail',
      state: 'revert_failed',
      text: `Revert of ${a.id} FAILED — the block on ${who} is still in force. ${detail}`,
    }
  }
  if (result.fromProxy && result.status === 504) {
    return {
      tone: 'fail',
      state: 'error',
      text: `${capitalise(verb)} ${a.id}: ${detail}. The outcome is unknown — check the lists below once the controller answers.`,
    }
  }
  if (result.fromProxy) {
    return {
      tone: 'fail',
      state: 'error',
      text: `${capitalise(verb)} ${a.id} did not reach the controller: ${detail}. Nothing was changed.`,
    }
  }
  return {
    tone: 'fail',
    state: 'error',
    text: `${capitalise(verb)} ${a.id} failed (HTTP ${result.status}): ${detail}`,
  }
}

/**
 * True when a revert answer means the block is still in place: the contract
 * returns the action as `revert_failed` with HTTP 502, and older controllers
 * answer 502/503 with only an error message.
 */
export function revertLeftEnforced(result: ActionResult): boolean {
  if (result.action) return isStillEnforced(result.action)
  return !result.fromProxy && (result.status === 502 || result.status === 503)
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
