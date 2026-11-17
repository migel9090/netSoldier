import type { ActionResult } from './api'
import { formatActionType } from './api'
import type { AuditEntry, EnforcementAction, KillswitchPolicy } from './types'

/**
 * What an enforcement action means for the household, in the killswitch's
 * own terms (contract v2 §3, killswitch-controller internal/actions/doc.go).
 */

export type FailureKind = 'apply' | 'revert'

/**
 * `apply_failed`: the block was never put in place. `revert_failed`: a
 * revert did not take (or an apply could not be undone) — still in force.
 */
export function failureKind(a: EnforcementAction): FailureKind | null {
  if (a.state === 'revert_failed') return 'revert'
  if (a.state === 'apply_failed') return 'apply'
  return null
}

/** True while the block is, or may be, in force: active, or a revert that did not lift it. */
export function isStillEnforced(a: EnforcementAction): boolean {
  return a.state === 'active' || a.state === 'revert_failed'
}

export function enforcedSince(a: EnforcementAction): string {
  return a.activated_at || a.timestamp
}

export type Operation = 'apply' | 'revert'

/** Whether the controller that served this action says what is in flight. */
export function reportsInFlight(a: Pick<EnforcementAction, 'in_flight'>): boolean {
  return a.in_flight === 'apply' || a.in_flight === 'revert'
}

/**
 * The driver operation outstanding on an action, as the controller reports
 * it in `in_flight`. A controller that predates the field still implies one
 * case: an `approved` action always has its apply outstanding. A revert
 * under way cannot be read from the state at all (the action stays active,
 * or revert_failed, until it is confirmed).
 */
export function operationInFlight(
  a: Pick<EnforcementAction, 'in_flight' | 'state'>,
): Operation | null {
  if (a.in_flight === 'apply' || a.in_flight === 'revert') return a.in_flight
  return a.state === 'approved' ? 'apply' : null
}

/** Still in force, and a revert of it is under way: "being lifted". */
export function isBeingLifted(a: EnforcementAction): boolean {
  return isStillEnforced(a) && operationInFlight(a) === 'revert'
}

export interface DeviceRef {
  name: string
  mac: string
  ip: string
}

/** Name from the action or, failing that, from the device inventory. */
export function deviceOf(
  a: Pick<EnforcementAction, 'target_mac' | 'target_ip'> & { client_name?: string },
  names: ReadonlyMap<string, string>,
): DeviceRef {
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
export function describeBlock(
  a: Pick<EnforcementAction, 'action_type' | 'blocked_domain'>,
): string {
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

// ── Choosing the enforcement at approval ──────────────────────────────

/** The action types in order of strength; DNS sinkhole is the narrowest. */
export const ACTION_TYPE_ORDER = ['dns_sinkhole', 'arp_isolate', 'switch_acl'] as const

export interface ActionTypeChoice {
  type: string
  /** Short name, used in the confirmation button. */
  name: string
  /** What it does to the device, in plain words. */
  does: string
  /** What it relies on. */
  needs: string
  /** False when it cannot work for this action; `why` says why. */
  usable: boolean
  why: string
  /** Anything but the DNS sinkhole takes the device itself off (part of) the network. */
  strong: boolean
}

export function describeActionType(
  type: string,
  a: EnforcementAction,
  device: DeviceRef,
): ActionTypeChoice {
  const who = device.name || device.mac || device.ip || 'the device'
  switch (type) {
    case 'dns_sinkhole':
      return {
        type,
        name: 'DNS sinkhole',
        does: a.blocked_domain
          ? `Stops ${who} from looking up ${a.blocked_domain} and its subdomains. Everything else on the device keeps working.`
          : `Stops ${who} from looking up the detected domain.`,
        needs: 'Done in AdGuard (the DNS server); nothing changes on the device itself.',
        usable: Boolean(a.blocked_domain),
        why: a.blocked_domain
          ? ''
          : 'This detection names no domain, so there is nothing to sinkhole.',
        strong: false,
      }
    case 'arp_isolate':
      return {
        type,
        name: 'Cut off from the network (ARP isolation)',
        does: `Cuts ${who} off from the router: it loses its internet connection and everything else it reaches through the gateway until the block is lifted or expires.`,
        needs:
          'Needs the network agent (netagent) running with isolation enabled. The block only counts once the agent confirms it; until then the action shows as in progress.',
        usable: Boolean(a.target_mac && a.target_ip),
        why:
          a.target_mac && a.target_ip
            ? ''
            : 'The device is not identified by both MAC and IP address, which isolation needs.',
        strong: true,
      }
    case 'switch_acl':
      return {
        type,
        name: 'Quarantine at the switch port (switch ACL)',
        does: `Moves the switch port ${who} is plugged into to the quarantine VLAN, or shuts the port: the device, and anything else on that port, loses the network.`,
        needs: 'Needs the managed-switch integration (the switch webhook) to be configured.',
        usable: Boolean(a.target_mac),
        why: a.target_mac ? '' : 'The device has no known MAC address, which the switch needs.',
        strong: true,
      }
    default:
      return {
        type,
        name: formatActionType(type),
        does: `Enforcement of type "${type}".`,
        needs: 'Reported as available by the killswitch controller.',
        usable: true,
        why: '',
        strong: true,
      }
  }
}

/**
 * The choices offered at approval: what GET /policy reports as available,
 * strongest last.
 */
export function actionTypeChoices(
  a: EnforcementAction,
  device: DeviceRef,
  available: readonly string[],
): ActionTypeChoice[] {
  const rank = (t: string) => {
    const i = (ACTION_TYPE_ORDER as readonly string[]).indexOf(t)
    return i < 0 ? ACTION_TYPE_ORDER.length : i
  }
  return [...new Set(available)]
    .sort((x, y) => rank(x) - rank(y) || x.localeCompare(y))
    .map((t) => describeActionType(t, a, device))
}

/**
 * What is selected when the approval dialog opens: the DNS sinkhole when it
 * can work, otherwise nothing — anything stronger has to be picked, even
 * when the policy proposed it.
 */
export function defaultChoice(choices: readonly ActionTypeChoice[]): string {
  const dns = choices.find((c) => c.type === 'dns_sinkhole')
  return dns?.usable ? dns.type : ''
}

/** The question the approval dialog asks, naming the device and the chosen enforcement. */
export function approveQuestion(choice: ActionTypeChoice, device: DeviceRef): string {
  return choice.strong
    ? `Approve: ${choice.name} for ${describeDevice(device)}?`
    : `Approve: ${choice.name} on ${describeDevice(device)}?`
}

// ── Outcomes ──────────────────────────────────────────────────────────

export type Verb = 'approve' | 'reject' | 'revert'
export type Tone = 'ok' | 'warn' | 'fail' | 'progress'

export interface Outcome {
  tone: Tone
  /** The state the controller reported, or "error" when it reported none. */
  state: string
  text: string
  /**
   * The controller has not finished (HTTP 202): the page keeps reading the
   * action by id until {@link hasSettled}.
   */
  settling: boolean
}

/** Who the driver is waiting for, by action type. */
function waitingFor(actionType: string): string {
  switch (actionType) {
    case 'arp_isolate':
      return 'the network agent to confirm'
    case 'switch_acl':
      return 'the switch to answer'
    case 'dns_sinkhole':
      return 'AdGuard to answer'
    default:
      return 'the driver to answer'
  }
}

/**
 * True once an operation the controller answered with 202 has an outcome:
 * nothing of its kind is in flight any more.
 *
 * `inFlightKnown`: the controller reports `in_flight` (it did when it
 * answered the 202). Only then can a revert be followed: a retried revert of
 * a revert_failed action stays revert_failed until the retry answers, which
 * the state cannot tell from a retry that already failed. From a controller
 * that predates the field, the state is all there is: an approve settles
 * when the action leaves `approved`, a revert when it leaves `active`.
 */
export function hasSettled(
  verb: Verb,
  a: EnforcementAction,
  inFlightKnown = reportsInFlight(a),
): boolean {
  const op = operationInFlight(a)
  if (verb === 'approve') return op !== 'apply'
  if (verb === 'revert') return inFlightKnown ? op !== 'revert' : a.state !== 'active'
  return true
}

/**
 * What an operation still in flight is doing, for the "in progress" list.
 * `verb` is what this page asked for, the fallback for a controller that
 * does not report `in_flight`.
 */
export function progressWords(a: EnforcementAction, verb?: Verb): string {
  const op = operationInFlight(a) ?? (verb === 'revert' ? 'revert' : verb ? 'apply' : null)
  if (op === 'revert') {
    const waiting = a.action_type ? ` — waiting for ${waitingFor(a.action_type)}` : ''
    return a.state === 'revert_failed'
      ? `retrying a revert that failed${waiting}; still in force until it is confirmed`
      : `being lifted${waiting}; still in force until it is confirmed`
  }
  if (!a.action_type) return 'approved — checking…'
  // Every approved action has its apply in flight; whether that waits for
  // the network agent, the switch or AdGuard is told by the action type.
  return `being applied as ${formatActionType(a.action_type)} — waiting for ${waitingFor(a.action_type)}; not enforced until confirmed`
}

/** The action's state in words. */
export function stateWords(a: EnforcementAction): string {
  const lifting = operationInFlight(a) === 'revert'
  switch (a.state) {
    case 'pending':
      return 'waiting for approval'
    case 'approved':
      return 'approved, still being applied'
    case 'active':
      return lifting ? 'enforced, being lifted (still in force until confirmed)' : 'enforced'
    case 'revert_failed':
      return lifting
        ? 'STILL ENFORCED (a revert failed; a retry is under way)'
        : 'STILL ENFORCED (a revert failed and is being retried)'
    case 'reverted':
      return 'reverted (lifted)'
    case 'rejected':
      return 'rejected'
    case 'expired':
      return 'expired (nobody approved it in time)'
    case 'apply_failed':
      return 'not enforced (the apply failed)'
    default:
      return `in state "${a.state}"`
  }
}

/**
 * What just happened, from the controller's answer — the HTTP status
 * together with the state in the response body, never the status alone.
 */
export function describeOutcome(
  verb: Verb,
  a: EnforcementAction,
  device: DeviceRef,
  result: ActionResult,
): Outcome {
  const who = describeDevice(device)
  const done = (tone: Tone, state: string, text: string): Outcome => ({
    tone,
    state,
    text,
    settling: false,
  })
  const reported = result.action

  if (result.fromProxy) {
    const detail = result.error || `HTTP ${result.status}`
    if (result.status === 504) {
      return done(
        'fail',
        'error',
        `${capitalise(verb)} ${a.id}: ${detail}. The outcome is unknown — check the lists below once the controller answers.`,
      )
    }
    return done(
      'fail',
      'error',
      `${capitalise(verb)} ${a.id} did not reach the controller: ${detail}. Nothing was changed.`,
    )
  }

  // 202: the driver has not answered yet. Neither success nor failure.
  if (result.status === 202 && reported && !hasSettled(verb, reported)) {
    const waiting = `in progress — waiting for ${waitingFor(reported.action_type)}`
    const text =
      verb === 'approve'
        ? `Approved ${a.id} as ${formatActionType(reported.action_type)}; ${waiting}. Nothing is enforced on ${who} until it does.`
        : reported.state === 'revert_failed'
          ? `Retrying the revert of ${a.id}: ${waiting}. The block on ${who} stays in force until then.`
          : `Reverting ${a.id}: ${waiting}. The block on ${who} stays in force until then.`
    return { tone: 'progress', state: reported.state, text, settling: true }
  }

  if (result.status === 409 && reported) {
    return done(
      'warn',
      reported.state,
      `${capitalise(verb)} ${a.id} was refused: ${result.error}. It is now ${stateWords(reported)}.`,
    )
  }

  if (result.status === 422) {
    const available = result.available ?? []
    return done(
      'fail',
      'error',
      `${capitalise(verb)} ${a.id} was refused: ${result.error}. ` +
        (available.length > 0
          ? `Available now: ${available.map(formatActionType).join(', ')}.`
          : 'No enforcement type is available right now.') +
        ' Nothing was changed.',
    )
  }

  if (reported) return describeState(verb, a, who, reported, result)

  const detail = result.error || `HTTP ${result.status}`
  if (verb === 'revert' && result.status === 502) {
    // The contract's revert_failed comes with the action; without one the
    // safe reading is still "in force".
    return done(
      'fail',
      'revert_failed',
      `Revert of ${a.id} FAILED — the block on ${who} is still in force. ${detail}`,
    )
  }
  if (result.status === 404) {
    return done(
      'fail',
      'error',
      `${capitalise(verb)} ${a.id}: the controller does not know this action (any more).`,
    )
  }
  return done(
    'fail',
    'error',
    `${capitalise(verb)} ${a.id} failed (HTTP ${result.status}): ${detail}`,
  )
}

function describeState(
  verb: Verb,
  a: EnforcementAction,
  who: string,
  reported: EnforcementAction,
  result: ActionResult,
): Outcome {
  const done = (tone: Tone, text: string): Outcome => ({
    tone,
    state: reported.state,
    text,
    settling: false,
  })
  const reason = reported.failure_reason ? ` Reason: ${reported.failure_reason}` : ''
  const state = reported.state
  if (verb === 'approve') {
    if (state === 'active') {
      const by = reported.approved_by ? ` Approved by ${reported.approved_by}.` : ''
      return done(
        'ok',
        `Approved ${a.id}: ${describeBlock(reported)} is now blocked for ${who}.${by}`,
      )
    }
    if (state === 'apply_failed') {
      return done(
        'fail',
        `Approved ${a.id}, but the block could NOT be applied — nothing is enforced on ${who}.${reason}`,
      )
    }
    if (state === 'revert_failed') {
      return done(
        'fail',
        `Approved ${a.id}, but the apply failed and could not be undone: treat ${who} as STILL BLOCKED; the controller keeps retrying.${reason}`,
      )
    }
  }
  if (verb === 'reject' && state === 'rejected') {
    return done('ok', `Rejected ${a.id}: nothing will be blocked on ${who}.`)
  }
  if (verb === 'revert') {
    if (state === 'reverted') return done('ok', `Reverted ${a.id}: the block on ${who} is lifted.`)
    if (isStillEnforced(reported)) {
      return done(
        'fail',
        `Revert of ${a.id} FAILED — the block on ${who} is still in force and the controller keeps retrying.${reason}`,
      )
    }
  }
  return {
    tone: result.ok ? 'warn' : 'fail',
    state,
    text: `${capitalise(verb)} ${a.id}: the controller reports it ${stateWords(reported)}.${reason}`,
    settling: false,
  }
}

/** The outcome once an operation answered with 202 has settled. */
export function describeSettled(verb: Verb, a: EnforcementAction, device: DeviceRef): Outcome {
  return describeOutcome(verb, a, device, {
    ok: true,
    status: 200,
    action: a,
    error: '',
    available: null,
    fromProxy: false,
  })
}

/**
 * Actions approved but not yet confirmed, from the audit log (newest
 * first): the transitions to `approved` that are the most recent of their
 * action. Such actions are in no list — GET /actions/active does not
 * include `approved`, and `in_flight` does not change that — so this is how
 * the page finds an approval made elsewhere, or before a reload, while its
 * driver is still working. The entry says when it was approved.
 */
export function awaitingConfirmation(entries: readonly AuditEntry[]): AuditEntry[] {
  const latest = new Map<string, AuditEntry>()
  for (const e of entries) {
    const seen = latest.get(e.action_id)
    if (!seen || e.seq > seen.seq) latest.set(e.action_id, e)
  }
  return [...latest.values()].filter((e) => e.to_state === 'approved')
}

// ── Automatic blocking (GET /policy) ──────────────────────────────────

export interface AutoBlockStatus {
  /** null: the controller did not say. */
  on: boolean | null
  /** The controller's own reason, verbatim; '' when it gave none. */
  reason: string
  /** Plain words for a reason this UI recognises; '' for any other. */
  explanation: string
}

/**
 * Whether the controller blocks on its own, and why not. The reason is
 * always shown as the controller gave it: it is free text, and new reasons
 * appear (POLICY_AUTO_BLOCK, for one) without this UI knowing them.
 */
export function autoBlockStatus(
  p: Pick<KillswitchPolicy, 'auto_block_allowed' | 'auto_block_disabled_reason'>,
): AutoBlockStatus {
  const reason =
    typeof p.auto_block_disabled_reason === 'string' ? p.auto_block_disabled_reason.trim() : ''
  const on =
    typeof p.auto_block_allowed === 'boolean' ? p.auto_block_allowed : reason ? false : null
  return {
    on,
    reason: on === false ? reason : '',
    explanation: on === false ? explain(reason) : '',
  }
}

function explain(reason: string): string {
  if (/POLICY_AUTO_BLOCK/i.test(reason)) {
    return 'It is switched off in the killswitch settings (POLICY_AUTO_BLOCK).'
  }
  if (/allowlist is empty/i.test(reason)) {
    return 'No device is on the allowlist, so nothing (not even the router) is protected from an automatic block.'
  }
  if (/protection entr/i.test(reason)) {
    return 'Some of the protected-device settings could not be read when the killswitch started.'
  }
  return ''
}

// ── Audit log in words ────────────────────────────────────────────────

/** The killswitch's own actors, explained. */
const SYSTEM_ACTORS: Record<string, string> = {
  'auto-policy': 'the policy (automatic)',
  ttl: 'the TTL reaper (automatic)',
  reconcile: 'reconciliation (automatic)',
  netagent: 'the network agent',
  system: 'the controller (queue full)',
}

export function describeActor(actor: string): string {
  return SYSTEM_ACTORS[actor.toLowerCase()] ?? actor
}

export function isSystemActor(actor: string): boolean {
  return actor.toLowerCase() in SYSTEM_ACTORS
}

/** One audit transition in words, e.g. "approved", "enforced", "revert failed — still enforced". */
export function describeTransition(e: Pick<AuditEntry, 'from_state' | 'to_state'>): string {
  const to = e.to_state
  if (!e.from_state) {
    return to === 'pending'
      ? 'proposed, waiting for approval'
      : `created as ${to.replace('_', ' ')}`
  }
  switch (to) {
    case 'approved':
      return 'approved'
    case 'active':
      return 'enforced'
    case 'rejected':
      return 'rejected'
    case 'expired':
      return 'expired unapproved'
    case 'reverted':
      return 'reverted (lifted)'
    case 'apply_failed':
      return 'apply failed — not enforced'
    case 'revert_failed':
      return 'revert failed — still enforced'
    default:
      return `${e.from_state} → ${to}`
  }
}

/** Who ended a finished action, for the history view. */
export function endedBy(a: EnforcementAction): string {
  switch (a.state) {
    case 'reverted':
      return a.reverted_by ? describeActor(a.reverted_by) : '—'
    case 'rejected':
      return a.rejected_by ? describeActor(a.rejected_by) : '—'
    case 'expired':
      return 'nobody approved it in time'
    case 'apply_failed':
      return 'the driver (apply failed)'
    default:
      return '—'
  }
}

/** Who approved an action, in words: the operator, the policy, or nobody yet. */
export function approverWords(a: Pick<EnforcementAction, 'approved_by' | 'auto_approved'>): string {
  if (a.approved_by) return describeActor(a.approved_by)
  return a.auto_approved ? describeActor('auto-policy') : '—'
}

// ── History ───────────────────────────────────────────────────────────

/** The outcomes the history can be narrowed to; '' is every finished action. */
export const HISTORY_OUTCOMES: readonly { value: string; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'reverted', label: 'Reverted' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'expired', label: 'Expired' },
  { value: 'apply_failed', label: 'Failed' },
]

export function historyOutcomeFrom(params: Pick<URLSearchParams, 'get'>): string {
  const v = params.get('outcome') ?? ''
  return HISTORY_OUTCOMES.some((o) => o.value === v) ? v : ''
}

export interface Paged<T> {
  items: T[]
  /** 0-based, clamped to the pages there are. */
  page: number
  pages: number
  total: number
}

/** Page `page` of `items`, `size` to a page. */
export function pageOf<T>(items: readonly T[], page: number, size: number): Paged<T> {
  const pages = Math.max(1, Math.ceil(items.length / size))
  const p = Math.min(Math.max(0, Math.floor(page)), pages - 1)
  return { items: items.slice(p * size, (p + 1) * size), page: p, pages, total: items.length }
}

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
