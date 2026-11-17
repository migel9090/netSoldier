import { describe, expect, it } from 'vitest'
import type { ActionResult } from './api'
import {
  actionTypeChoices,
  approveQuestion,
  approverWords,
  autoBlockStatus,
  awaitingConfirmation,
  defaultChoice,
  describeActor,
  describeOutcome,
  describeSettled,
  describeTransition,
  deviceOf,
  endedBy,
  failureKind,
  hasSettled,
  historyOutcomeFrom,
  isBeingLifted,
  isStillEnforced,
  operationInFlight,
  pageOf,
  progressWords,
  reportsInFlight,
  stateWords,
} from './killswitch'
import { newestFirst, oldestFirst } from './order'
import type { AuditEntry, EnforcementAction } from './types'

function action(over: Partial<EnforcementAction> = {}): EnforcementAction {
  return {
    id: 'ACT-1',
    timestamp: '2026-11-16T10:00:00Z',
    detection_id: 'DET-a-1',
    action_type: 'dns_sinkhole',
    state: 'pending',
    target_mac: 'aa:bb:cc:00:00:01',
    target_ip: '192.168.1.77',
    blocked_domain: 'evil.example',
    policy_rule: 'below auto threshold',
    auto_approved: false,
    ...over,
  }
}

function result(over: Partial<ActionResult>): ActionResult {
  return {
    ok: true,
    status: 200,
    action: null,
    error: '',
    available: null,
    fromProxy: false,
    ...over,
  }
}

const noNames = new Map<string, string>()

describe('state semantics', () => {
  it('treats revert_failed as still enforced, and approved as not yet', () => {
    expect(isStillEnforced(action({ state: 'active' }))).toBe(true)
    expect(isStillEnforced(action({ state: 'revert_failed' }))).toBe(true)
    expect(isStillEnforced(action({ state: 'approved' }))).toBe(false)
    expect(isStillEnforced(action({ state: 'apply_failed' }))).toBe(false)
    expect(isStillEnforced(action({ state: 'reverted' }))).toBe(false)
  })

  it('classifies failures', () => {
    expect(failureKind(action({ state: 'apply_failed' }))).toBe('apply')
    expect(failureKind(action({ state: 'revert_failed' }))).toBe('revert')
    expect(failureKind(action({ state: 'active' }))).toBeNull()
    expect(failureKind(action({ state: 'expired' }))).toBeNull()
  })

  it('reads the operation in flight from in_flight, and approved alone without it', () => {
    expect(operationInFlight(action({ state: 'active', in_flight: 'revert' }))).toBe('revert')
    expect(operationInFlight(action({ state: 'revert_failed', in_flight: 'revert' }))).toBe(
      'revert',
    )
    expect(operationInFlight(action({ state: 'approved', in_flight: 'apply' }))).toBe('apply')
    // A controller that predates the field: approved still implies the apply…
    expect(operationInFlight(action({ state: 'approved' }))).toBe('apply')
    // …but nothing tells a block being lifted from one nobody is lifting.
    expect(operationInFlight(action({ state: 'active' }))).toBeNull()
    expect(operationInFlight(action({ state: 'active', in_flight: 'bogus' }))).toBeNull()
    expect(reportsInFlight(action({ in_flight: 'revert' }))).toBe(true)
    expect(reportsInFlight(action({}))).toBe(false)
  })

  it('calls an enforced action with a revert in flight "being lifted"', () => {
    expect(isBeingLifted(action({ state: 'active', in_flight: 'revert' }))).toBe(true)
    expect(isBeingLifted(action({ state: 'revert_failed', in_flight: 'revert' }))).toBe(true)
    expect(isBeingLifted(action({ state: 'active' }))).toBe(false)
    expect(isBeingLifted(action({ state: 'revert_failed' }))).toBe(false)
    expect(isBeingLifted(action({ state: 'reverted', in_flight: 'revert' }))).toBe(false)
    expect(stateWords(action({ state: 'active', in_flight: 'revert' }))).toMatch(
      /being lifted \(still in force/,
    )
    expect(stateWords(action({ state: 'revert_failed', in_flight: 'revert' }))).toMatch(
      /retry is under way/,
    )
  })

  it('knows when an operation the controller answered with 202 has settled', () => {
    expect(hasSettled('approve', action({ state: 'approved', in_flight: 'apply' }))).toBe(false)
    expect(hasSettled('approve', action({ state: 'approved' }))).toBe(false)
    for (const state of ['active', 'apply_failed', 'revert_failed']) {
      expect(hasSettled('approve', action({ state })), state).toBe(true)
    }
    // With in_flight, the field decides — including a retried revert of a
    // revert_failed action, which the state cannot tell from a failed one.
    expect(hasSettled('revert', action({ state: 'active', in_flight: 'revert' }))).toBe(false)
    expect(hasSettled('revert', action({ state: 'revert_failed', in_flight: 'revert' }))).toBe(
      false,
    )
    for (const state of ['reverted', 'revert_failed', 'active']) {
      expect(hasSettled('revert', action({ state }), true), state).toBe(true)
    }
    // Without it (an older controller), the state as before.
    expect(hasSettled('revert', action({ state: 'active' }))).toBe(false)
    for (const state of ['reverted', 'revert_failed']) {
      expect(hasSettled('revert', action({ state })), state).toBe(true)
    }
  })

  it('says what an operation in flight waits for, from the action type', () => {
    const arp = action({ state: 'approved', in_flight: 'apply', action_type: 'arp_isolate' })
    expect(progressWords(arp)).toBe(
      'being applied as ARP Isolation — waiting for the network agent to confirm; not enforced until confirmed',
    )
    expect(progressWords(action({ state: 'approved' }))).toContain('waiting for AdGuard')
    expect(progressWords(action({ state: 'active', in_flight: 'revert' }))).toMatch(
      /^being lifted — waiting for AdGuard to answer; still in force/,
    )
    expect(progressWords(action({ state: 'revert_failed', in_flight: 'revert' }))).toMatch(
      /^retrying a revert that failed/,
    )
    // An older controller: the page's own revert.
    expect(progressWords(action({ state: 'active' }), 'revert')).toMatch(/^being lifted/)
    expect(progressWords(action({ state: 'approved', action_type: '' }))).toBe(
      'approved — checking…',
    )
  })
})

describe('outcomes come from the status and the reported state', () => {
  const a = action()
  const dev = deviceOf(action({ client_name: 'kids-tablet' }), noNames)

  it('approve → 200 active names the approver', () => {
    const o = describeOutcome(
      'approve',
      a,
      dev,
      result({ action: action({ state: 'active', approved_by: 'Michal' }) }),
    )
    expect(o).toMatchObject({ tone: 'ok', state: 'active', settling: false })
    expect(o.text).toContain('kids-tablet')
    expect(o.text).toContain('Approved by Michal')
  })

  it('approve → 200 apply_failed is a failure', () => {
    const o = describeOutcome(
      'approve',
      a,
      dev,
      result({ action: action({ state: 'apply_failed', failure_reason: 'AdGuard unreachable' }) }),
    )
    expect(o).toMatchObject({ tone: 'fail', state: 'apply_failed' })
    expect(o.text).toMatch(/NOT be applied/)
    expect(o.text).toContain('AdGuard unreachable')
  })

  it('approve → 200 revert_failed (an apply that could not be undone) is still blocked', () => {
    const o = describeOutcome(
      'approve',
      a,
      dev,
      result({ action: action({ state: 'revert_failed' }) }),
    )
    expect(o).toMatchObject({ tone: 'fail', state: 'revert_failed' })
    expect(o.text).toMatch(/STILL BLOCKED/)
  })

  // The driver has not answered: neither success nor failure, and the page
  // must keep reading the action until it settles.
  it('approve → 202 approved is in progress, not success', () => {
    const o = describeOutcome(
      'approve',
      a,
      dev,
      result({ status: 202, action: action({ state: 'approved', action_type: 'arp_isolate' }) }),
    )
    expect(o).toMatchObject({ tone: 'progress', state: 'approved', settling: true })
    expect(o.text).toMatch(/in progress/)
    expect(o.text).toContain('network agent')
    expect(o.text).toMatch(/Nothing is enforced/)
  })

  it('revert → 202 active is in progress, with the block still in force', () => {
    for (const reported of [
      action({ state: 'active', in_flight: 'revert' }),
      action({ state: 'active' }), // a controller without in_flight
    ]) {
      const o = describeOutcome('revert', a, dev, result({ status: 202, action: reported }))
      expect(o).toMatchObject({ tone: 'progress', state: 'active', settling: true })
      expect(o.text).toMatch(/^Reverting ACT-1: in progress/)
      expect(o.text).toMatch(/stays in force/)
    }
  })

  // The retry has not answered: reporting the previous attempt's failure
  // would be wrong. in_flight is what tells the two apart.
  it('revert → 202 revert_failed with a revert in flight is a retry in progress', () => {
    const o = describeOutcome(
      'revert',
      a,
      dev,
      result({ status: 202, action: action({ state: 'revert_failed', in_flight: 'revert' }) }),
    )
    expect(o).toMatchObject({ tone: 'progress', state: 'revert_failed', settling: true })
    expect(o.text).toMatch(/^Retrying the revert of ACT-1: in progress/)
  })

  it('the settled outcome of a 202 is reported from the state it reached', () => {
    expect(describeSettled('approve', action({ state: 'active' }), dev)).toMatchObject({
      tone: 'ok',
      settling: false,
    })
    expect(describeSettled('revert', action({ state: 'revert_failed' }), dev).tone).toBe('fail')
  })

  it('revert → 502 revert_failed is "still in force"', () => {
    const r = result({
      ok: false,
      status: 502,
      action: action({ state: 'revert_failed', failure_reason: 'timeout' }),
      error: 'revert failed, the enforcement is STILL IN FORCE and is being retried: timeout',
    })
    const o = describeOutcome('revert', a, dev, r)
    expect(o).toMatchObject({ tone: 'fail', state: 'revert_failed' })
    expect(o.text).toMatch(/still in force/)
  })

  it('revert → 502 without an action is still read as "in force"', () => {
    const r = result({ ok: false, status: 502, error: 'revert failed' })
    expect(describeOutcome('revert', a, dev, r)).toMatchObject({ state: 'revert_failed' })
  })

  it('409 reports the error and the state the action is in now', () => {
    const r = result({
      ok: false,
      status: 409,
      error: 'action ACT-1 is rejected, not pending',
      action: action({ state: 'rejected', rejected_by: 'Anna' }),
    })
    const o = describeOutcome('approve', a, dev, r)
    expect(o).toMatchObject({ tone: 'warn', state: 'rejected', settling: false })
    expect(o.text).toContain('is rejected, not pending')
    expect(o.text).toContain('It is now rejected')
  })

  it('422 lists what the controller can carry out now', () => {
    const r = result({
      ok: false,
      status: 422,
      error: 'action type "arp_isolate" is not available: no netagent has polled since start-up',
      available: ['dns_sinkhole'],
    })
    const o = describeOutcome('approve', a, dev, r)
    expect(o).toMatchObject({ tone: 'fail', state: 'error' })
    expect(o.text).toContain('no netagent has polled')
    expect(o.text).toContain('Available now: DNS Sinkhole')
    expect(o.text).toContain('Nothing was changed')
  })

  it('a proxy-side failure is not mistaken for the controller verdict', () => {
    const r = result({
      ok: false,
      status: 502,
      error: 'killswitch is unreachable',
      fromProxy: true,
    })
    expect(describeOutcome('revert', a, dev, r).text).toMatch(/did not reach the controller/)
    const timeout = result({ ok: false, status: 504, error: 'timed out', fromProxy: true })
    expect(describeOutcome('approve', a, dev, timeout).text).toMatch(/outcome is unknown/)
  })
})

describe('choosing the enforcement at approval', () => {
  const dev = { name: 'kids-tablet', mac: 'aa:bb:cc:00:00:01', ip: '192.168.1.77' }

  it('offers what the policy reports, narrowest first', () => {
    const choices = actionTypeChoices(action(), dev, ['switch_acl', 'arp_isolate', 'dns_sinkhole'])
    expect(choices.map((c) => c.type)).toEqual(['dns_sinkhole', 'arp_isolate', 'switch_acl'])
    expect(choices.map((c) => c.strong)).toEqual([false, true, true])
  })

  it('selects the DNS sinkhole by default, and nothing stronger', () => {
    expect(defaultChoice(actionTypeChoices(action(), dev, ['arp_isolate', 'dns_sinkhole']))).toBe(
      'dns_sinkhole',
    )
    // Even when the policy proposed the isolation, it must be picked.
    const proposed = action({ action_type: 'arp_isolate' })
    expect(defaultChoice(actionTypeChoices(proposed, dev, ['arp_isolate']))).toBe('')
    // A sinkhole cannot work without a domain.
    const ipOnly = action({ blocked_domain: '' })
    const choices = actionTypeChoices(ipOnly, dev, ['dns_sinkhole', 'arp_isolate'])
    expect(choices[0]).toMatchObject({ type: 'dns_sinkhole', usable: false })
    expect(defaultChoice(choices)).toBe('')
  })

  it('describes the stronger types in plain words, with what they need', () => {
    const [arp] = actionTypeChoices(action(), dev, ['arp_isolate'])
    expect(arp.does).toContain('Cuts kids-tablet off')
    expect(arp.needs).toContain('network agent')
    const [sw] = actionTypeChoices(action(), dev, ['switch_acl'])
    expect(sw.does).toContain('switch port')
    // Isolation needs both identifiers.
    expect(actionTypeChoices(action({ target_ip: '' }), dev, ['arp_isolate'])[0].usable).toBe(false)
  })

  it('the confirmation names the chosen enforcement and the device', () => {
    const [dns, arp] = actionTypeChoices(action(), dev, ['dns_sinkhole', 'arp_isolate'])
    expect(approveQuestion(dns, dev)).toContain('DNS sinkhole on kids-tablet')
    const q = approveQuestion(arp, dev)
    expect(q).toContain('Cut off from the network (ARP isolation)')
    expect(q).toContain('aa:bb:cc:00:00:01')
  })

  it('prefers the name carried by the action', () => {
    const a = action({ client_name: 'from-event' })
    expect(deviceOf(a, new Map([['aa:bb:cc:00:00:01', 'from-inventory']])).name).toBe('from-event')
    expect(deviceOf(action(), new Map([['aa:bb:cc:00:00:01', 'from-inventory']])).name).toBe(
      'from-inventory',
    )
  })
})

describe('audit log', () => {
  function entry(over: Partial<AuditEntry>): AuditEntry {
    return {
      seq: 1,
      timestamp: '2026-11-16T10:00:00Z',
      action_id: 'ACT-1',
      from_state: 'pending',
      to_state: 'approved',
      actor: 'Michal',
      reason: '',
      detection_id: 'DET-1',
      detection_summary: '',
      target_mac: '',
      target_ip: '',
      action_type: 'dns_sinkhole',
      blocked_domain: '',
      policy_rule: '',
      ...over,
    }
  }

  // GET /actions/active leaves `approved` out; the log is how the page finds them.
  it('finds approvals that have no outcome yet', () => {
    const entries = [
      entry({ seq: 6, action_id: 'ACT-3', from_state: 'pending', to_state: 'approved' }),
      entry({ seq: 5, action_id: 'ACT-2', from_state: 'approved', to_state: 'active' }),
      entry({ seq: 4, action_id: 'ACT-2', from_state: 'pending', to_state: 'approved' }),
      entry({ seq: 3, action_id: 'ACT-3', from_state: '', to_state: 'pending' }),
    ]
    const ids = (es: AuditEntry[]) => awaitingConfirmation(es).map((e) => e.action_id)
    expect(ids(entries)).toEqual(['ACT-3'])
    expect(ids([...entries].reverse())).toEqual(['ACT-3'])
    // The entry says when it was approved, for the "since" column.
    expect(awaitingConfirmation(entries)[0].seq).toBe(6)
  })

  it('describes transitions and the controller’s own actors', () => {
    expect(describeTransition(entry({ from_state: '', to_state: 'pending' }))).toMatch(/proposed/)
    expect(describeTransition(entry({ from_state: 'approved', to_state: 'active' }))).toBe(
      'enforced',
    )
    expect(describeTransition(entry({ from_state: 'active', to_state: 'revert_failed' }))).toMatch(
      /still enforced/,
    )
    expect(describeActor('ttl')).toMatch(/TTL reaper/)
    expect(describeActor('Michal')).toBe('Michal')
    expect(endedBy(action({ state: 'reverted', reverted_by: 'ttl' }))).toMatch(/TTL/)
    expect(endedBy(action({ state: 'rejected', rejected_by: 'Anna' }))).toBe('Anna')
    expect(endedBy(action({ state: 'expired' }))).toMatch(/nobody approved/)
  })
})

describe('automatic blocking', () => {
  it('shows whatever reason the controller gives, explained when it is a known one', () => {
    expect(
      autoBlockStatus({ auto_block_allowed: true, auto_block_disabled_reason: '' }),
    ).toMatchObject({ on: true, reason: '' })

    const empty = autoBlockStatus({
      auto_block_allowed: false,
      auto_block_disabled_reason: 'auto-block disabled: allowlist is empty',
    })
    expect(empty).toMatchObject({ on: false, reason: 'auto-block disabled: allowlist is empty' })
    expect(empty.explanation).toContain('allowlist')

    const setting = autoBlockStatus({
      auto_block_allowed: false,
      auto_block_disabled_reason: 'auto-block disabled: POLICY_AUTO_BLOCK is off',
    })
    expect(setting.explanation).toContain('POLICY_AUTO_BLOCK')

    // A reason this UI has never heard of: shown as given, nothing invented.
    const unknown = autoBlockStatus({
      auto_block_allowed: false,
      auto_block_disabled_reason: '  auto-block disabled: the moon is full ',
    })
    expect(unknown).toEqual({
      on: false,
      reason: 'auto-block disabled: the moon is full',
      explanation: '',
    })
    expect(autoBlockStatus({ auto_block_allowed: false })).toEqual({
      on: false,
      reason: '',
      explanation: '',
    })
  })

  it('does not guess when the controller does not say', () => {
    expect(autoBlockStatus({}).on).toBeNull()
    // A reason without the flag still means it is off.
    expect(autoBlockStatus({ auto_block_disabled_reason: 'off for maintenance' })).toMatchObject({
      on: false,
      reason: 'off for maintenance',
    })
  })
})

describe('ordering', () => {
  const items = [
    { id: 'b', timestamp: '2026-11-16T10:00:00Z' },
    { id: 'c', timestamp: '2026-11-16T09:00:00Z' },
    { id: 'a', timestamp: '2026-11-16T10:00:00Z' },
  ]

  it('is the same whatever order the backend sent', () => {
    expect(oldestFirst(items).map((i) => i.id)).toEqual(['c', 'a', 'b'])
    expect(oldestFirst([...items].reverse()).map((i) => i.id)).toEqual(['c', 'a', 'b'])
    expect(newestFirst(items).map((i) => i.id)).toEqual(['a', 'b', 'c'])
  })
})

describe('history', () => {
  it('pages a list, clamping the page to the ones there are', () => {
    const items = Array.from({ length: 120 }, (_, i) => i)
    expect(pageOf(items, 0, 50)).toMatchObject({ page: 0, pages: 3, total: 120 })
    expect(pageOf(items, 2, 50).items).toEqual(items.slice(100))
    expect(pageOf(items, 7, 50).page).toBe(2)
    expect(pageOf(items, -1, 50).page).toBe(0)
    expect(pageOf([], 3, 50)).toEqual({ items: [], page: 0, pages: 1, total: 0 })
  })

  it('takes the outcome filter from the URL, and only one it knows', () => {
    expect(historyOutcomeFrom(new URLSearchParams('outcome=rejected'))).toBe('rejected')
    expect(historyOutcomeFrom(new URLSearchParams('outcome=apply_failed'))).toBe('apply_failed')
    expect(historyOutcomeFrom(new URLSearchParams('outcome=active'))).toBe('')
    expect(historyOutcomeFrom(new URLSearchParams())).toBe('')
  })

  it('says who approved: a person, the policy, or nobody', () => {
    expect(approverWords({ approved_by: 'Anna', auto_approved: false })).toBe('Anna')
    expect(approverWords({ approved_by: '', auto_approved: true })).toBe('the policy (automatic)')
    expect(approverWords({ auto_approved: false })).toBe('—')
  })
})
