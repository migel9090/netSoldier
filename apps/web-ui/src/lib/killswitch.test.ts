import { describe, expect, it } from 'vitest'
import type { ActionResult } from './api'
import {
  actionTypeChoices,
  approveQuestion,
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
  isStillEnforced,
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

  it('knows when an operation the controller answered with 202 has settled', () => {
    expect(hasSettled('approve', action({ state: 'approved' }))).toBe(false)
    for (const state of ['active', 'apply_failed', 'revert_failed']) {
      expect(hasSettled('approve', action({ state })), state).toBe(true)
    }
    expect(hasSettled('revert', action({ state: 'active' }))).toBe(false)
    for (const state of ['reverted', 'revert_failed']) {
      expect(hasSettled('revert', action({ state })), state).toBe(true)
    }
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
    const o = describeOutcome(
      'revert',
      a,
      dev,
      result({ status: 202, action: action({ state: 'active' }) }),
    )
    expect(o).toMatchObject({ tone: 'progress', state: 'active', settling: true })
    expect(o.text).toMatch(/stays in force/)
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
    expect(awaitingConfirmation(entries)).toEqual(['ACT-3'])
    expect(awaitingConfirmation([...entries].reverse())).toEqual(['ACT-3'])
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
