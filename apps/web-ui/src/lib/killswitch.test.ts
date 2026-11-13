import { describe, expect, it } from 'vitest'
import type { ActionResult } from './api'
import {
  approveConfirmText,
  describeOutcome,
  deviceOf,
  failureKind,
  isStillEnforced,
  revertLeftEnforced,
} from './killswitch'
import { mergeById, newestFirst, oldestFirst } from './order'
import type { EnforcementAction } from './types'

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
  return { ok: true, status: 200, action: null, error: '', fromProxy: false, ...over }
}

const noNames = new Map<string, string>()

describe('state semantics', () => {
  it('treats revert_failed, and the legacy failed-after-revert, as still enforced', () => {
    expect(isStillEnforced(action({ state: 'active' }))).toBe(true)
    expect(isStillEnforced(action({ state: 'revert_failed' }))).toBe(true)
    expect(
      isStillEnforced(action({ state: 'failed', failure_reason: 'revert failed: adguard down' })),
    ).toBe(true)
    expect(isStillEnforced(action({ state: 'apply_failed' }))).toBe(false)
    expect(isStillEnforced(action({ state: 'failed', failure_reason: 'get rules: refused' }))).toBe(
      false,
    )
    expect(isStillEnforced(action({ state: 'reverted' }))).toBe(false)
  })

  it('classifies failures, legacy failed included', () => {
    expect(failureKind(action({ state: 'apply_failed' }))).toBe('apply')
    expect(failureKind(action({ state: 'failed' }))).toBe('apply')
    expect(failureKind(action({ state: 'revert_failed' }))).toBe('revert')
    expect(failureKind(action({ state: 'active' }))).toBeNull()
    expect(failureKind(action({ state: 'expired' }))).toBeNull()
  })
})

describe('outcomes come from the reported state', () => {
  const a = action()
  const dev = deviceOf(action({ client_name: 'kids-tablet' }), noNames)

  it('approve → active', () => {
    const o = describeOutcome('approve', a, dev, result({ action: action({ state: 'active' }) }))
    expect(o).toMatchObject({ tone: 'ok', state: 'active' })
    expect(o.text).toContain('kids-tablet')
  })

  it('approve → apply_failed (HTTP 200) is a failure', () => {
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

  it('approve → legacy failed is a failure', () => {
    const o = describeOutcome('approve', a, dev, result({ action: action({ state: 'failed' }) }))
    expect(o.tone).toBe('fail')
  })

  it('revert → 502 revert_failed is "still in force"', () => {
    const r = result({
      ok: false,
      status: 502,
      action: action({ state: 'revert_failed', failure_reason: 'timeout' }),
    })
    expect(revertLeftEnforced(r)).toBe(true)
    expect(describeOutcome('revert', a, dev, r)).toMatchObject({
      tone: 'fail',
      state: 'revert_failed',
    })
  })

  it('revert → legacy 502 with only an error is "still in force"', () => {
    const r = result({ ok: false, status: 502, error: 'revert failed, enforcement still active' })
    expect(revertLeftEnforced(r)).toBe(true)
    expect(describeOutcome('revert', a, dev, r).text).toMatch(/still in force/)
  })

  it('a proxy-side failure is not mistaken for the controller verdict', () => {
    const r = result({
      ok: false,
      status: 502,
      error: 'killswitch is unreachable',
      fromProxy: true,
    })
    expect(revertLeftEnforced(r)).toBe(false)
    expect(describeOutcome('revert', a, dev, r).text).toMatch(/did not reach the controller/)
  })

  it('a conflict is reported with the controller message', () => {
    const r = result({ ok: false, status: 409, error: 'action is not pending' })
    expect(describeOutcome('approve', a, dev, r)).toMatchObject({ tone: 'fail', state: 'error' })
  })
})

describe('approval confirmation', () => {
  it('names the device, the action type and what will be blocked', () => {
    const a = action({ detection_summary: 'DNS query for a domain listed by ThreatFox' })
    const text = approveConfirmText(a, deviceOf(a, new Map([['aa:bb:cc:00:00:01', 'kids-tablet']])))
    for (const part of [
      'kids-tablet',
      'aa:bb:cc:00:00:01',
      '192.168.1.77',
      'DNS Sinkhole',
      'evil.example',
      'ThreatFox',
    ]) {
      expect(text).toContain(part)
    }
  })

  it('prefers the name carried by the action', () => {
    const a = action({ client_name: 'from-event' })
    expect(deviceOf(a, new Map([['aa:bb:cc:00:00:01', 'from-inventory']])).name).toBe('from-event')
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

  it('mergeById keeps the first occurrence', () => {
    const merged = mergeById(
      [{ id: '1', v: 'server' }],
      [
        { id: '1', v: 'local' },
        { id: '2', v: 'local' },
      ],
    )
    expect(merged).toEqual([
      { id: '1', v: 'server' },
      { id: '2', v: 'local' },
    ])
  })
})
