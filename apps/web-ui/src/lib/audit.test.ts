import { describe, expect, it } from 'vitest'
import { actorsIn, auditFilterFrom, auditMatches, isFiltered, scanAudit } from './audit'
import type { AuditEntry } from './types'

function entry(seq: number, actor: string, to: string): AuditEntry {
  return {
    seq,
    timestamp: new Date(Date.UTC(2026, 10, 1) + seq * 60_000).toISOString(),
    action_id: `ACT-${Math.ceil(seq / 3)}`,
    from_state: to === 'pending' ? '' : 'pending',
    to_state: to,
    actor,
    reason: '',
    detection_id: '',
    detection_summary: '',
    target_mac: '',
    target_ip: '',
    action_type: 'dns_sinkhole',
    blocked_domain: '',
    policy_rule: '',
  }
}

/** A log of `n` entries, seq 1..n; every tenth is Anna's approval, the rest the policy's proposals. */
function log(n: number): AuditEntry[] {
  return Array.from({ length: n }, (_, i) =>
    (i + 1) % 10 === 0 ? entry(i + 1, 'Anna', 'approved') : entry(i + 1, 'auto-policy', 'pending'),
  )
}

/** GET /audit over `all`: newest first, older than `before`, at most `limit`. */
function reader(all: AuditEntry[]) {
  const calls: { before: number | undefined; limit: number }[] = []
  const read = async (before: number | undefined, limit: number) => {
    calls.push({ before, limit })
    return [...all]
      .reverse()
      .filter((e) => !before || e.seq < before)
      .slice(0, limit)
  }
  return { read, calls }
}

describe('audit filter', () => {
  it('comes from the URL, dropping a transition it does not know', () => {
    expect(auditFilterFrom(new URLSearchParams('actor=%20Anna%20&what=approved'))).toEqual({
      actor: 'Anna',
      what: 'approved',
    })
    expect(auditFilterFrom(new URLSearchParams('what=deleted'))).toEqual({ actor: '', what: '' })
    expect(isFiltered({ actor: '', what: '' })).toBe(false)
    expect(auditFilterFrom(new URLSearchParams(`actor=${'x'.repeat(100)}`)).actor).toHaveLength(64)
  })

  it('matches the actor case-insensitively and the transition exactly', () => {
    const e = entry(1, 'Anna', 'approved')
    expect(auditMatches(e, { actor: 'anna', what: '' })).toBe(true)
    expect(auditMatches(e, { actor: 'ann', what: '' })).toBe(false)
    expect(auditMatches(e, { actor: '', what: 'approved' })).toBe(true)
    expect(auditMatches(e, { actor: 'Anna', what: 'rejected' })).toBe(false)
  })

  it('lists the actors seen, once each', () => {
    expect(
      actorsIn([
        entry(1, 'Anna', 'approved'),
        entry(2, 'anna', 'active'),
        entry(3, 'ttl', 'reverted'),
      ]),
    ).toEqual(['Anna', 'ttl'])
  })
})

describe('scanAudit', () => {
  it('without a filter is one page, exactly as the log pages', async () => {
    const { read, calls } = reader(log(120))
    const page = await scanAudit(read, { actor: '', what: '' }, undefined, 50)
    expect(calls).toEqual([{ before: undefined, limit: 50 }])
    expect(page.entries.map((e) => e.seq)).toEqual(Array.from({ length: 50 }, (_, i) => 120 - i))
    expect(page.next).toBe(71)
    const last = await scanAudit(read, { actor: '', what: '' }, 21, 50)
    expect(last.entries).toHaveLength(20)
    expect(last.next).toBeUndefined()
  })

  it('reads batches until it has a page of matches, and goes on from the last one', async () => {
    const { read, calls } = reader(log(3000))
    const f = { actor: 'anna', what: 'approved' }
    const first = await scanAudit(read, f, undefined, 50, { batch: 100, maxBatches: 10 })
    expect(first.entries).toHaveLength(50)
    expect(first.entries[0].seq).toBe(3000)
    expect(first.entries.at(-1)!.seq).toBe(2510)
    expect(first.next).toBe(2510)
    expect(first.stopped).toBe(false)
    expect(calls).toHaveLength(5)

    const second = await scanAudit(read, f, first.next, 50, { batch: 100, maxBatches: 10 })
    expect(second.entries[0].seq).toBe(2500)
    expect(calls.at(-5)!.before).toBe(2510)
  })

  it('stops after its batch budget and says where to go on', async () => {
    const { read, calls } = reader(log(3000))
    const scan = await scanAudit(read, { actor: 'nobody', what: '' }, undefined, 50, {
      batch: 100,
      maxBatches: 3,
    })
    expect(calls).toHaveLength(3)
    expect(scan.entries).toEqual([])
    expect(scan.stopped).toBe(true)
    expect(scan.next).toBe(2701)
    expect(scan.scanned).toBe(300)
    expect(scan.oldestScanned).toBe(entry(2701, '', '').timestamp)
  })

  it('reaches the start of the log', async () => {
    const { read } = reader(log(150))
    const scan = await scanAudit(read, { actor: 'Anna', what: '' }, undefined, 50, { batch: 100 })
    expect(scan.entries).toHaveLength(15)
    expect(scan.next).toBeUndefined()
    expect(scan.stopped).toBe(false)
    expect(scan.scanned).toBe(150)
  })
})
