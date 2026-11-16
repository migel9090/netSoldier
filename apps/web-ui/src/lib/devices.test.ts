import { describe, expect, it } from 'vitest'
import { bindingWords, conflictCount, describeConflict, sourceName } from './devices'
import type { DeviceConflict } from './types'

const TABLET = 'aa:bb:cc:00:00:01'
const INTRUDER = '02:de:ad:be:ef:01'

function conflict(over: Partial<DeviceConflict>): DeviceConflict {
  return {
    kind: 'ip_taken',
    mac: TABLET,
    claimant: INTRUDER,
    ip: '192.168.1.77',
    source: 'arp',
    first_seen: '2026-11-16T10:00:00Z',
    last_seen: '2026-11-16T10:05:00Z',
    count: 3,
    ...over,
  }
}

describe('device conflicts', () => {
  it('on the holder’s page: another device is claiming to be this one', () => {
    const t = describeConflict(conflict({}), TABLET)
    expect(t.what).toBe(
      `Another device (${INTRUDER}) claimed this device's address 192.168.1.77 over ARP.`,
    )
    expect(t.meaning).toMatch(/claiming to be this device/)
    expect(t.other).toBe(INTRUDER)
  })

  it('on the claimant’s page: this device tried to take another’s address', () => {
    const t = describeConflict(conflict({}), INTRUDER.toUpperCase())
    expect(t.what).toContain(`which ${TABLET} holds`)
    expect(t.other).toBe(TABLET)
  })

  it('describes a second address, a name and a profile', () => {
    expect(
      describeConflict(conflict({ kind: 'ip_moved', claimant: '', value: '192.168.1.99' }), TABLET)
        .what,
    ).toContain('second address, 192.168.1.99')
    expect(
      describeConflict(
        conflict({ kind: 'name', claimant: '', value: 'evil', source: 'mdns' }),
        TABLET,
      ).what,
    ).toBe('mDNS offered the name "evil" for this device.')
    expect(
      describeConflict(conflict({ kind: 'profile', claimant: '', value: '1,3,6' }), TABLET).meaning,
    ).toMatch(/Another device may be using this MAC/)
  })

  it('counts conflicts from the list count or the attached ones', () => {
    expect(conflictCount({ conflict_count: 2 })).toBe(2)
    expect(conflictCount({ conflict_count: 0, conflicts: [conflict({})] })).toBe(1)
    expect(conflictCount({})).toBe(0)
  })
})

describe('provenance', () => {
  it('says how far the address is trusted and where it came from', () => {
    expect(bindingWords({ ip: '192.168.1.77', ip_state: 'live' })).toMatch(/^live/)
    expect(bindingWords({ ip: '192.168.1.77', ip_state: 'stale' })).toMatch(/may take it over/)
    expect(bindingWords({ ip: '', ip_state: '' })).toBe('no address')
    expect(sourceName('dhcp')).toBe('DHCP')
    expect(sourceName(undefined)).toBe('unknown source')
  })
})
