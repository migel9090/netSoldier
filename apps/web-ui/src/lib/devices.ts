import type { Device, DeviceConflict } from './types'

/**
 * How device-inventory's provenance and conflicts read for the household
 * (device-inventory internal/store/doc.go). A conflict is a claim the
 * inventory refused because it contradicted a live binding or an
 * established device: most often something on the network claiming to be
 * this device.
 */

const SOURCES: Record<string, string> = {
  dhcp: 'DHCP',
  arp: 'ARP',
  lldp: 'LLDP',
  mdns: 'mDNS',
  ssdp: 'SSDP',
  lease: "the router's lease table",
}

export function sourceName(source: string | undefined): string {
  if (!source) return 'unknown source'
  return SOURCES[source] ?? source
}

/** The address binding in words: how far the inventory trusts it. */
export function bindingWords(d: Pick<Device, 'ip' | 'ip_state'>): string {
  if (!d.ip) return 'no address'
  switch (d.ip_state) {
    case 'live':
      return 'live (re-confirmed recently)'
    case 'tentative':
      return 'tentative (seen once, not yet re-confirmed)'
    case 'stale':
      return 'stale (not confirmed lately; another device may take it over)'
    default:
      return d.ip_state ? d.ip_state : 'unknown'
  }
}

/** Number of recent conflicts; the lists carry only the count. */
export function conflictCount(d: Pick<Device, 'conflict_count' | 'conflicts'>): number {
  const n = d.conflict_count ?? 0
  return Math.max(n, d.conflicts?.length ?? 0)
}

export interface ConflictText {
  /** One sentence: who claimed what. */
  what: string
  /** Why it matters. */
  meaning: string
  /** The other device involved, if any, for a link. */
  other: string
}

/**
 * One conflict, from the point of view of the device page it is shown on
 * (`self`): it is listed on both the holder's and the claimant's page.
 */
export function describeConflict(c: DeviceConflict, self: string): ConflictText {
  const me = self.toLowerCase()
  const via = sourceName(c.source)
  switch (c.kind) {
    case 'ip_taken':
      if (c.claimant && c.claimant.toLowerCase() !== me) {
        return {
          what: `Another device (${c.claimant}) claimed this device's address ${c.ip ?? ''} over ${via}.`,
          meaning:
            'Something on the network is claiming to be this device. It was refused: the address stays with this device.',
          other: c.claimant,
        }
      }
      return {
        what: `This device claimed the address ${c.ip ?? ''} over ${via}, which ${c.mac} holds.`,
        meaning:
          'This device tried to take over the address of another one. It was refused: the address stays where it was.',
        other: c.mac,
      }
    case 'ip_moved':
      return {
        what: `This device claimed a second address, ${c.value ?? ''}, over ${via} while holding ${c.ip ?? 'its address'}.`,
        meaning:
          "Either something else is using this device's MAC address, or the device really uses two addresses. The second was not applied.",
        other: '',
      }
    case 'name':
      return {
        what: `${via} offered the name "${c.value ?? ''}" for this device.`,
        meaning:
          'Something on the network is announcing a different name for this device. The name it already had was kept.',
        other: '',
      }
    case 'profile':
      return {
        what: `A DHCP request from this device's MAC address described different hardware or software (${c.value ?? ''}).`,
        meaning:
          'Another device may be using this MAC address. The profile the device already had was kept.',
        other: '',
      }
    default:
      return {
        what: `${c.kind} over ${via}${c.value ? `: ${c.value}` : ''}.`,
        meaning: 'The inventory refused a claim about this device.',
        other: c.claimant && c.claimant.toLowerCase() !== me ? c.claimant : '',
      }
  }
}

/** Single-device reads attach at most this many conflicts (device-inventory maxConflictsShown). */
export const CONFLICTS_SHOWN = 10
