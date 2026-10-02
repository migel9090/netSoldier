import type {
  Device,
  Alert,
  EnforcementAction,
  TopologyData,
  DeviceConnection,
  DeviceDNS,
  DeviceAlert,
} from './types'

/**
 * Reads the double-submit CSRF token the server set at login.
 *
 * Every mutating call echoes it in X-CSRF-Token. The server also checks
 * Origin; this is the second half of the pair, and without it a cross-site
 * POST would be accepted because the proxy runs before SvelteKit's own CSRF
 * protection.
 */
function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)netsoldier_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : ''
}

/** Headers for a mutating request. */
function mutateHeaders(): Record<string, string> {
  return { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() }
}

/**
 * Wraps fetch so an expired session sends the operator back to login instead
 * of surfacing as an opaque error on a page full of stale data.
 */
async function guard(res: Response): Promise<Response> {
  if (res.status === 401) {
    window.location.href = '/login'
    throw new Error('Session expired')
  }
  return res
}

export async function fetchDevices(): Promise<Device[]> {
  const res = await guard(await fetch('/api/devices'))
  if (!res.ok) throw new Error(`Devices API: ${res.status}`)
  return res.json()
}

export async function fetchAlerts(): Promise<Alert[]> {
  const res = await guard(await fetch('/api/alerts'))
  if (!res.ok) throw new Error(`Alerts API: ${res.status}`)
  return res.json()
}

export async function fetchDevice(mac: string): Promise<Device> {
  const res = await guard(await fetch(`/api/devices/${encodeURIComponent(mac)}`))
  if (!res.ok) throw new Error(`Device API: ${res.status}`)
  return res.json()
}

export async function fetchDeviceConnections(mac: string): Promise<DeviceConnection[]> {
  const res = await guard(await fetch(`/api/devices/${encodeURIComponent(mac)}/connections`))
  if (!res.ok) throw new Error(`Connections API: ${res.status}`)
  return (await res.json()) ?? []
}

export async function fetchDeviceDNS(mac: string): Promise<DeviceDNS[]> {
  const res = await guard(await fetch(`/api/devices/${encodeURIComponent(mac)}/dns`))
  if (!res.ok) throw new Error(`DNS API: ${res.status}`)
  return (await res.json()) ?? []
}

export async function fetchDeviceAlerts(mac: string): Promise<DeviceAlert[]> {
  const res = await guard(await fetch(`/api/devices/${encodeURIComponent(mac)}/alerts`))
  if (!res.ok) throw new Error(`Alerts API: ${res.status}`)
  return (await res.json()) ?? []
}

export async function fetchTopology(hours = 1): Promise<TopologyData> {
  const res = await guard(await fetch(`/api/topology?hours=${hours}`))
  if (!res.ok) throw new Error(`Topology API: ${res.status}`)
  return res.json()
}

export async function fetchPendingActions(): Promise<EnforcementAction[]> {
  const res = await guard(await fetch('/api/killswitch/pending'))
  if (!res.ok) throw new Error(`Killswitch API: ${res.status}`)
  return (await res.json()) ?? []
}

export async function fetchActiveActions(): Promise<EnforcementAction[]> {
  const res = await guard(await fetch('/api/killswitch/active'))
  if (!res.ok) throw new Error(`Killswitch API: ${res.status}`)
  return (await res.json()) ?? []
}

export async function approveAction(id: string): Promise<EnforcementAction> {
  const res = await guard(
    await fetch(`/api/killswitch/${id}/approve`, {
      method: 'POST',
      headers: mutateHeaders(),
      body: JSON.stringify({ approved_by: 'web-ui' }),
    }),
  )
  if (!res.ok) throw new Error(`Approve failed: ${res.status}`)
  return res.json()
}

export async function rejectAction(id: string, reason: string): Promise<EnforcementAction> {
  const res = await guard(
    await fetch(`/api/killswitch/${id}/reject`, {
      method: 'POST',
      headers: mutateHeaders(),
      body: JSON.stringify({ reason }),
    }),
  )
  if (!res.ok) throw new Error(`Reject failed: ${res.status}`)
  return res.json()
}

export async function revertAction(id: string, reason: string): Promise<EnforcementAction> {
  const res = await guard(
    await fetch(`/api/killswitch/${id}/revert`, {
      method: 'POST',
      headers: mutateHeaders(),
      body: JSON.stringify({ reason }),
    }),
  )
  if (!res.ok) throw new Error(`Revert failed: ${res.status}`)
  return res.json()
}

export interface FeedbackVerdict {
  alert_id?: string
  matched_ioc: string
  client_ip?: string
  verdict: 'false_positive' | 'confirmed'
  reason?: string
  analyst?: string
}

export async function submitFeedback(v: FeedbackVerdict): Promise<void> {
  const res = await guard(
    await fetch('/api/feedback', {
      method: 'POST',
      headers: mutateHeaders(),
      body: JSON.stringify({ analyst: 'web-ui', ...v }),
    }),
  )
  if (!res.ok) throw new Error(`Feedback failed: ${res.status}`)
}

export function formatTime(iso: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function formatActionType(t: string): string {
  switch (t) {
    case 'dns_sinkhole':
      return 'DNS Sinkhole'
    case 'arp_isolate':
      return 'ARP Isolation'
    case 'switch_acl':
      return 'Switch ACL'
    default:
      return t
  }
}
