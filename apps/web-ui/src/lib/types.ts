export interface Device {
  mac: string
  ip: string
  hostname: string
  dhcp_fingerprint: string
  vendor_class: string
  vendor: string
  os: string
  device_type: string
  stable_id?: string
  labels: string[]
  first_seen: string
  last_seen: string
}

/** One signal of a contract v2 detection: its own class, confidence and indicator. */
export interface AlertSignal {
  class: string
  confidence?: number
  indicator?: string
  indicator_type?: string
  source?: string
}

/**
 * A detection-engine alert (GET /alerts). Contract v2 shape; engines from
 * before the rollout send no `summary`, no client name/MAC, and `signals`
 * as plain strings, so everything beyond id/timestamp/severity is optional.
 */
export interface Alert {
  id: string
  timestamp: string
  /** The only field meant for display (v2; always present there). */
  summary?: string
  /** The DNS name actually observed; empty for IDS, volumetric and IP-only detections. */
  domain?: string
  matched_ioc?: string
  ioc_type?: string
  client_ip?: string
  client_mac?: string
  client_name?: string
  query_type?: string
  severity: string
  source?: string
  confidence?: number
  mitre_id?: string
  mitre_name?: string
  threat?: string
  tags?: string[]
  signal_class?: string
  signals?: (AlertSignal | string)[]
  target?: { type: 'domain' | 'ip'; value: string }
}

export interface TopologyNode {
  id: string
  label: string
  mac: string
  ip: string
  device_type: string
  vendor: string
  is_local: boolean
  total_bytes: number
  connection_count: number
}

export interface TopologyEdge {
  source: string
  target: string
  total_bytes: number
  total_packets: number
  flow_count: number
}

export interface TopologyData {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

export interface DeviceConnection {
  timestamp: string
  dst_ip: string
  dst_domain: string
  dst_port: number
  protocol: number
  bytes_in: number
  bytes_out: number
  duration_ms: number
}

export interface DeviceDNS {
  timestamp: string
  domain: string
  query_type: string
  answer: string
  status: string
  response_ms: number
  blocked: number
}

/** A device's alerts from device-inventory; may carry the v2 `summary` too. */
export interface DeviceAlert {
  timestamp: string
  id: string
  summary?: string
  domain?: string
  query_type?: string
  matched_ioc?: string
  severity: string
  source?: string
}

/**
 * Contract v2 §3. `failed` is the legacy single failure state of controllers
 * that predate `apply_failed`/`revert_failed`; it still has to render as a
 * failure.
 */
export type ActionState =
  | 'pending'
  | 'approved'
  | 'active'
  | 'reverted'
  | 'rejected'
  | 'expired'
  | 'apply_failed'
  | 'revert_failed'
  | 'failed'

export interface EnforcementAction {
  id: string
  timestamp: string
  detection_id: string
  action_type: string
  /** An {@link ActionState}; kept as string so an unknown state still renders. */
  state: string
  target_mac: string
  target_ip?: string
  blocked_domain?: string
  policy_rule: string
  auto_approved: boolean
  ttl_seconds?: number
  expires_at?: string | null
  reverted_at?: string | null
  approved_by?: string
  reason?: string
  /** Why the driver failed: an apply that never took, or a revert that did not lift. */
  failure_reason?: string
  // Contract v2 additions; absent on older controllers.
  detection_summary?: string
  client_name?: string
  activated_at?: string | null
  rejected_by?: string
  reverted_by?: string
}
