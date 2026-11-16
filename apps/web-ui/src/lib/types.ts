/** How far device-inventory trusts a device's address (store.IPTentative etc.). */
export type IPState = 'tentative' | 'live' | 'stale'

/**
 * A claim device-inventory refused because it contradicted a live binding or
 * an established device: something on the network claiming to be this
 * device, or this device claiming what another holds. Kinds (store.Conflict):
 * `ip_taken` (`claimant` claimed `ip`, which `mac` holds), `ip_moved` (`mac`
 * claimed `value` while holding `ip`), `name` and `profile` (an equal-strength
 * source offered `value` as `mac`'s name or DHCP profile).
 */
export interface DeviceConflict {
  kind: string
  mac: string
  claimant?: string
  ip?: string
  value?: string
  source: string
  first_seen: string
  last_seen: string
  count: number
}

/**
 * A device as device-inventory serves it (contract v2 §5). Every value records
 * the source that set it; `conflicts` only comes with single-device reads,
 * the lists carry `conflict_count` alone.
 */
export interface Device {
  mac: string
  ip: string
  /** Which source bound the address: dhcp, arp, lldp, mdns, ssdp, lease. */
  ip_source?: string
  ip_state?: IPState | string
  ip_since?: string
  ip_confirmed_at?: string
  hostname: string
  hostname_source?: string
  dhcp_fingerprint: string
  vendor_class: string
  vendor: string
  os: string
  device_type: string
  randomized_mac?: boolean
  /** The row this device probably used before a MAC rotation; a hint only. */
  rotation_of?: string
  labels: string[] | null
  /** Labelled, or seen across 24 h: equal-strength sources cannot rename it. */
  established?: boolean
  /** Recent conflicts this device is involved in (as holder or claimant). */
  conflict_count?: number
  conflicts?: DeviceConflict[] | null
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
 * A detection-engine alert (GET /alerts, newest first). Contract v2 shape;
 * engines from before the rollout send no `summary`, no client name/MAC, and
 * `signals` as plain strings, so everything beyond id/timestamp/severity is
 * optional.
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
  /** `composite` for an alert that combines several signals. */
  signal_class?: string
  signals?: (AlertSignal | string)[]
  target?: { type: 'domain' | 'ip'; value: string }
}

/**
 * An active false-positive suppression (GET /feedback): the verdict that
 * created it. It silences `matched_ioc` for one signal class, on
 * `client_ip` or (empty) on every device, from `timestamp` for the engine's
 * suppression TTL (30 days unless configured otherwise).
 */
export interface Suppression {
  alert_id?: string
  matched_ioc: string
  client_ip?: string
  signal_class: string
  verdict: string
  reason?: string
  analyst?: string
  timestamp: string
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
 * Contract v2 §3 (killswitch-controller internal/actions/doc.go):
 *
 * - `pending` waits for a human;
 * - `approved` has its driver call outstanding — nothing confirmed yet, and
 *   it is in no list but GET /actions/{id};
 * - `active` is enforced;
 * - `revert_failed` is STILL ENFORCED (a revert did not take, or an apply
 *   could not be undone) and the controller keeps retrying;
 * - `reverted`, `rejected`, `expired` and `apply_failed` are finished.
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

export interface EnforcementAction {
  id: string
  timestamp: string
  detection_id: string
  detection_summary?: string
  client_name?: string
  action_type: string
  /** An {@link ActionState}; kept as string so an unknown state still renders. */
  state: string
  target_mac: string
  target_ip?: string
  blocked_domain?: string
  policy_rule: string
  auto_approved: boolean
  ttl_seconds?: number
  /** When the driver confirmed the apply. */
  activated_at?: string | null
  expires_at?: string | null
  reverted_at?: string | null
  approved_by?: string
  rejected_by?: string
  reverted_by?: string
  reason?: string
  /** Why the driver failed: an apply that never took, or a revert that did not lift. */
  failure_reason?: string
}

/**
 * One transition in the killswitch's audit log (GET /audit, newest first).
 * `from_state` is empty for the action's creation.
 */
export interface AuditEntry {
  seq: number
  timestamp: string
  action_id: string
  from_state: string
  to_state: string
  actor: string
  reason: string
  detection_id: string
  detection_summary: string
  target_mac: string
  target_ip: string
  action_type: string
  blocked_domain: string
  policy_rule: string
}

/** GET /policy: the part of it the approval page uses. */
export interface KillswitchPolicy {
  /** What an operator may choose in an approve right now. */
  available_action_types: string[]
  default_action?: string
  auto_block_allowed?: boolean
  auto_block_disabled_reason?: string
  default_ttl?: number
  pending_ttl_seconds?: number
}
