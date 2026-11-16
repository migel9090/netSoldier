import type {
  Device,
  Alert,
  AuditEntry,
  EnforcementAction,
  KillswitchPolicy,
  Suppression,
  TopologyData,
  DeviceConnection,
  DeviceDNS,
  DeviceAlert,
} from './types'

/**
 * Set by the web UI's proxy on errors it produced itself (backend unreachable,
 * timed out, refusing the UI's API key), as opposed to a backend's own answer.
 */
export const UPSTREAM_ERROR_HEADER = 'X-Netsoldier-Upstream-Error'

/** An API call that failed; `message` is meant to be shown as is. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/**
 * Reads the CSRF token the server set at sign-in.
 *
 * Every mutating call echoes it in X-CSRF-Token; the server also checks
 * Origin. The token is bound to the session, so it is only valid together
 * with the HttpOnly session cookie it was issued with.
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
 * fetch, with an expired session sending the household back to sign-in.
 *
 * Only the web UI's own session check answers 401: a backend rejecting the
 * UI's API key comes back as a 502 that names the misconfiguration, so it can
 * no longer bounce the page to /login in a loop.
 */
async function request(path: string, init?: RequestInit): Promise<Response> {
  let res: Response
  try {
    res = await fetch(path, init)
  } catch {
    throw new ApiError(0, 'The web UI server could not be reached')
  }
  if (res.status === 401) {
    window.location.href = '/login'
    throw new ApiError(401, 'Your session has expired; sign in again')
  }
  return res
}

async function readJSON(res: Response): Promise<unknown> {
  try {
    return await res.json()
  } catch {
    return null
  }
}

function errorText(body: unknown, res: Response): string {
  if (body && typeof body === 'object' && typeof (body as { error?: unknown }).error === 'string') {
    return (body as { error: string }).error
  }
  return `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}`
}

async function fail(res: Response, what: string): Promise<never> {
  throw new ApiError(res.status, `${what}: ${errorText(await readJSON(res), res)}`)
}

async function getJSON<T>(path: string, what: string): Promise<T> {
  const res = await request(path)
  if (!res.ok) return fail(res, what)
  const body = await readJSON(res)
  if (body === null) throw new ApiError(502, `${what}: unreadable response`)
  return body as T
}

/**
 * A list endpoint. `null` is how Go encodes a nil slice, so it is an empty
 * list; anything that is not an array is an error, never "no data".
 */
async function getList<T>(path: string, what: string): Promise<T[]> {
  return readList<T>(await request(path), what)
}

async function readList<T>(res: Response, what: string): Promise<T[]> {
  if (!res.ok) return fail(res, what)
  const text = await res.text()
  let body: unknown
  try {
    body = JSON.parse(text)
  } catch {
    throw new ApiError(502, `${what}: unreadable response`)
  }
  if (body === null) return []
  if (!Array.isArray(body)) throw new ApiError(502, `${what}: unexpected response`)
  return body as T[]
}

const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/

/** Lower-case colon-separated MAC, or null when `raw` is not a MAC. */
export function normaliseMac(raw: string): string | null {
  const mac = raw.trim().toLowerCase().replace(/-/g, ':')
  return MAC_RE.test(mac) ? mac : null
}

// The MAC goes into the path as is: it is validated, and its colons are
// legal in a path segment. encodeURIComponent turned them into %3A, which
// the proxy's route allowlist did not accept — every detail page was a 404.
function devicePath(mac: string): string {
  const m = normaliseMac(mac)
  if (!m) throw new ApiError(400, `"${mac}" is not a MAC address`)
  return `/api/devices/${m}`
}

const ACTION_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/

export function isActionId(id: string): boolean {
  return ACTION_ID_RE.test(id) && !id.includes('..')
}

function actionPath(id: string): string {
  if (!isActionId(id)) throw new ApiError(400, `"${id}" is not an action id`)
  return `/api/killswitch/${id}`
}

/** GET /devices returns at most this many per page (contract v2 §5). */
export const DEVICE_PAGE_LIMIT = 1000

export interface DevicePage {
  devices: Device[]
  /** The inventory's size (X-Total-Count); more than `devices.length` when truncated. */
  total: number
}

export async function fetchDevices(): Promise<DevicePage> {
  const res = await request(`/api/devices?limit=${DEVICE_PAGE_LIMIT}`)
  const total = Number(res.headers.get('X-Total-Count'))
  const devices = await readList<Device>(res, 'Device inventory')
  return { devices, total: Number.isFinite(total) && total > 0 ? total : devices.length }
}

/** How many alerts a page asks for at first; GET /alerts caps ?limit= at 5000. */
export const ALERTS_LIMIT = 500
export const ALERTS_MAX_LIMIT = 5000

/** The newest `limit` alerts, newest first. */
export async function fetchAlerts(limit = ALERTS_LIMIT): Promise<Alert[]> {
  const n = Math.max(1, Math.min(ALERTS_MAX_LIMIT, Math.floor(limit)))
  return getList<Alert>(`/api/alerts?limit=${n}`, 'Detection engine')
}

export async function fetchDevice(mac: string): Promise<Device> {
  return getJSON<Device>(devicePath(mac), 'Device inventory')
}

export async function fetchDeviceConnections(mac: string): Promise<DeviceConnection[]> {
  return getList<DeviceConnection>(`${devicePath(mac)}/connections`, 'Connections')
}

export async function fetchDeviceDNS(mac: string): Promise<DeviceDNS[]> {
  return getList<DeviceDNS>(`${devicePath(mac)}/dns`, 'DNS queries')
}

export async function fetchDeviceAlerts(mac: string): Promise<DeviceAlert[]> {
  return getList<DeviceAlert>(`${devicePath(mac)}/alerts`, 'Device alerts')
}

export async function fetchTopology(hours = 1): Promise<TopologyData> {
  return getJSON<TopologyData>(`/api/topology?hours=${hours}`, 'Topology')
}

export async function fetchPendingActions(): Promise<EnforcementAction[]> {
  return getList<EnforcementAction>('/api/killswitch/pending', 'Killswitch')
}

/** Everything still enforced: `active` and `revert_failed`. Not `approved`. */
export async function fetchActiveActions(): Promise<EnforcementAction[]> {
  return getList<EnforcementAction>('/api/killswitch/active', 'Killswitch')
}

export async function fetchFailedActions(): Promise<EnforcementAction[]> {
  return getList<EnforcementAction>('/api/killswitch/failed', 'Killswitch failures')
}

/** GET /actions/history: default 100, at most 500, and no way to page past that. */
export const HISTORY_MAX_LIMIT = 500

/** Finished actions, most recently finished first. */
export async function fetchActionHistory(limit = 50): Promise<EnforcementAction[]> {
  const n = Math.max(1, Math.min(HISTORY_MAX_LIMIT, Math.floor(limit)))
  return getList<EnforcementAction>(`/api/killswitch/history?limit=${n}`, 'Killswitch history')
}

export interface AuditQuery {
  limit?: number
  /** Entries older than this sequence number. */
  before?: number
  actionId?: string
}

/** The killswitch's audit log, newest first. */
export async function fetchAudit(q: AuditQuery = {}): Promise<AuditEntry[]> {
  const params = new URLSearchParams()
  params.set('limit', String(Math.max(1, Math.min(500, Math.floor(q.limit ?? 50)))))
  if (q.before !== undefined && Number.isSafeInteger(q.before) && q.before > 0) {
    params.set('before', String(q.before))
  }
  if (q.actionId) {
    if (!isActionId(q.actionId)) throw new ApiError(400, `"${q.actionId}" is not an action id`)
    params.set('action_id', q.actionId)
  }
  return getList<AuditEntry>(`/api/killswitch/audit?${params}`, 'Killswitch audit log')
}

export async function fetchPolicy(): Promise<KillswitchPolicy> {
  const body = await getJSON<Record<string, unknown>>('/api/killswitch/policy', 'Killswitch policy')
  const types = body.available_action_types
  return {
    ...body,
    available_action_types: Array.isArray(types)
      ? types.filter((t): t is string => typeof t === 'string')
      : [],
  } as KillswitchPolicy
}

/** One action by id; `null` when the controller does not know it. */
export async function fetchAction(id: string): Promise<EnforcementAction | null> {
  const res = await request(actionPath(id))
  if (res.status === 404) return null
  if (!res.ok) return fail(res, 'Killswitch')
  const body = await readJSON(res)
  return isAction(body) ? body : null
}

/**
 * What a killswitch mutation answered. Callers MUST look at `action.state`,
 * not just `ok`: an approve can succeed as a request and still report
 * `apply_failed`, a 202 means the driver has not finished, a failed revert
 * comes back as a 502 whose body is the action, still enforced, and a 409
 * carries the action as it now is.
 */
export interface ActionResult {
  ok: boolean
  status: number
  /** The action from the response body, when the body is one. */
  action: EnforcementAction | null
  error: string
  /** 422: the action types the controller can carry out now. */
  available: string[] | null
  /**
   * The web UI's proxy produced this response (backend unreachable, timed
   * out, or refusing the UI's API key): the controller never answered.
   */
  fromProxy: boolean
}

export function isAction(v: unknown): v is EnforcementAction {
  return (
    typeof v === 'object' &&
    v !== null &&
    typeof (v as { id?: unknown }).id === 'string' &&
    typeof (v as { state?: unknown }).state === 'string'
  )
}

function availableTypes(body: unknown): string[] | null {
  const v = (body as { available_action_types?: unknown } | null)?.available_action_types
  return Array.isArray(v) ? v.filter((t): t is string => typeof t === 'string') : null
}

async function mutateAction(
  id: string,
  verb: 'approve' | 'reject' | 'revert',
  body: Record<string, string>,
): Promise<ActionResult> {
  const res = await request(`${actionPath(id)}/${verb}`, {
    method: 'POST',
    headers: mutateHeaders(),
    body: JSON.stringify(body),
  })
  const parsed = await readJSON(res)
  // A 502 revert_failed and a 409 carry the action AND an error.
  return {
    ok: res.ok,
    status: res.status,
    action: isAction(parsed) ? parsed : null,
    error: res.ok ? '' : errorText(parsed, res),
    available: res.status === 422 ? availableTypes(parsed) : null,
    fromProxy: res.headers.has(UPSTREAM_ERROR_HEADER),
  }
}

// The approver, rejecter and reverter are taken from the session by the
// proxy (X-Netsoldier-Actor), never from these bodies — contract v2 §3.

/**
 * Approves a pending action. `actionType` is the operator's choice of
 * enforcement; without it the controller applies the type it proposed.
 */
export function approveAction(id: string, actionType?: string): Promise<ActionResult> {
  return mutateAction(id, 'approve', actionType ? { action_type: actionType } : {})
}

export function rejectAction(id: string, reason: string): Promise<ActionResult> {
  return mutateAction(id, 'reject', { reason })
}

export function revertAction(id: string, reason: string): Promise<ActionResult> {
  return mutateAction(id, 'revert', { reason })
}

export async function signOut(): Promise<void> {
  const res = await fetch('/api/logout', { method: 'POST', headers: mutateHeaders() })
  if (!res.ok) await fail(res, 'Sign-out failed')
}

/**
 * A verdict for POST /feedback. The analyst is not part of it: the engine
 * takes it from X-Netsoldier-Actor, which the proxy sets from the session.
 */
export interface FeedbackVerdict {
  alert_id?: string
  matched_ioc: string
  client_ip?: string
  /** Required by the engine, unless it still holds the alert named by alert_id. */
  signal_class?: string
  verdict: 'false_positive' | 'confirmed'
  reason?: string
}

export interface FeedbackResult {
  /**
   * False: the verdict is in force now but was not saved (ClickHouse
   * unavailable), so it is forgotten when the detection engine restarts.
   * Null when the engine did not say.
   */
  persisted: boolean | null
}

export async function submitFeedback(v: FeedbackVerdict): Promise<FeedbackResult> {
  const res = await request('/api/feedback', {
    method: 'POST',
    headers: mutateHeaders(),
    body: JSON.stringify(v),
  })
  if (!res.ok) await fail(res, 'Feedback failed')
  const body = (await readJSON(res)) as { persisted?: unknown } | null
  return { persisted: typeof body?.persisted === 'boolean' ? body.persisted : null }
}

/** The false-positive suppressions in force. */
export async function fetchSuppressions(): Promise<Suppression[]> {
  return getList<Suppression>('/api/feedback', 'Suppressions')
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString()
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
