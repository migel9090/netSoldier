/**
 * Route allowlist and bounded upstream calls for the API proxy.
 *
 * The proxy used to build the backend URL by string-replacing a prefix on
 * whatever path arrived, so the caller controlled the tail of an internal
 * URL. Matching against an explicit table instead means only the routes the
 * UI actually uses can be reached, and nothing new is exposed by accident
 * when a backend grows an endpoint.
 */

export type Service = 'device-inventory' | 'detection-engine' | 'killswitch'

export interface Route {
  service: Service
  method: 'GET' | 'POST' | 'PUT'
  /** Pattern over the incoming /api path; {mac} and {id} are single segments. */
  pattern: RegExp
  /** Builds the upstream path from the match groups. */
  upstream: (m: RegExpMatchArray) => string
  /**
   * Query parameters passed on to the backend. Anything else is refused, so
   * a page cannot reach a backend option the UI does not use either.
   */
  query?: readonly string[]
}

// {mac} and {id} are intentionally narrow: a MAC or an action ID, nothing
// that could contain a slash, a dot-segment or an encoded separator. A MAC's
// colons may arrive percent-encoded (`%3A`) — encodeURIComponent produces
// that, and refusing it made every device detail page a 404 — so the
// separator accepts both spellings and the upstream path always uses `:`.
const MAC = '([0-9a-fA-F]{2}(?:(?::|%3[aA])[0-9a-fA-F]{2}){5})'
const ID = '([A-Za-z0-9_.:-]{1,128})'

function mac(raw: string): string {
  return raw.replace(/%3a/gi, ':')
}

export const ROUTES: Route[] = [
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: /^\/api\/devices$/,
    upstream: () => '/devices',
    query: ['limit', 'offset'],
  },
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: new RegExp(`^/api/devices/${MAC}$`),
    upstream: (m) => `/devices/${mac(m[1])}`,
  },
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: new RegExp(`^/api/devices/${MAC}/(connections|dns|alerts)$`),
    upstream: (m) => `/devices/${mac(m[1])}/${m[2]}`,
  },
  {
    service: 'device-inventory',
    method: 'PUT',
    pattern: new RegExp(`^/api/devices/${MAC}/labels$`),
    upstream: (m) => `/devices/${mac(m[1])}/labels`,
  },
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: /^\/api\/topology$/,
    upstream: () => '/topology',
    query: ['hours'],
  },
  {
    service: 'detection-engine',
    method: 'GET',
    pattern: /^\/api\/alerts$/,
    upstream: () => '/alerts',
    // GET /alerts returns 1000 alerts without ?limit=, and up to 5000 with it.
    query: ['limit'],
  },
  {
    service: 'detection-engine',
    method: 'GET',
    pattern: /^\/api\/feedback$/,
    upstream: () => '/feedback',
  },
  {
    service: 'detection-engine',
    method: 'POST',
    pattern: /^\/api\/feedback$/,
    upstream: () => '/feedback',
  },
  // Ends one suppression. A "confirmed" verdict used to stand in for it,
  // which records the indicator as a true positive: a different statement.
  {
    service: 'detection-engine',
    method: 'POST',
    pattern: /^\/api\/feedback\/lift$/,
    upstream: () => '/feedback/lift',
  },
  // The fixed killswitch names come before the generic {id} route: matching
  // is first-hit, and {id} would otherwise swallow them (it used to make
  // /api/killswitch/policy unreachable, and would send `audit` to
  // /actions/audit).
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/(pending|active|failed)$/,
    upstream: (m) => `/actions/${m[1]}`,
  },
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/history$/,
    upstream: () => '/actions/history',
    query: ['limit'],
  },
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/audit$/,
    upstream: () => '/audit',
    // Newest first; ?before=<seq> pages back, ?action_id= narrows to one action.
    query: ['limit', 'before', 'action_id'],
  },
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/policy$/,
    upstream: () => '/policy',
  },
  // The devices the controller must never act against (the operator's
  // list; the infrastructure it protects on its own is not listed there).
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/allowlist$/,
    upstream: () => '/allowlist',
  },
  {
    service: 'killswitch',
    method: 'GET',
    pattern: new RegExp(`^/api/killswitch/${ID}$`),
    upstream: (m) => `/actions/${m[1]}`,
  },
  {
    service: 'killswitch',
    method: 'POST',
    pattern: new RegExp(`^/api/killswitch/${ID}/(approve|reject|revert)$`),
    upstream: (m) => `/actions/${m[1]}/${m[2]}`,
  },
]

export interface Matched {
  route: Route
  upstreamPath: string
}

/** Resolves an incoming request to an allowlisted upstream path. */
export function matchRoute(method: string, pathname: string): Matched | null {
  // Reject anything with traversal or encoded separators before matching,
  // so a crafted path cannot reach a backend at all.
  if (pathname.includes('..') || /%2f|%5c/i.test(pathname)) return null

  for (const route of ROUTES) {
    if (route.method !== method) continue
    const m = pathname.match(route.pattern)
    if (m) return { route, upstreamPath: route.upstream(m) }
  }
  return null
}

export type QueryResult = { ok: true; search: string } | { ok: false; error: string }

/**
 * The query string sent upstream: the route's parameters, re-encoded, each
 * at most once. A parameter the route does not take is refused rather than
 * dropped, so a page asking for something the backend never sees fails
 * loudly instead of quietly getting the default.
 */
export function upstreamQuery(route: Route, params: URLSearchParams): QueryResult {
  const allowed = route.query ?? []
  const out = new URLSearchParams()
  for (const [name, value] of params) {
    if (!allowed.includes(name)) {
      return { ok: false, error: `query parameter "${name}" is not supported here` }
    }
    if (out.has(name)) return { ok: false, error: `query parameter "${name}" is repeated` }
    out.set(name, value)
  }
  const search = out.toString()
  return { ok: true, search: search ? `?${search}` : '' }
}

/**
 * Response headers passed on to the page, numeric values only.
 * device-inventory reports the size of its whole list in X-Total-Count;
 * GET /devices returns one page of it.
 */
export const PASSED_RESPONSE_HEADERS = ['x-total-count'] as const

/** Upstream request timeout: a hung backend must not hang the UI. */
export const UPSTREAM_TIMEOUT_MS = 10_000

export async function callUpstream(
  url: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<Response> {
  const { timeoutMs = UPSTREAM_TIMEOUT_MS, ...rest } = init
  // Node's fetch has no default timeout, so without this a stalled backend
  // pins a UI request until the client gives up.
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { ...rest, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}
