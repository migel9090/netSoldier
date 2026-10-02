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
}

// {mac} and {id} are intentionally narrow: a MAC or an action ID, nothing
// that could contain a slash, a dot-segment or an encoded separator.
const MAC = '([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})'
const ID = '([A-Za-z0-9_.:-]{1,128})'

export const ROUTES: Route[] = [
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: /^\/api\/devices$/,
    upstream: () => '/devices',
  },
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: new RegExp(`^/api/devices/${MAC}$`),
    upstream: (m) => `/devices/${m[1]}`,
  },
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: new RegExp(`^/api/devices/${MAC}/(connections|dns|alerts)$`),
    upstream: (m) => `/devices/${m[1]}/${m[2]}`,
  },
  {
    service: 'device-inventory',
    method: 'PUT',
    pattern: new RegExp(`^/api/devices/${MAC}/labels$`),
    upstream: (m) => `/devices/${m[1]}/labels`,
  },
  {
    service: 'device-inventory',
    method: 'GET',
    pattern: /^\/api\/topology$/,
    upstream: () => '/topology',
  },
  {
    service: 'detection-engine',
    method: 'GET',
    pattern: /^\/api\/alerts$/,
    upstream: () => '/alerts',
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
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/(pending|active)$/,
    upstream: (m) => `/actions/${m[1]}`,
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
  {
    service: 'killswitch',
    method: 'GET',
    pattern: /^\/api\/killswitch\/policy$/,
    upstream: () => '/policy',
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
