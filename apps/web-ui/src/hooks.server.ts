import type { Handle, RequestEvent, ServerInit } from '@sveltejs/kit'
import { building } from '$app/environment'
import { env } from '$env/dynamic/private'
import { SESSION_COOKIE, csrfOk, originOk, verifySession, type Session } from '$lib/server/auth'
import { readConfig, type Config } from '$lib/server/config'
import { log } from '$lib/server/log'
import { countUpstreamError, type UpstreamErrorKind } from '$lib/server/metrics'
import { startMetricsListener } from '$lib/server/metrics-listener'
import {
  PASSED_RESPONSE_HEADERS,
  callUpstream,
  matchRoute,
  upstreamQuery,
  type Service,
} from '$lib/server/upstream'

/**
 * Request pipeline for the household UI.
 *
 * Order matters: configuration, then the session, then — for anything that
 * changes state — Origin and CSRF, then the route allowlist, and only then a
 * backend. Sign-in and sign-out are ordinary `+server.ts` endpoints reached
 * through `resolve()`: SvelteKit only writes cookies set via `event.cookies`
 * onto responses that come out of `resolve()`, and answering /api/login from
 * the hook directly is why no browser could ever sign in.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD'])
const PUBLIC_PAGES = new Set(['/login'])

/** Upstream request bodies are small JSON documents; anything larger is refused. */
const MAX_PROXY_BODY_BYTES = 64 * 1024

export const init: ServerInit = async () => {
  const result = readConfig()
  if (result.ok) {
    log('INFO', 'web-ui configured', {
      origin: result.config.origin,
      secure_cookies: result.config.secureCookies,
    })
  } else {
    log('ERROR', 'web-ui is not configured; every request will get 503', {
      problems: result.problems,
    })
  }
  // /metrics has a listener of its own (METRICS_ADDR), never the UI's port.
  // adapter-node awaits this before it opens the UI's port, so a metrics
  // address that cannot be used stops the start-up with its reason.
  if (!building) await startMetricsListener(env.METRICS_ADDR)
}

export const handle: Handle = async ({ event, resolve }) => {
  const response = await route(event, resolve)
  return withSecurityHeaders(response, event.url)
}

async function route(event: RequestEvent, resolve: Parameters<Handle>[0]['resolve']) {
  const { pathname } = event.url
  const method = event.request.method
  const result = readConfig()

  // Probes stay unauthenticated. An unconfigured UI is not ready, so the
  // probe says so instead of reporting a healthy pod that serves only 503s.
  if (pathname === '/healthz') {
    return result.ok
      ? json({ status: 'ok' }, 200)
      : json({ status: 'unconfigured', problems: result.problems }, 503)
  }
  // Not served on this port, which is published on the LAN: the counters
  // are on the metrics listener. A plain 404, signed in or not, so a scrape
  // still aimed here fails as "not found" rather than following a redirect
  // to the sign-in page.
  if (pathname === '/metrics') return json({ error: 'not found' }, 404)

  const api = pathname === '/api' || pathname.startsWith('/api/')
  if (!result.ok) return unconfigured(result.problems, api)
  const config = result.config

  const session = verifySession(config.sessionSecret, event.cookies.get(SESSION_COOKIE))
  event.locals.session = session ?? undefined
  event.locals.actor = session?.actor

  if (api) {
    const mutating = !SAFE_METHODS.has(method)
    if (mutating && !originOk(event.request.headers.get('origin'), config.origin)) {
      return json({ error: 'cross-origin request refused' }, 403)
    }

    if (pathname === '/api/login') return resolve(event)
    if (pathname === '/api/logout') {
      // Signing out a live session needs its CSRF token: otherwise any page
      // the household visits could sign them out at will.
      if (mutating && session && !csrfOk(config.sessionSecret, session, csrfHeader(event))) {
        return json({ error: 'csrf check failed' }, 403)
      }
      return resolve(event)
    }

    if (!session) return json({ error: 'not signed in', reason: 'session' }, 401)
    if (mutating && !csrfOk(config.sessionSecret, session, csrfHeader(event))) {
      return json({ error: 'csrf check failed' }, 403)
    }
    return proxy(event, session, config)
  }

  if (PUBLIC_PAGES.has(pathname)) {
    if (session) return redirect('/')
    return resolve(event)
  }
  // Pages: anyone without a session goes to the sign-in page. SvelteKit turns
  // this into its JSON redirect form for client-side data requests.
  if (!session) return redirect('/login')
  return resolve(event)
}

function csrfHeader(event: RequestEvent): string | null {
  return event.request.headers.get('x-csrf-token')
}

async function proxy(event: RequestEvent, session: Session, config: Config): Promise<Response> {
  const method = event.request.method
  const matched = matchRoute(method, event.url.pathname)
  if (!matched) return json({ error: 'not found' }, 404)

  const { route, upstreamPath } = matched
  const query = upstreamQuery(route, event.url.searchParams)
  if (!query.ok) return json({ error: query.error }, 400)
  const upstream = config.upstreams[route.service]
  const target = `${upstream.url}${upstreamPath}${query.search}`

  // Built from scratch: nothing the browser sent (cookies, Authorization,
  // a forged X-Netsoldier-Actor) is forwarded. The actor passed the
  // printable-ASCII and reserved-name rules at sign-in, so it is a valid
  // header value and one the killswitch accepts on approve, reject and
  // revert (it refuses those without it).
  const headers: Record<string, string> = {
    Accept: 'application/json',
    Authorization: `Bearer ${upstream.key}`,
    'X-Netsoldier-Actor': session.actor,
  }

  let body: string | undefined
  if (!SAFE_METHODS.has(method)) {
    body = await event.request.text()
    if (Buffer.byteLength(body) > MAX_PROXY_BODY_BYTES) {
      return json({ error: 'request body too large' }, 413)
    }
    headers['Content-Type'] = 'application/json'
  }

  let res: Response
  try {
    res = await callUpstream(target, { method, headers, body })
  } catch (err) {
    const timedOut = err instanceof Error && err.name === 'AbortError'
    const kind = timedOut ? 'timeout' : 'unreachable'
    countUpstreamError(route.service, kind)
    log('WARN', 'upstream call failed', {
      service: route.service,
      path: upstreamPath,
      kind,
      error: err instanceof Error ? err.message : String(err),
    })
    return upstreamError(
      `${route.service} ${timedOut ? 'timed out' : 'is unreachable'}`,
      route.service,
      kind,
      timedOut ? 504 : 502,
    )
  }

  // A backend refusing our API key is a deployment problem, not an expired
  // session. Passing its 401 through made the page bounce the household to
  // the sign-in form in a loop; say what is wrong instead.
  if (res.status === 401 || res.status === 403) {
    await res.body?.cancel()
    countUpstreamError(route.service, 'auth')
    log('ERROR', 'upstream refused the web-ui credentials', {
      service: route.service,
      path: upstreamPath,
      status: res.status,
      key_var: upstream.keyVar,
    })
    return upstreamError(
      `${route.service} refused the web UI's credentials (HTTP ${res.status}). ` +
        `Check ${upstream.keyVar} in the web UI's configuration.`,
      route.service,
      'auth',
      502,
    )
  }

  // Always served as JSON: an upstream that answers with HTML must not get
  // to render a document on this origin. Other headers are dropped, except
  // the few the pages read.
  const out = new Headers({ 'Content-Type': 'application/json; charset=utf-8' })
  for (const name of PASSED_RESPONSE_HEADERS) {
    const value = res.headers.get(name)
    if (value !== null && /^\d{1,12}$/.test(value)) out.set(name, value)
  }
  return new Response(res.body, { status: res.status, headers: out })
}

/**
 * An error the proxy produced itself — the backend never answered, or
 * refused the UI's key. The header tells the page this was not the
 * backend's verdict on the request (see UPSTREAM_ERROR_HEADER in $lib/api).
 */
function upstreamError(
  error: string,
  service: Service,
  kind: UpstreamErrorKind,
  status: number,
): Response {
  return new Response(JSON.stringify({ error, upstream: service, kind }), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Netsoldier-Upstream-Error': kind },
  })
}

function unconfigured(problems: string[], api: boolean): Response {
  if (api) {
    return json({ error: 'web-ui is not configured', problems }, 503)
  }
  const text =
    'The netSoldier web UI is not configured, so it refuses to serve the killswitch ' +
    'approval UI.\n\n' +
    problems.map((p) => `  - ${p}\n`).join('') +
    '\nSet these environment variables and restart the web UI.\n'
  return new Response(text, {
    status: 503,
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  })
}

function redirect(location: string): Response {
  return new Response(null, { status: 303, headers: { Location: location } })
}

function json(payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// Pages get their Content-Security-Policy from SvelteKit (`kit.csp` in
// svelte.config.js), which adds a nonce to the inline script that boots the
// client. A fixed `script-src 'self'` header used to block that script and
// leave every page blank. Responses that are not pages get this policy.
const NON_PAGE_CSP =
  "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

/** Baseline headers for every response; never replaces the page CSP. */
function withSecurityHeaders(res: Response, url: URL): Response {
  const { pathname } = url
  let out = res
  try {
    out.headers.set('X-Content-Type-Options', 'nosniff')
  } catch {
    // Some responses (e.g. straight from fetch) have immutable headers.
    out = new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: new Headers(res.headers),
    })
  }
  const h = out.headers
  h.set('X-Content-Type-Options', 'nosniff')
  if (!h.has('Content-Security-Policy')) h.set('Content-Security-Policy', NON_PAGE_CSP)
  h.set('X-Frame-Options', 'DENY')
  h.set('Referrer-Policy', 'no-referrer')
  h.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
  // Browsers only honour COOP on trustworthy origins; over plain HTTP on a
  // LAN Chromium ignores it and logs an error on every page load.
  if (url.protocol === 'https:') h.set('Cross-Origin-Opener-Policy', 'same-origin')
  if (pathname.startsWith('/api/') || pathname === '/healthz') {
    h.set('Cache-Control', 'no-store')
  }
  return out
}
