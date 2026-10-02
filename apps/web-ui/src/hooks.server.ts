import type { Handle } from '@sveltejs/kit'
import { env } from '$env/dynamic/private'
import {
  CSRF_COOKIE,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  csrfOk,
  newCsrfToken,
  verifySession,
} from '$lib/server/auth'
import { callUpstream, matchRoute, type Service } from '$lib/server/upstream'

/**
 * Request pipeline for the household UI.
 *
 * Order matters: authenticate, then CSRF-check, then match the request
 * against an allowlist of upstream routes, and only then talk to a backend.
 * The previous version did none of these — it matched a path prefix and
 * forwarded, attaching KILLSWITCH_API_KEY on the way out, which made the UI
 * a confused deputy for anyone who could reach port 3000.
 */

const PUBLIC_PATHS = new Set(['/login', '/healthz'])

export const handle: Handle = async ({ event, resolve }) => {
  const { pathname } = event.url
  const secret = env.SESSION_SECRET ?? ''
  const password = env.WEB_UI_PASSWORD ?? ''

  // Fail closed: with no secret configured we cannot issue or verify a
  // session, so refuse rather than serve the UI unauthenticated.
  if (!secret || !password) {
    if (pathname === '/healthz') return json({ status: 'ok' }, 200)
    return json(
      {
        error:
          'web-ui is not configured: set SESSION_SECRET and WEB_UI_PASSWORD. ' +
          'Refusing to serve the killswitch approval UI without authentication.',
      },
      503,
    )
  }

  const session = verifySession(secret, event.cookies.get(SESSION_COOKIE))
  event.locals.actor = session?.actor

  if (pathname === '/healthz') return json({ status: 'ok' }, 200)

  // Login is handled here so the credential check never reaches a route
  // that could be rendered or cached.
  if (pathname === '/api/login') {
    return handleLogin(event, secret, password)
  }
  if (pathname === '/api/logout') {
    event.cookies.delete(SESSION_COOKIE, { path: '/' })
    event.cookies.delete(CSRF_COOKIE, { path: '/' })
    return json({ status: 'logged out' }, 200)
  }

  if (pathname.startsWith('/api/')) {
    if (!session) return json({ error: 'unauthorized' }, 401)

    if (
      !csrfOk(
        event.request.method,
        event.request.headers.get('origin'),
        event.url.origin,
        event.request.headers.get('x-csrf-token'),
        event.cookies.get(CSRF_COOKIE),
      )
    ) {
      return json({ error: 'csrf check failed' }, 403)
    }

    return proxy(event, session.actor)
  }

  // Page requests: send anyone without a session to the login page.
  if (!session && !PUBLIC_PATHS.has(pathname)) {
    return new Response(null, { status: 302, headers: { location: '/login' } })
  }

  const response = await resolve(event)
  return withSecurityHeaders(response)
}

async function handleLogin(
  event: Parameters<Handle>[0]['event'],
  secret: string,
  password: string,
): Promise<Response> {
  if (event.request.method !== 'POST') return json({ error: 'method not allowed' }, 405)

  const { issueSession, safeEqual } = await import('$lib/server/auth')
  let body: { password?: string; actor?: string }
  try {
    body = await event.request.json()
  } catch {
    return json({ error: 'invalid body' }, 400)
  }

  if (!body.password || !safeEqual(body.password, password)) {
    // Deliberately vague, and slow enough that the shared password is not
    // worth brute-forcing over a LAN.
    await new Promise((r) => setTimeout(r, 500))
    return json({ error: 'invalid credentials' }, 401)
  }

  // The actor label is self-asserted — there is no user directory until
  // step 159 — but recording it still answers "which household member
  // approved this" far better than the previous blank field.
  const actor = (body.actor ?? '').trim().slice(0, 64) || 'household'
  const secure = event.url.protocol === 'https:'

  event.cookies.set(SESSION_COOKIE, issueSession(secret, actor), {
    path: '/',
    httpOnly: true,
    sameSite: 'strict',
    secure,
    maxAge: SESSION_TTL_SECONDS,
  })
  // Readable by the page on purpose: this is the double-submit token the
  // client echoes back in X-CSRF-Token.
  event.cookies.set(CSRF_COOKIE, newCsrfToken(), {
    path: '/',
    httpOnly: false,
    sameSite: 'strict',
    secure,
    maxAge: SESSION_TTL_SECONDS,
  })

  return json({ status: 'ok', actor }, 200)
}

function upstreamBase(service: Service): string {
  switch (service) {
    case 'device-inventory':
      return env.DEVICE_INVENTORY_URL || 'http://device-inventory:8081'
    case 'detection-engine':
      return env.DETECTION_ENGINE_URL || 'http://detection-engine:8080'
    case 'killswitch':
      return env.KILLSWITCH_URL || 'http://killswitch-controller:8084'
  }
}

function upstreamToken(service: Service): string {
  switch (service) {
    case 'device-inventory':
      return env.DEVICE_API_KEY || ''
    case 'detection-engine':
      return env.DETECTION_API_KEY || ''
    case 'killswitch':
      return env.KILLSWITCH_API_KEY || ''
  }
}

async function proxy(event: Parameters<Handle>[0]['event'], actor: string): Promise<Response> {
  const matched = matchRoute(event.request.method, event.url.pathname)
  if (!matched) return json({ error: 'not found' }, 404)

  const { route, upstreamPath } = matched
  const search = event.url.search ?? ''
  const target = `${upstreamBase(route.service)}${upstreamPath}${search}`

  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = upstreamToken(route.service)
  if (token) headers['Authorization'] = `Bearer ${token}`
  // Let the backend attribute the action to a person rather than recording
  // whatever the request body claimed.
  headers['X-Netsoldier-Actor'] = actor

  try {
    const body = event.request.method === 'GET' ? undefined : await event.request.text()
    const res = await callUpstream(target, { method: event.request.method, headers, body })
    return withSecurityHeaders(
      new Response(res.body as ReadableStream, {
        status: res.status,
        headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' },
      }),
    )
  } catch (err) {
    const timedOut = err instanceof Error && err.name === 'AbortError'
    return json({ error: `${route.service} ${timedOut ? 'timed out' : 'unavailable'}` }, 502)
  }
}

function json(payload: unknown, status: number): Response {
  return withSecurityHeaders(
    new Response(JSON.stringify(payload), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
}

/**
 * Baseline security headers. The UI renders device names, hostnames and
 * domains that come from the network, so a strict CSP is the backstop if any
 * of that ever reaches the DOM unescaped.
 */
function withSecurityHeaders(res: Response): Response {
  const h = new Headers(res.headers)
  h.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; connect-src 'self'; font-src 'self'; " +
      "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  )
  h.set('X-Content-Type-Options', 'nosniff')
  h.set('X-Frame-Options', 'DENY')
  h.set('Referrer-Policy', 'no-referrer')
  h.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
  h.set('Cross-Origin-Opener-Policy', 'same-origin')
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h })
}
