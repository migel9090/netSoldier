import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto'

/**
 * Interim session authentication for the household UI.
 *
 * This UI is the human-in-the-loop approval surface for the killswitch: the
 * proxy in hooks.server.ts attaches KILLSWITCH_API_KEY to whatever reaches
 * it, and the web-ui NetworkPolicy accepts ingress from anywhere. Before this
 * existed, any device on the LAN could POST
 * /api/killswitch/{id}/approve and quarantine any other device, or POST
 * /api/feedback and permanently silence a detection — the service held the
 * credential and asked nothing of the caller.
 *
 * Full OIDC/SSO is roadmap step 159. Until then a single shared household
 * password gated by a signed, HttpOnly cookie is the proportionate control:
 * it stops the "anyone on the LAN" case and gives every mutating request an
 * identity to record in the audit log. It is deliberately not a user
 * directory — there are no roles and no per-person accounts.
 */

const SESSION_COOKIE = 'netsoldier_session'
const CSRF_COOKIE = 'netsoldier_csrf'
const SESSION_TTL_SECONDS = 12 * 60 * 60

export { SESSION_COOKIE, CSRF_COOKIE, SESSION_TTL_SECONDS }

export interface Session {
  actor: string
  expiresAt: number
}

function sign(secret: string, payload: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url')
}

/** Constant-time string comparison that tolerates length differences. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ab.length !== bb.length) {
    // Still compare something of equal length so the branch does not
    // leak the expected length through timing.
    timingSafeEqual(ab, ab)
    return false
  }
  return timingSafeEqual(ab, bb)
}

/** Builds a signed session token. */
export function issueSession(secret: string, actor: string, now = Date.now()): string {
  const expiresAt = Math.floor(now / 1000) + SESSION_TTL_SECONDS
  const payload = `${actor}:${expiresAt}`
  return `${Buffer.from(payload, 'utf8').toString('base64url')}.${sign(secret, payload)}`
}

/** Verifies a session token, returning null when invalid or expired. */
export function verifySession(
  secret: string,
  token: string | undefined,
  now = Date.now(),
): Session | null {
  if (!token) return null
  const dot = token.lastIndexOf('.')
  if (dot <= 0) return null

  const encoded = token.slice(0, dot)
  const signature = token.slice(dot + 1)

  let payload: string
  try {
    payload = Buffer.from(encoded, 'base64url').toString('utf8')
  } catch {
    return null
  }
  if (!safeEqual(signature, sign(secret, payload))) return null

  const sep = payload.lastIndexOf(':')
  if (sep <= 0) return null
  const actor = payload.slice(0, sep)
  const expiresAt = Number.parseInt(payload.slice(sep + 1), 10)
  if (!Number.isFinite(expiresAt) || expiresAt * 1000 <= now) return null

  return { actor, expiresAt }
}

export function newCsrfToken(): string {
  return randomBytes(32).toString('base64url')
}

/**
 * Checks the double-submit CSRF token.
 *
 * SvelteKit's own CSRF protection never applied here: this handle hook
 * intercepts /api/* BEFORE resolve(event), so the framework's origin check
 * for form actions and endpoints was bypassed entirely. A page in the
 * household's browser could therefore POST an approval cross-site. Origin is
 * checked as well because a token alone does not help if the browser is
 * willing to send it from anywhere.
 */
export function csrfOk(
  method: string,
  origin: string | null,
  selfOrigin: string,
  headerToken: string | null,
  cookieToken: string | undefined,
): boolean {
  if (method === 'GET' || method === 'HEAD') return true
  if (origin !== null && origin !== selfOrigin) return false
  if (!cookieToken || !headerToken) return false
  return safeEqual(headerToken, cookieToken)
}
