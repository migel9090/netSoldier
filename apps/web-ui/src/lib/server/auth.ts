import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto'
import { isValidActor } from '$lib/actor'

/**
 * Interim session authentication for the household UI.
 *
 * This UI is the human-in-the-loop approval surface for the killswitch: the
 * proxy in hooks.server.ts attaches the backend API keys to whatever reaches
 * it. Before sessions existed, any device on the LAN could POST
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
  /** Random per-sign-in id; what sign-out revokes and the CSRF token binds to. */
  sid: string
  actor: string
  /** Unix seconds. */
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

/** Builds a signed session token for an actor that already passed validation. */
export function issueSession(
  secret: string,
  actor: string,
  now = Date.now(),
): { token: string; session: Session } {
  if (!isValidActor(actor)) throw new Error('issueSession: actor failed validation')
  const session: Session = {
    sid: randomBytes(18).toString('base64url'),
    actor,
    expiresAt: Math.floor(now / 1000) + SESSION_TTL_SECONDS,
  }
  const payload = JSON.stringify({ v: 1, sid: session.sid, exp: session.expiresAt, actor })
  const token = `${Buffer.from(payload, 'utf8').toString('base64url')}.${sign(secret, payload)}`
  return { token, session }
}

/** Verifies a session token, returning null when invalid, expired or signed out. */
export function verifySession(
  secret: string,
  token: string | undefined,
  now = Date.now(),
): Session | null {
  if (!token) return null
  const dot = token.lastIndexOf('.')
  if (dot <= 0) return null

  const payload = Buffer.from(token.slice(0, dot), 'base64url').toString('utf8')
  if (!safeEqual(token.slice(dot + 1), sign(secret, payload))) return null

  let parsed: unknown
  try {
    parsed = JSON.parse(payload)
  } catch {
    return null
  }
  if (typeof parsed !== 'object' || parsed === null) return null
  const { v, sid, exp, actor } = parsed as Record<string, unknown>
  if (v !== 1 || typeof sid !== 'string' || !sid) return null
  if (typeof exp !== 'number' || !Number.isFinite(exp) || exp * 1000 <= now) return null
  // Signed by us, so this only fails for a token minted before the actor rule
  // existed — but the actor goes into an HTTP header, so check anyway.
  if (typeof actor !== 'string' || !isValidActor(actor)) return null
  if (isRevoked(sid, now)) return null

  return { sid, actor, expiresAt: exp }
}

/**
 * Sign-out revocation. Sessions are stateless signed tokens, so without this
 * a copied cookie stayed valid for its full 12 h after the user signed out.
 * The list lives in memory (the UI runs as one replica) and is lost on
 * restart; rotating SESSION_SECRET is the way to end every session at once.
 */
const REVOCATION_CAP = 10_000
const revoked = new Map<string, number>()

export function revokeSession(session: Session, now = Date.now()): void {
  for (const [sid, exp] of revoked) {
    if (exp * 1000 <= now || revoked.size >= REVOCATION_CAP) revoked.delete(sid)
    else break
  }
  revoked.set(session.sid, session.expiresAt)
}

function isRevoked(sid: string, now: number): boolean {
  const exp = revoked.get(sid)
  if (exp === undefined) return false
  if (exp * 1000 <= now) {
    revoked.delete(sid)
    return false
  }
  return true
}

/**
 * The CSRF token for a session: derived from the session id, so a token
 * planted in the browser by anyone else (a cookie set from a sibling host,
 * for example) does not match. The page reads it from the CSRF cookie and
 * echoes it in X-CSRF-Token on every mutating request.
 */
export function csrfTokenFor(secret: string, session: Session): string {
  return sign(secret, `csrf:${session.sid}`)
}

export function csrfOk(secret: string, session: Session, headerToken: string | null): boolean {
  if (!headerToken) return false
  return safeEqual(headerToken, csrfTokenFor(secret, session))
}

/**
 * True when a state-changing request came from the UI's own pages.
 *
 * Browsers send Origin on every non-GET fetch, same-origin included, so a
 * missing or different Origin means the request did not come from a page
 * served at ORIGIN and is refused — sign-in and sign-out included.
 */
export function originOk(origin: string | null, expected: string): boolean {
  return origin !== null && origin === expected
}
