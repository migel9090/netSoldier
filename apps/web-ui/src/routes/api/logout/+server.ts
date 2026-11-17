import type { RequestHandler } from './$types'
import { revokeSession } from '#lib/server/auth.ts'
import { readConfig } from '#lib/server/config.ts'
import { clearSessionCookies } from '#lib/server/cookies.ts'
import { log } from '#lib/server/log.ts'

/**
 * POST /api/logout — ends the session.
 *
 * POST only (SvelteKit answers 405 to anything else); the hook has already
 * checked Origin and the session's CSRF token. The session id is revoked
 * server-side, so a copy of the cookie stops working too.
 */
export const POST: RequestHandler = async ({ cookies, locals, getClientAddress }) => {
  const result = readConfig()
  if (!result.ok) return Response.json({ error: 'web-ui is not configured' }, { status: 503 })

  if (locals.session) {
    revokeSession(locals.session)
    log('INFO', 'signed out', { client: getClientAddress(), actor: locals.session.actor })
  }
  clearSessionCookies(cookies, result.config)
  return Response.json({ status: 'signed out' })
}
