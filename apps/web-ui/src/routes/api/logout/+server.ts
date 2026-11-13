import { json } from '@sveltejs/kit'
import type { RequestHandler } from './$types'
import { revokeSession } from '$lib/server/auth'
import { readConfig } from '$lib/server/config'
import { clearSessionCookies } from '$lib/server/cookies'
import { log } from '$lib/server/log'

/**
 * POST /api/logout — ends the session.
 *
 * POST only (SvelteKit answers 405 to anything else); the hook has already
 * checked Origin and the session's CSRF token. The session id is revoked
 * server-side, so a copy of the cookie stops working too.
 */
export const POST: RequestHandler = async ({ cookies, locals, getClientAddress }) => {
  const result = readConfig()
  if (!result.ok) return json({ error: 'web-ui is not configured' }, { status: 503 })

  if (locals.session) {
    revokeSession(locals.session)
    log('INFO', 'signed out', { client: getClientAddress(), actor: locals.session.actor })
  }
  clearSessionCookies(cookies, result.config)
  return json({ status: 'signed out' })
}
