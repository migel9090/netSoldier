import type { RequestHandler } from './$types'
import { readConfig } from '#lib/server/config.ts'
import { gatherStatus } from '#lib/server/status.ts'

/**
 * GET /api/status — what the services report about their own health,
 * composed here (see #lib/server/status.ts). Reached through `resolve()`
 * after the hook has checked the session; it is not a proxy route, and it
 * never passes a backend's answer through as it is.
 */
export const GET: RequestHandler = async ({ locals }) => {
  const result = readConfig()
  if (!result.ok) return Response.json({ error: 'web-ui is not configured' }, { status: 503 })
  if (!locals.session) return Response.json({ error: 'not signed in' }, { status: 401 })
  return Response.json(await gatherStatus(result.config, locals.session.actor))
}
