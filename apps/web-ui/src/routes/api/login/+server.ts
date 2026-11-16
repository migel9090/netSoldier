import { json } from '@sveltejs/kit'
import type { RequestHandler } from './$types'
import { validateActor } from '$lib/actor'
import { csrfTokenFor, issueSession, safeEqual } from '$lib/server/auth'
import { readConfig } from '$lib/server/config'
import { setDeviceCookie, setSessionCookies } from '$lib/server/cookies'
import { DEVICE_COOKIE, issueDeviceToken, verifyDeviceToken } from '$lib/server/device'
import { log } from '$lib/server/log'
import { countLogin, countLoginFailure } from '$lib/server/metrics'
import { loginLimiter } from '$lib/server/ratelimit'

/**
 * POST /api/login — exchanges the household password for a session.
 *
 * Reached through `resolve()` (see hooks.server.ts) so the cookies set here
 * are actually written to the response. The hook has already checked Origin.
 */

const MAX_BODY_BYTES = 4096
const MAX_PASSWORD_LENGTH = 1024

export const POST: RequestHandler = async (event) => {
  const result = readConfig()
  if (!result.ok) return json({ error: 'web-ui is not configured' }, { status: 503 })
  const config = result.config
  const client = event.getClientAddress()

  const body = await readBody(event.request)
  if (!body.ok) {
    countLoginFailure('invalid_request')
    return json({ error: body.error }, { status: body.status })
  }

  // Checked before the password so the household gets a useful message
  // whether or not they typed the password right. The rule is public.
  const actor = validateActor(body.actor)
  if (!actor.ok) {
    countLoginFailure('invalid_actor')
    return json({ error: actor.message, field: 'actor' }, { status: 400 })
  }

  const now = Date.now()
  // A browser that signed in here before is judged by its own failure
  // window, not by the windows an attacker can exhaust (see ratelimit.ts).
  const deviceId = verifyDeviceToken(config.sessionSecret, event.cookies.get(DEVICE_COOKIE), now)
  const gate = loginLimiter.check(client, deviceId, now)
  if (!gate.allowed) {
    countLoginFailure('rate_limited')
    log('WARN', 'sign-in refused: too many failed attempts', {
      client,
      scope: gate.scope,
      known_device: deviceId !== null,
      retry_after_s: gate.retryAfterSeconds,
    })
    const minutes = Math.max(1, Math.ceil(gate.retryAfterSeconds / 60))
    return json(
      {
        error:
          gate.scope === 'client'
            ? `Too many failed sign-in attempts from this network address. Try again in ${minutes} min.`
            : `Too many failed sign-in attempts from browsers this UI does not recognise. ` +
              `Sign-in from new browsers is paused for ${minutes} min; ` +
              `browsers that have signed in here before are not affected.`,
      },
      { status: 429, headers: { 'Retry-After': String(gate.retryAfterSeconds) } },
    )
  }

  if (!safeEqual(body.password, config.password)) {
    const failures = loginLimiter.fail(client, deviceId, gate.trusted, now)
    countLoginFailure('bad_password')
    log('WARN', 'sign-in failed: wrong password', {
      client,
      known_device: gate.trusted,
      failures_in_window: failures,
    })
    return json({ error: 'invalid credentials' }, { status: 401 })
  }

  loginLimiter.succeed(client, deviceId, gate.trusted)
  const { token, session } = issueSession(config.sessionSecret, actor.actor, now)
  setSessionCookies(event.cookies, config, token, csrfTokenFor(config.sessionSecret, session))
  // Same id for a browser we already know; its expiry moves forward.
  setDeviceCookie(
    event.cookies,
    config,
    issueDeviceToken(config.sessionSecret, deviceId ?? undefined, now).token,
  )
  countLogin()
  log('INFO', 'signed in', { client, actor: session.actor, known_device: deviceId !== null })

  return json({ status: 'ok', actor: session.actor })
}

type Body =
  { ok: true; password: string; actor: unknown } | { ok: false; status: number; error: string }

async function readBody(request: Request): Promise<Body> {
  if (!/^application\/json\b/i.test(request.headers.get('content-type') ?? '')) {
    return { ok: false, status: 415, error: 'send the sign-in form as application/json' }
  }
  if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
    return { ok: false, status: 413, error: 'request body too large' }
  }

  let text: string
  try {
    text = await request.text()
  } catch {
    return { ok: false, status: 400, error: 'could not read the request body' }
  }
  if (Buffer.byteLength(text) > MAX_BODY_BYTES) {
    return { ok: false, status: 413, error: 'request body too large' }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return { ok: false, status: 400, error: 'request body is not valid JSON' }
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, status: 400, error: 'request body must be a JSON object' }
  }

  const { password, actor } = parsed as Record<string, unknown>
  if (typeof password !== 'string' || password === '') {
    return { ok: false, status: 400, error: 'password is required' }
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return { ok: false, status: 400, error: 'password is too long' }
  }
  return { ok: true, password, actor }
}
