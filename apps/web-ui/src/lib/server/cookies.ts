import type { Cookies } from '@sveltejs/kit'
import { CSRF_COOKIE, SESSION_COOKIE, SESSION_TTL_SECONDS } from './auth'
import type { Config } from './config'
import { DEVICE_COOKIE, DEVICE_COOKIE_PATH, DEVICE_TTL_SECONDS } from './device'

type CookieOptions = Parameters<Cookies['set']>[2]

/**
 * Cookie attributes for both cookies. `Secure` follows ORIGIN: over plain
 * HTTP on a LAN a `Secure` cookie is silently dropped by the browser, and
 * behind TLS it must be set.
 */
function options(config: Config, httpOnly: boolean): CookieOptions {
  return {
    path: '/',
    httpOnly,
    sameSite: 'strict',
    secure: config.secureCookies,
    maxAge: SESSION_TTL_SECONDS,
  }
}

export function setSessionCookies(
  cookies: Cookies,
  config: Config,
  token: string,
  csrf: string,
): void {
  cookies.set(SESSION_COOKIE, token, options(config, true))
  // Readable by the page on purpose: this is the token the client echoes
  // back in X-CSRF-Token.
  cookies.set(CSRF_COOKIE, csrf, options(config, false))
}

export function clearSessionCookies(cookies: Cookies, config: Config): void {
  cookies.delete(SESSION_COOKIE, options(config, true))
  cookies.delete(CSRF_COOKIE, options(config, false))
}

/**
 * The device cookie (see device.ts): HttpOnly, sent only to the sign-in
 * endpoint, and deliberately left in place by sign-out.
 */
export function setDeviceCookie(cookies: Cookies, config: Config, token: string): void {
  cookies.set(DEVICE_COOKIE, token, {
    path: DEVICE_COOKIE_PATH,
    httpOnly: true,
    sameSite: 'strict',
    secure: config.secureCookies,
    maxAge: DEVICE_TTL_SECONDS,
  })
}
