import { createHmac, randomBytes } from 'node:crypto'
import { safeEqual } from './auth'

/**
 * Device cookies: "this browser has signed in here before".
 *
 * Set on every successful sign-in, kept across sign-out, and presented only
 * to POST /api/login (Path=/api/login). Its value is a random device id and
 * an expiry, signed with a key derived from SESSION_SECRET. Only someone
 * who knew the password can hold a valid one, so an attempt carrying it is
 * judged by that device's own failure window rather than by the per-address
 * and global windows an attacker on the LAN can exhaust (see ratelimit.ts).
 *
 * Format: `<version>.<device id>.<expiry, unix s>.<signature>`. The version
 * is part of both the signed text and the key derivation; bumping it — or
 * rotating SESSION_SECRET — revokes every device cookie at once.
 */

export const DEVICE_COOKIE = 'netsoldier_device'
export const DEVICE_COOKIE_PATH = '/api/login'
export const DEVICE_TTL_SECONDS = 180 * 24 * 60 * 60

const VERSION = 'v1'
const DEVICE_ID = /^[A-Za-z0-9_-]{16,64}$/

function deviceKey(secret: string, version: string): Buffer {
  return createHmac('sha256', secret).update(`netsoldier/device-cookie/${version}`).digest()
}

function sign(secret: string, payload: string): string {
  return createHmac('sha256', deviceKey(secret, VERSION)).update(payload).digest('base64url')
}

/** A device cookie value for `deviceId` (a new random id when omitted). */
export function issueDeviceToken(
  secret: string,
  deviceId: string = randomBytes(18).toString('base64url'),
  now = Date.now(),
): { token: string; deviceId: string } {
  const payload = `${VERSION}.${deviceId}.${Math.floor(now / 1000) + DEVICE_TTL_SECONDS}`
  return { token: `${payload}.${sign(secret, payload)}`, deviceId }
}

/**
 * The device id from a cookie value, or null. Forged, expired, malformed and
 * old-version values all count as no cookie at all; this never throws.
 */
export function verifyDeviceToken(
  secret: string,
  token: string | undefined,
  now = Date.now(),
): string | null {
  try {
    if (typeof token !== 'string' || token.length > 256) return null
    const parts = token.split('.')
    if (parts.length !== 4) return null
    const [version, deviceId, exp, signature] = parts
    if (version !== VERSION || !DEVICE_ID.test(deviceId) || !/^\d{1,12}$/.test(exp)) return null
    if (!safeEqual(signature, sign(secret, `${version}.${deviceId}.${exp}`))) return null
    if (Number(exp) * 1000 <= now) return null
    return deviceId
  } catch {
    return null
  }
}
