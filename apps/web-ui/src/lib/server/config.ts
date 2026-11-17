import { env } from '#lib/server/env.ts'
import type { Service } from './upstream'

/**
 * Runtime configuration (contract v2 §7), validated as a whole.
 *
 * The UI fails closed: if anything required is missing or weak it serves a
 * 503 that names the problem instead of running half-configured. Two of these
 * were silent before. Without ORIGIN, adapter-node assumes every request
 * arrived over https, so on a plain-HTTP LAN the cookies came back `Secure`
 * (the browser drops them) and the browser's Origin never matched. And a
 * one-character SESSION_SECRET was accepted for signing sessions.
 */

export const MIN_SESSION_SECRET_LENGTH = 32
export const MIN_PASSWORD_LENGTH = 12

export interface Upstream {
  url: string
  key: string
  /** Env var names, for messages that tell the operator what to fix. */
  urlVar: string
  keyVar: string
}

/**
 * A service the UI reads for the system-status page only, never through
 * the proxy, and can run without: threat-intel-sync (no API key; it serves
 * only probes, metrics and its public feed exports).
 */
export interface OptionalUpstream {
  url: string
  urlVar: string
}

export interface Config {
  sessionSecret: string
  password: string
  /** Normalised external origin, e.g. "https://netsoldier.lan". */
  origin: string
  /** Cookies carry `Secure` exactly when the UI is served over https. */
  secureCookies: boolean
  upstreams: Record<Service, Upstream>
  /** THREAT_INTEL_URL; null when it is not set (or not usable, see `notes`). */
  threatIntel: OptionalUpstream | null
  /**
   * Problems with optional settings. They never make the UI unconfigured —
   * the approval pages do not depend on them — but the status page and the
   * start-up log name them.
   */
  notes: string[]
}

export const THREAT_INTEL_URL_VAR = 'THREAT_INTEL_URL'

export type ConfigResult = { ok: true; config: Config } | { ok: false; problems: string[] }

const UPSTREAM_VARS: Record<Service, { urlVar: string; keyVar: string; what: string }> = {
  killswitch: {
    urlVar: 'KILLSWITCH_URL',
    keyVar: 'KILLSWITCH_API_KEY',
    what: 'the killswitch operator token',
  },
  'device-inventory': {
    urlVar: 'DEVICE_INVENTORY_URL',
    keyVar: 'DEVICE_API_KEY',
    what: 'the device-inventory API key',
  },
  'detection-engine': {
    urlVar: 'DETECTION_ENGINE_URL',
    keyVar: 'DETECTION_API_KEY',
    what: 'the detection-engine API key',
  },
}

export function readConfig(source: Record<string, string | undefined> = env): ConfigResult {
  const problems: string[] = []

  // The problems are shown to anyone who opens the unconfigured UI, so they
  // name the rule that failed but never a secret, or its length.
  const sessionSecret = source.SESSION_SECRET ?? ''
  if (!sessionSecret) {
    problems.push(
      `SESSION_SECRET is not set (at least ${MIN_SESSION_SECRET_LENGTH} random characters, e.g. \`openssl rand -base64 48\`)`,
    )
  } else if (sessionSecret.length < MIN_SESSION_SECRET_LENGTH) {
    problems.push(
      `SESSION_SECRET is too short (at least ${MIN_SESSION_SECRET_LENGTH} characters required)`,
    )
  }

  // Throttling bounds the guessing rate, not the number of guesses over
  // weeks: a short household password is still found eventually.
  const password = source.WEB_UI_PASSWORD ?? ''
  if (!password) {
    problems.push(
      `WEB_UI_PASSWORD is not set (the shared household password, at least ${MIN_PASSWORD_LENGTH} characters)`,
    )
  } else if ([...password].length < MIN_PASSWORD_LENGTH) {
    problems.push(
      `WEB_UI_PASSWORD is too short (at least ${MIN_PASSWORD_LENGTH} characters required)`,
    )
  } else if (password === sessionSecret) {
    problems.push('WEB_UI_PASSWORD must not be the same as SESSION_SECRET')
  }

  const origin = parseOrigin(source.ORIGIN, problems)

  const upstreams = {} as Record<Service, Upstream>
  for (const [service, vars] of Object.entries(UPSTREAM_VARS) as [
    Service,
    (typeof UPSTREAM_VARS)[Service],
  ][]) {
    const url = (source[vars.urlVar] ?? '').trim()
    const key = source[vars.keyVar] ?? ''
    if (!url) problems.push(`${vars.urlVar} is not set`)
    else if (!isHttpUrl(url)) problems.push(`${vars.urlVar} must be an http:// or https:// URL`)
    if (!key) problems.push(`${vars.keyVar} is not set (${vars.what})`)
    upstreams[service] = { url: url.replace(/\/+$/, ''), key, ...vars }
  }

  const notes: string[] = []
  let threatIntel: OptionalUpstream | null = null
  const tiUrl = (source[THREAT_INTEL_URL_VAR] ?? '').trim()
  if (tiUrl && !isHttpUrl(tiUrl)) {
    notes.push(
      `${THREAT_INTEL_URL_VAR} must be an http:// or https:// URL; threat-intel-sync is not read`,
    )
  } else if (tiUrl) {
    threatIntel = { url: tiUrl.replace(/\/+$/, ''), urlVar: THREAT_INTEL_URL_VAR }
  }

  if (problems.length > 0) return { ok: false, problems }
  return {
    ok: true,
    config: {
      sessionSecret,
      password,
      origin: origin!,
      secureCookies: origin!.startsWith('https:'),
      upstreams,
      threatIntel,
      notes,
    },
  }
}

function parseOrigin(raw: string | undefined, problems: string[]): string | null {
  const value = (raw ?? '').trim()
  if (!value) {
    problems.push(
      'ORIGIN is not set (the address people open in the browser, e.g. http://192.168.1.5:3000 ' +
        'on a plain LAN or https://netsoldier.lan behind TLS)',
    )
    return null
  }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    problems.push(`ORIGIN is not a URL: "${value}"`)
    return null
  }
  if (
    (url.protocol !== 'http:' && url.protocol !== 'https:') ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    problems.push(`ORIGIN must be a bare http:// or https:// origin with no path: "${value}"`)
    return null
  }
  return url.origin
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value)
    return (u.protocol === 'http:' || u.protocol === 'https:') && !u.username && !u.password
  } catch {
    return false
  }
}
