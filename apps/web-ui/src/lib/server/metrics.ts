/**
 * Prometheus counters for the two things an operator needs to be alerted on:
 * password guessing against the sign-in form, and a backend refusing the
 * web UI's API key. Served as text exposition format on GET /metrics.
 *
 * Every series is pre-initialised to zero, so "no failures yet" is a 0 and
 * not a missing series that an alert rule cannot tell apart from no data.
 */

import type { Service } from './upstream'

export type LoginFailureReason =
  'bad_password' | 'rate_limited' | 'invalid_request' | 'invalid_actor'
export type UpstreamErrorKind = 'auth' | 'unreachable' | 'timeout'

const LOGIN_FAILURE_REASONS: LoginFailureReason[] = [
  'bad_password',
  'rate_limited',
  'invalid_request',
  'invalid_actor',
]
const SERVICES: Service[] = ['killswitch', 'device-inventory', 'detection-engine']
const UPSTREAM_ERROR_KINDS: UpstreamErrorKind[] = ['auth', 'unreachable', 'timeout']

let loginFailures = new Map<LoginFailureReason, number>()
let logins = 0
let upstreamErrors = new Map<string, number>()

export function resetMetrics(): void {
  loginFailures = new Map(LOGIN_FAILURE_REASONS.map((r) => [r, 0]))
  logins = 0
  upstreamErrors = new Map(
    SERVICES.flatMap((s) => UPSTREAM_ERROR_KINDS.map((k) => [`${s}|${k}`, 0] as const)),
  )
}
resetMetrics()

export function countLoginFailure(reason: LoginFailureReason): void {
  loginFailures.set(reason, (loginFailures.get(reason) ?? 0) + 1)
}

export function countLogin(): void {
  logins++
}

export function countUpstreamError(service: Service, kind: UpstreamErrorKind): void {
  const key = `${service}|${kind}`
  upstreamErrors.set(key, (upstreamErrors.get(key) ?? 0) + 1)
}

export const METRICS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8'

export function renderMetrics(): string {
  const lines = [
    '# HELP netsoldier_webui_login_failures_total Refused sign-in attempts, by reason.',
    '# TYPE netsoldier_webui_login_failures_total counter',
    ...[...loginFailures].map(
      ([reason, n]) => `netsoldier_webui_login_failures_total{reason="${reason}"} ${n}`,
    ),
    '# HELP netsoldier_webui_logins_total Successful sign-ins.',
    '# TYPE netsoldier_webui_logins_total counter',
    `netsoldier_webui_logins_total ${logins}`,
    '# HELP netsoldier_webui_upstream_errors_total Backend calls that failed before returning data, by service and kind.',
    '# TYPE netsoldier_webui_upstream_errors_total counter',
    ...[...upstreamErrors].map(([key, n]) => {
      const [service, kind] = key.split('|')
      return `netsoldier_webui_upstream_errors_total{service="${service}",kind="${kind}"} ${n}`
    }),
  ]
  return lines.join('\n') + '\n'
}
