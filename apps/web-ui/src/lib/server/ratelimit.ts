/**
 * Sign-in throttling.
 *
 * Before this, 400 password guesses went through in 1.8 s: the 500 ms sleep
 * on failure slowed one request, not the hundreds running concurrently.
 * Sliding windows of *failed* attempts now gate the password check.
 *
 * Attempts from a browser without a valid device cookie (device.ts) — every
 * attacker, and any browser that never signed in here — are limited:
 *
 * - per client address, so one device on the LAN cannot grind the password;
 * - globally, so rotating addresses (or every client sharing a reverse
 *   proxy's address when ADDRESS_HEADER is not configured) does not reset
 *   the budget. This bounds total guessing at LOGIN_MAX_FAILURES_GLOBAL per
 *   window, whatever the attacker's address space.
 *
 * Attempts presenting a valid device cookie skip both and are limited only
 * by that device's own window. Without that exemption the global window was
 * a denial of service against the approval surface: twenty wrong guesses per
 * window, repeated forever by any device on the LAN, would keep the
 * household from signing in to approve a quarantine. A device cookie cannot
 * be obtained without the password, so the exemption gives an attacker no
 * extra guesses. When a device's own window is exhausted its cookie is not
 * honoured until the window passes, and the attempt takes the untrusted path.
 *
 * Residual limitation: a browser that has never signed in here (or whose
 * cookies were cleared) has no device cookie, so during an active attack it
 * is still paused by the global window like any other untrusted client.
 *
 * Check, password comparison and record happen in one synchronous turn, so
 * concurrent requests cannot all pass the check before a failure is counted.
 */

export const LOGIN_WINDOW_MS = 15 * 60 * 1000
export const LOGIN_MAX_FAILURES_PER_CLIENT = 5
export const LOGIN_MAX_FAILURES_GLOBAL = 20
export const LOGIN_MAX_FAILURES_PER_DEVICE = 5

export class FailureWindow {
  #failures = new Map<string, number[]>()

  constructor(
    readonly limit: number,
    readonly windowMs: number,
  ) {}

  /** Milliseconds until `key` may try again; 0 when it may try now. */
  retryAfterMs(key: string, now: number): number {
    const recent = this.#recent(key, now)
    if (recent.length < this.limit) return 0
    return recent[recent.length - this.limit] + this.windowMs - now
  }

  /** Records a failure and returns how many `key` now has in the window. */
  record(key: string, now: number): number {
    const recent = this.#recent(key, now)
    recent.push(now)
    // Only the newest `limit` entries can ever matter.
    if (recent.length > this.limit) recent.splice(0, recent.length - this.limit)
    this.#failures.set(key, recent)
    this.#prune(now)
    return recent.length
  }

  clear(key: string): void {
    this.#failures.delete(key)
  }

  reset(): void {
    this.#failures.clear()
  }

  #recent(key: string, now: number): number[] {
    return (this.#failures.get(key) ?? []).filter((t) => t > now - this.windowMs)
  }

  #prune(now: number): void {
    if (this.#failures.size < 1024) return
    for (const [key, times] of this.#failures) {
      if (times.every((t) => t <= now - this.windowMs)) this.#failures.delete(key)
    }
  }
}

/**
 * `trusted` attempts carry a device cookie whose own window still has room;
 * they are charged to that device only. The rest are charged to their
 * address and to the global window.
 */
export type LoginGate =
  | { allowed: true; trusted: boolean }
  | { allowed: false; scope: 'client' | 'global'; retryAfterSeconds: number }

const GLOBAL_KEY = '*'

export class LoginLimiter {
  readonly client = new FailureWindow(LOGIN_MAX_FAILURES_PER_CLIENT, LOGIN_WINDOW_MS)
  readonly global = new FailureWindow(LOGIN_MAX_FAILURES_GLOBAL, LOGIN_WINDOW_MS)
  readonly device = new FailureWindow(LOGIN_MAX_FAILURES_PER_DEVICE, LOGIN_WINDOW_MS)

  /** `deviceId` is the id from a *verified* device cookie, or null. */
  check(clientKey: string, deviceId: string | null, now = Date.now()): LoginGate {
    if (deviceId !== null && this.device.retryAfterMs(deviceId, now) === 0) {
      return { allowed: true, trusted: true }
    }
    const perClient = this.client.retryAfterMs(clientKey, now)
    if (perClient > 0) {
      return { allowed: false, scope: 'client', retryAfterSeconds: Math.ceil(perClient / 1000) }
    }
    const global = this.global.retryAfterMs(GLOBAL_KEY, now)
    if (global > 0) {
      return { allowed: false, scope: 'global', retryAfterSeconds: Math.ceil(global / 1000) }
    }
    return { allowed: true, trusted: false }
  }

  /** Records a wrong password; returns the failure count of the window charged. */
  fail(clientKey: string, deviceId: string | null, trusted: boolean, now = Date.now()): number {
    if (trusted && deviceId !== null) return this.device.record(deviceId, now)
    this.global.record(GLOBAL_KEY, now)
    return this.client.record(clientKey, now)
  }

  /**
   * Clears the window that admitted the attempt. A trusted sign-in leaves the
   * address window alone: someone else behind the same address may be the
   * one guessing.
   */
  succeed(clientKey: string, deviceId: string | null, trusted: boolean): void {
    if (trusted && deviceId !== null) this.device.clear(deviceId)
    else this.client.clear(clientKey)
  }

  reset(): void {
    this.client.reset()
    this.global.reset()
    this.device.reset()
  }
}

export const loginLimiter = new LoginLimiter()
