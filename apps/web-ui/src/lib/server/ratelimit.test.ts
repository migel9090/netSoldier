import { describe, expect, it } from 'vitest'
import {
  FailureWindow,
  LOGIN_MAX_FAILURES_GLOBAL,
  LOGIN_MAX_FAILURES_PER_CLIENT,
  LOGIN_MAX_FAILURES_PER_DEVICE,
  LOGIN_WINDOW_MS,
  LoginLimiter,
} from './ratelimit'

describe('FailureWindow', () => {
  it('blocks at the limit and frees up as failures age out', () => {
    const w = new FailureWindow(3, 1000)
    w.record('a', 0)
    w.record('a', 100)
    expect(w.retryAfterMs('a', 200)).toBe(0)
    w.record('a', 200)
    // Blocked until the oldest of the three leaves the window.
    expect(w.retryAfterMs('a', 300)).toBe(700)
    expect(w.retryAfterMs('a', 1001)).toBe(0)
    expect(w.retryAfterMs('b', 300)).toBe(0)
  })

  it('clear() forgets a key', () => {
    const w = new FailureWindow(1, 1000)
    w.record('a', 0)
    expect(w.retryAfterMs('a', 1)).toBeGreaterThan(0)
    w.clear('a')
    expect(w.retryAfterMs('a', 1)).toBe(0)
  })
})

describe('LoginLimiter', () => {
  it('locks a client out for the rest of the window, then lets it try again', () => {
    const l = new LoginLimiter()
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_CLIENT; i++) l.fail('10.0.0.1', null, false, i)
    const gate = l.check('10.0.0.1', null, 10)
    expect(gate).toMatchObject({ allowed: false, scope: 'client' })
    expect(l.check('10.0.0.1', null, LOGIN_WINDOW_MS + 10)).toEqual({
      allowed: true,
      trusted: false,
    })
  })

  it('a successful sign-in resets that client only', () => {
    const l = new LoginLimiter()
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_CLIENT - 1; i++) l.fail('10.0.0.1', null, false, i)
    l.succeed('10.0.0.1', null, false)
    expect(l.fail('10.0.0.1', null, false, 10)).toBe(1)
  })

  it('a known device bypasses full address and global windows until its own fills', () => {
    const l = new LoginLimiter()
    for (let i = 0; i < LOGIN_MAX_FAILURES_GLOBAL; i++) l.fail(`10.0.1.${i}`, null, false, i)
    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_CLIENT; i++) l.fail('10.0.1.0', null, false, i)
    expect(l.check('10.0.1.0', null, 100)).toMatchObject({ allowed: false })
    expect(l.check('10.0.1.0', 'device-a', 100)).toEqual({ allowed: true, trusted: true })

    for (let i = 0; i < LOGIN_MAX_FAILURES_PER_DEVICE; i++)
      l.fail('10.0.1.0', 'device-a', true, 200)
    expect(l.check('10.0.1.0', 'device-a', 300)).toMatchObject({ allowed: false })
    // Another known device is unaffected.
    expect(l.check('10.0.1.0', 'device-b', 300)).toEqual({ allowed: true, trusted: true })
  })
})
