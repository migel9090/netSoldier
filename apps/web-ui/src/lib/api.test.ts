import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { formatTimeLeft, liftSuppression, submitFeedback } from './api'

describe('time left', () => {
  const now = Date.parse('2026-11-16T12:00:00Z')
  const at = (minutes: number) => new Date(now + minutes * 60_000).toISOString()

  it('rounds to the unit that reads naturally', () => {
    expect(formatTimeLeft(at(30 * 24 * 60), now)).toBe('30 days left')
    expect(formatTimeLeft(at(30 * 24 * 60 - 1), now)).toBe('30 days left')
    expect(formatTimeLeft(at(40 * 60), now)).toBe('2 days left')
    expect(formatTimeLeft(at(5 * 60), now)).toBe('5 hours left')
    expect(formatTimeLeft(at(61), now)).toBe('61 minutes left')
    expect(formatTimeLeft(at(1), now)).toBe('1 minute left')
    expect(formatTimeLeft(at(0.5), now)).toBe('less than a minute left')
    expect(formatTimeLeft(at(-5), now)).toBe('ending now')
    expect(formatTimeLeft(undefined, now)).toBe('')
    expect(formatTimeLeft('not a time', now)).toBe('')
  })
})

describe('POST /feedback/lift', () => {
  let calls: { url: string; init: RequestInit }[]
  let reply: () => Response

  beforeEach(() => {
    calls = []
    vi.stubGlobal('document', { cookie: 'netsoldier_csrf=csrf-token-1' })
    vi.stubGlobal('window', { location: { href: '/alerts' } })
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push({ url, init })
      return reply()
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const json = (status: number, body: unknown) =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })

  const req = { matched_ioc: 'evil.example', client_ip: '192.168.1.77', signal_class: 'ioc' }

  it('posts the suppression’s key with the CSRF token, and reads persisted', async () => {
    reply = () => json(200, { status: 'lifted', persisted: true })
    expect(await liftSuppression(req)).toEqual({ inForce: true, persisted: true })
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe('/api/feedback/lift')
    expect(calls[0].init.method).toBe('POST')
    expect((calls[0].init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-token-1')
    expect(JSON.parse(String(calls[0].init.body))).toEqual(req)

    reply = () => json(200, { status: 'lifted', persisted: false })
    expect(await liftSuppression(req)).toEqual({ inForce: true, persisted: false })
    reply = () => json(200, { status: 'lifted' })
    expect(await liftSuppression(req)).toEqual({ inForce: true, persisted: null })
  })

  it('takes the engine’s 404 as "not in force"', async () => {
    reply = () => json(404, { error: 'no such suppression is in force' })
    expect(await liftSuppression(req)).toEqual({ inForce: false })
  })

  // An engine from before the route answers Go's plain-text 404 (served as
  // JSON by the proxy): nothing was lifted, and it must not say "already".
  it('does not take an engine without the route for "already lifted"', async () => {
    reply = () => json(404, '404 page not found\n')
    await expect(liftSuppression(req)).rejects.toThrow(/has no POST \/feedback\/lift/)
  })

  it('reports a refusal with the engine’s reason', async () => {
    reply = () => json(400, { error: 'signal_class "x" is not a signal class' })
    await expect(liftSuppression(req)).rejects.toThrow(
      'Lifting the suppression failed: signal_class "x" is not a signal class',
    )
  })

  it('reads persisted on a verdict the same way', async () => {
    reply = () => json(202, { status: 'recorded', persisted: false })
    expect(
      await submitFeedback({ matched_ioc: 'evil.example', verdict: 'false_positive' }),
    ).toEqual({ persisted: false })
  })
})
