import { describe, expect, it } from 'vitest'
import { csrfOk, issueSession, newCsrfToken, safeEqual, verifySession } from './auth'

const SECRET = 'test-secret'

describe('session tokens', () => {
  it('round-trips an actor', () => {
    const session = verifySession(SECRET, issueSession(SECRET, 'michal'))
    expect(session?.actor).toBe('michal')
  })

  it('rejects a token signed with a different secret', () => {
    expect(verifySession(SECRET, issueSession('other-secret', 'michal'))).toBeNull()
  })

  // The whole point of signing: a cookie the client edited must not grant
  // access to the killswitch approval API.
  it('rejects a forged payload', () => {
    const token = issueSession(SECRET, 'guest')
    const [, signature] = token.split('.')
    const forged =
      Buffer.from(`admin:${Math.floor(Date.now() / 1000) + 9999}`, 'utf8').toString('base64url') +
      `.${signature}`
    expect(verifySession(SECRET, forged)).toBeNull()
  })

  it('rejects an expired token', () => {
    const issuedAt = Date.now() - 13 * 60 * 60 * 1000 // past the 12h TTL
    expect(verifySession(SECRET, issueSession(SECRET, 'michal', issuedAt))).toBeNull()
  })

  it('rejects malformed input', () => {
    for (const token of [undefined, '', 'nodot', '.', 'a.b', '!!!.!!!']) {
      expect(verifySession(SECRET, token)).toBeNull()
    }
  })
})

describe('safeEqual', () => {
  it('compares equal strings', () => {
    expect(safeEqual('abc', 'abc')).toBe(true)
  })
  it('rejects different strings and lengths without throwing', () => {
    expect(safeEqual('abc', 'abd')).toBe(false)
    expect(safeEqual('abc', 'abcdef')).toBe(false)
    expect(safeEqual('', 'x')).toBe(false)
  })
})

describe('csrf double-submit', () => {
  const token = newCsrfToken()

  it('allows reads', () => {
    expect(csrfOk('GET', null, 'http://ui', null, undefined)).toBe(true)
  })

  // This is the gap SvelteKit's built-in protection did not cover: the
  // handle hook intercepts /api/* before resolve(), so a cross-site POST
  // reached the killswitch proxy.
  it('rejects a cross-site POST', () => {
    expect(csrfOk('POST', 'http://evil.example', 'http://ui', token, token)).toBe(false)
  })

  it('rejects a POST with no token', () => {
    expect(csrfOk('POST', 'http://ui', 'http://ui', null, token)).toBe(false)
    expect(csrfOk('POST', 'http://ui', 'http://ui', token, undefined)).toBe(false)
  })

  it('rejects a mismatched token', () => {
    expect(csrfOk('POST', 'http://ui', 'http://ui', token, newCsrfToken())).toBe(false)
  })

  it('accepts a same-origin POST with matching tokens', () => {
    expect(csrfOk('POST', 'http://ui', 'http://ui', token, token)).toBe(true)
  })

  it('generates distinct tokens', () => {
    expect(newCsrfToken()).not.toBe(newCsrfToken())
  })
})
