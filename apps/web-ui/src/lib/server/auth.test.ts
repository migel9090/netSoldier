import { describe, expect, it } from 'vitest'
import {
  csrfOk,
  csrfTokenFor,
  issueSession,
  originOk,
  revokeSession,
  safeEqual,
  verifySession,
} from './auth'

const SECRET = 'test-secret-test-secret-test-secret'

describe('session tokens', () => {
  it('round-trips an actor', () => {
    const { token, session } = issueSession(SECRET, 'michal')
    expect(verifySession(SECRET, token)).toEqual(session)
  })

  it('rejects a token signed with a different secret', () => {
    expect(verifySession(SECRET, issueSession('other-secret', 'michal').token)).toBeNull()
  })

  // The whole point of signing: a cookie the client edited must not grant
  // access to the killswitch approval API.
  it('rejects a forged payload', () => {
    const { token } = issueSession(SECRET, 'guest')
    const [, signature] = token.split('.')
    const forged =
      Buffer.from(
        JSON.stringify({
          v: 1,
          sid: 'x',
          exp: Math.floor(Date.now() / 1000) + 9999,
          actor: 'admin',
        }),
        'utf8',
      ).toString('base64url') + `.${signature}`
    expect(verifySession(SECRET, forged)).toBeNull()
  })

  it('rejects an expired token', () => {
    const issuedAt = Date.now() - 13 * 60 * 60 * 1000 // past the 12h TTL
    expect(verifySession(SECRET, issueSession(SECRET, 'michal', issuedAt).token)).toBeNull()
  })

  it('rejects malformed input', () => {
    for (const token of [undefined, '', 'nodot', '.', 'a.b', '!!!.!!!']) {
      expect(verifySession(SECRET, token)).toBeNull()
    }
  })

  it('refuses to sign an actor that fails validation', () => {
    expect(() => issueSession(SECRET, 'Łukasz')).toThrow()
    expect(() => issueSession(SECRET, '')).toThrow()
  })

  it('stops accepting a revoked session', () => {
    const { token, session } = issueSession(SECRET, 'michal')
    const other = issueSession(SECRET, 'anna')
    revokeSession(session)
    expect(verifySession(SECRET, token)).toBeNull()
    expect(verifySession(SECRET, other.token)).not.toBeNull()
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

describe('csrf token', () => {
  const a = issueSession(SECRET, 'michal').session
  const b = issueSession(SECRET, 'michal').session

  it('accepts the token derived from the same session', () => {
    expect(csrfOk(SECRET, a, csrfTokenFor(SECRET, a))).toBe(true)
  })

  // A double-submit cookie alone accepts any token the attacker managed to
  // plant as a cookie; binding it to the session id closes that.
  it("rejects another session's token, a missing token and a wrong secret", () => {
    expect(csrfOk(SECRET, a, csrfTokenFor(SECRET, b))).toBe(false)
    expect(csrfOk(SECRET, a, null)).toBe(false)
    expect(csrfOk(SECRET, a, '')).toBe(false)
    expect(csrfOk(SECRET, a, csrfTokenFor('other-secret', a))).toBe(false)
  })
})

describe('origin check', () => {
  it('accepts only the configured origin', () => {
    expect(originOk('http://ui', 'http://ui')).toBe(true)
    expect(originOk('http://evil.example', 'http://ui')).toBe(false)
    expect(originOk('null', 'http://ui')).toBe(false)
    expect(originOk(null, 'http://ui')).toBe(false)
  })
})
