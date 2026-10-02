import { describe, expect, it } from 'vitest'
import { matchRoute } from './upstream'

describe('route allowlist', () => {
  it('maps the routes the UI actually uses', () => {
    const cases: [string, string, string][] = [
      ['GET', '/api/devices', '/devices'],
      ['GET', '/api/devices/aa:bb:cc:dd:ee:ff', '/devices/aa:bb:cc:dd:ee:ff'],
      ['GET', '/api/devices/aa:bb:cc:dd:ee:ff/dns', '/devices/aa:bb:cc:dd:ee:ff/dns'],
      ['PUT', '/api/devices/aa:bb:cc:dd:ee:ff/labels', '/devices/aa:bb:cc:dd:ee:ff/labels'],
      ['GET', '/api/topology', '/topology'],
      ['GET', '/api/alerts', '/alerts'],
      ['POST', '/api/feedback', '/feedback'],
      ['GET', '/api/killswitch/pending', '/actions/pending'],
      ['POST', '/api/killswitch/ACT-1/approve', '/actions/ACT-1/approve'],
      ['POST', '/api/killswitch/ACT-1/revert', '/actions/ACT-1/revert'],
    ]
    for (const [method, path, want] of cases) {
      const matched = matchRoute(method, path)
      expect(matched, `${method} ${path} should be allowed`).not.toBeNull()
      expect(matched?.upstreamPath).toBe(want)
    }
  })

  // The proxy used to build the upstream URL by replacing a path prefix, so
  // the caller controlled the tail of an internal URL.
  it('rejects traversal and encoded separators', () => {
    const hostile = [
      '/api/devices/../../control/filtering/set_rules',
      '/api/killswitch/../policy',
      '/api/devices/..%2f..%2fcontrol',
      '/api/devices/%2e%2e/admin',
      '/api/killswitch/ACT-1%2fapprove/approve',
    ]
    for (const path of hostile) {
      expect(matchRoute('GET', path), `${path} must not match`).toBeNull()
      expect(matchRoute('POST', path), `${path} must not match`).toBeNull()
    }
  })

  it('rejects unknown endpoints and wrong methods', () => {
    expect(matchRoute('GET', '/api/unknown')).toBeNull()
    expect(matchRoute('DELETE', '/api/devices')).toBeNull()
    // Reading the allowlist is fine; approving via GET is not.
    expect(matchRoute('GET', '/api/killswitch/ACT-1/approve')).toBeNull()
    // Only well-formed MACs address a device.
    expect(matchRoute('GET', '/api/devices/not-a-mac')).toBeNull()
    expect(matchRoute('GET', '/api/devices/aa:bb:cc:dd:ee:ff/secrets')).toBeNull()
  })
})
