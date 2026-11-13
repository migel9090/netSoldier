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
      ['GET', '/api/killswitch/active', '/actions/active'],
      ['GET', '/api/killswitch/failed', '/actions/failed'],
      ['GET', '/api/killswitch/history', '/actions/history'],
      ['GET', '/api/killswitch/ACT-1', '/actions/ACT-1'],
      ['POST', '/api/killswitch/ACT-1/approve', '/actions/ACT-1/approve'],
      ['POST', '/api/killswitch/ACT-1/revert', '/actions/ACT-1/revert'],
      // Shadowed by the generic {id} route until the fixed names came first.
      ['GET', '/api/killswitch/policy', '/policy'],
      // What encodeURIComponent(mac) produces; refusing it 404'd every detail page.
      ['GET', '/api/devices/aa%3Abb%3Acc%3Add%3Aee%3Aff', '/devices/aa:bb:cc:dd:ee:ff'],
      [
        'GET',
        '/api/devices/AA%3aBB%3acc%3Add%3Aee%3Aff/alerts',
        '/devices/AA:BB:cc:dd:ee:ff/alerts',
      ],
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
    expect(matchRoute('GET', '/api/devices/aa%3Abb%3Acc%3Add%3Aee')).toBeNull()
    expect(matchRoute('GET', '/api/devices/aa%253Abb%253Acc%253Add%253Aee%253Aff')).toBeNull()
    expect(matchRoute('GET', '/api/devices/aa:bb:cc:dd:ee:ff/secrets')).toBeNull()
  })
})
