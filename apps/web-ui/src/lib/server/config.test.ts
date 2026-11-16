import { describe, expect, it } from 'vitest'
import { readConfig } from './config'

const BASE = {
  SESSION_SECRET: 's'.repeat(32),
  WEB_UI_PASSWORD: 'twelve chars',
  ORIGIN: 'http://192.168.1.5:3000',
  KILLSWITCH_URL: 'http://killswitch-controller:8084/',
  KILLSWITCH_API_KEY: 'k',
  DEVICE_INVENTORY_URL: 'http://device-inventory:8081',
  DEVICE_API_KEY: 'd',
  DETECTION_ENGINE_URL: 'http://detection-engine:8080',
  DETECTION_API_KEY: 'e',
}

describe('readConfig', () => {
  it('normalises ORIGIN the way browsers send it and derives the cookie flag', () => {
    const r = readConfig({ ...BASE, ORIGIN: 'HTTPS://NetSoldier.LAN:443/' })
    expect(r.ok && r.config.origin).toBe('https://netsoldier.lan')
    expect(r.ok && r.config.secureCookies).toBe(true)

    const lan = readConfig(BASE)
    expect(lan.ok && lan.config.secureCookies).toBe(false)
  })

  it('strips a trailing slash from backend URLs', () => {
    const r = readConfig(BASE)
    expect(r.ok && r.config.upstreams.killswitch.url).toBe('http://killswitch-controller:8084')
  })

  it('lists every problem at once and never echoes a secret', () => {
    const r = readConfig({ SESSION_SECRET: 'short-secret-value' })
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.problems).toHaveLength(9)
    expect(r.problems.join('\n')).not.toContain('short-secret-value')
  })

  it('accepts a 32-character secret and refuses 31', () => {
    expect(readConfig(BASE).ok).toBe(true)
    expect(readConfig({ ...BASE, SESSION_SECRET: 's'.repeat(31) }).ok).toBe(false)
  })

  // Throttling bounds the rate, not the total: a four-character household
  // password used to be accepted and would fall to patient guessing.
  it('requires a password of at least 12 characters, without echoing it', () => {
    for (const weak of ['1234', 'eleven char']) {
      const r = readConfig({ ...BASE, WEB_UI_PASSWORD: weak })
      expect(r.ok, weak).toBe(false)
      if (r.ok) continue
      expect(r.problems).toEqual(['WEB_UI_PASSWORD is too short (at least 12 characters required)'])
      expect(r.problems.join('\n')).not.toContain(weak)
    }
    // Counted in characters, not bytes.
    expect(readConfig({ ...BASE, WEB_UI_PASSWORD: 'zażółć gęśl' }).ok).toBe(false)
    expect(readConfig({ ...BASE, WEB_UI_PASSWORD: 'zażółć gęślą' }).ok).toBe(true)
  })

  it('refuses a password equal to SESSION_SECRET', () => {
    const secret = 'x'.repeat(40)
    const r = readConfig({ ...BASE, SESSION_SECRET: secret, WEB_UI_PASSWORD: secret })
    expect(r.ok).toBe(false)
    if (!r.ok)
      expect(r.problems).toEqual(['WEB_UI_PASSWORD must not be the same as SESSION_SECRET'])
  })
})
