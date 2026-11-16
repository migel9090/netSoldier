import { describe, expect, it } from 'vitest'
import {
  alertClient,
  alertClientText,
  alertHeadline,
  alertObservedDomain,
  falsePositiveQuestion,
  falsePositiveVerdict,
  liftQuestion,
  liftVerdict,
  signalClasses,
  suppressionFor,
} from './alerts'
import type { Alert, Suppression } from './types'

const v2ids: Alert = {
  id: 'DET-7f3a9c-42',
  timestamp: '2026-11-16T12:00:00Z',
  summary: 'Suricata: ET MALWARE Mozi botnet C2 traffic',
  domain: '',
  matched_ioc: '203.0.113.9',
  ioc_type: 'ip',
  client_ip: '192.168.1.77',
  client_mac: 'aa:bb:cc:00:00:01',
  client_name: 'kids-tablet',
  severity: 'high',
  signal_class: 'ids-signature',
  signals: [
    { class: 'ids-signature', confidence: 70, indicator: '2030919', indicator_type: 'sid' },
  ],
  target: { type: 'ip', value: '203.0.113.9' },
}

describe('alert display', () => {
  it('uses the v2 summary as the headline, never the empty domain', () => {
    expect(alertHeadline(v2ids)).toBe('Suricata: ET MALWARE Mozi botnet C2 traffic')
    expect(alertObservedDomain(v2ids)).toBe('')
    expect(alertClient(v2ids)).toEqual({
      name: 'kids-tablet',
      mac: 'aa:bb:cc:00:00:01',
      ip: '192.168.1.77',
    })
    expect(alertClientText(v2ids)).toContain('kids-tablet')
  })

  it('shows the observed domain as a detail under a v2 summary', () => {
    const a: Alert = {
      ...v2ids,
      summary: 'DNS query for a listed domain',
      domain: 'cdn.evil.example',
    }
    expect(alertObservedDomain(a)).toBe('cdn.evil.example')
  })

  it('falls back to the domain for alerts from an older engine', () => {
    const old = {
      id: 'DET-3',
      timestamp: '2026-11-16T12:00:00Z',
      domain: 'd3.example',
      client_ip: '192.168.1.77',
      severity: 'high',
      signals: ['ioc', 'beacon'],
    } as Alert
    expect(alertHeadline(old)).toBe('d3.example')
    expect(alertObservedDomain(old)).toBe('')
    expect(signalClasses(old)).toEqual(['ioc', 'beacon'])
    expect(alertClient(old)).toEqual({ name: '', mac: '', ip: '192.168.1.77' })
  })

  it('is never empty', () => {
    expect(alertHeadline({ id: 'DET-x-1', summary: '  ', domain: '' })).toBe('Alert DET-x-1')
    expect(alertHeadline({ id: 'DET-x-1', matched_ioc: '203.0.113.9' })).toBe('203.0.113.9')
  })

  it('reads signal classes from either shape', () => {
    expect(signalClasses(v2ids)).toEqual(['ids-signature'])
    expect(signalClasses({ ...v2ids, signals: undefined })).toEqual(['ids-signature'])
    expect(
      signalClasses({
        ...v2ids,
        signals: [{ class: 'ioc' }, { class: 'beacon' }, { class: 'ioc' }],
      }),
    ).toEqual(['ioc', 'beacon'])
  })
})

describe('false-positive feedback', () => {
  const suppression = (over: Partial<Suppression>): Suppression => ({
    matched_ioc: '203.0.113.9',
    client_ip: '192.168.1.77',
    signal_class: 'ids-signature',
    verdict: 'false_positive',
    analyst: 'Michal',
    timestamp: '2026-11-16T12:00:00Z',
    ...over,
  })

  // POST /feedback refuses a verdict without one unless it still holds the alert.
  it('sends the alert’s own signal class, indicator and device', () => {
    expect(falsePositiveVerdict(v2ids)).toEqual({
      alert_id: 'DET-7f3a9c-42',
      matched_ioc: '203.0.113.9',
      client_ip: '192.168.1.77',
      signal_class: 'ids-signature',
      verdict: 'false_positive',
    })
    const composite: Alert = {
      ...v2ids,
      signal_class: 'composite',
      signals: [{ class: 'ioc' }, { class: 'beacon' }],
    }
    expect(falsePositiveVerdict(composite).signal_class).toBe('composite')
    // An alert without signal_class falls back to its first signal.
    expect(falsePositiveVerdict({ ...v2ids, signal_class: undefined }).signal_class).toBe(
      'ids-signature',
    )
  })

  it('asks before suppressing, saying for how long and what it stops', () => {
    const q = falsePositiveQuestion(v2ids)
    expect(q).toContain('30 days')
    expect(q).toContain('203.0.113.9')
    expect(q).toContain('kids-tablet (192.168.1.77)')
    expect(q).toContain('no longer reach the killswitch')
    expect(falsePositiveQuestion({ ...v2ids, signal_class: 'composite' })).toContain(
      'covers the combination only',
    )
  })

  it('matches suppressions the way the engine does', () => {
    expect(suppressionFor(v2ids, [suppression({})])).toBeDefined()
    // Case and whitespace do not matter; the indicator-wide one applies too.
    expect(
      suppressionFor(v2ids, [suppression({ matched_ioc: ' 203.0.113.9 ', client_ip: '' })]),
    ).toBeDefined()
    // Another class, or another device, does not silence this alert.
    expect(suppressionFor(v2ids, [suppression({ signal_class: 'ioc' })])).toBeUndefined()
    expect(suppressionFor(v2ids, [suppression({ client_ip: '192.168.1.78' })])).toBeUndefined()
  })

  it('lifts a suppression with a confirmed verdict for the same key', () => {
    expect(liftVerdict(suppression({}))).toEqual({
      matched_ioc: '203.0.113.9',
      client_ip: '192.168.1.77',
      signal_class: 'ids-signature',
      verdict: 'confirmed',
      reason: 'suppression lifted in the web UI',
    })
    expect(liftVerdict(suppression({ client_ip: '' }))).not.toHaveProperty('client_ip')
    expect(liftQuestion(suppression({}))).toContain('reach the killswitch again')
  })
})
