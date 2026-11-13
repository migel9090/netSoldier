import { describe, expect, it } from 'vitest'
import {
  alertClient,
  alertClientText,
  alertHeadline,
  alertObservedDomain,
  signalClasses,
} from './alerts'
import type { Alert } from './types'

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
