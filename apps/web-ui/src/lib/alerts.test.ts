import { describe, expect, it } from 'vitest'
import {
  alertAnchor,
  alertClient,
  alertClientText,
  alertHeadline,
  alertById,
  alertObservedDomain,
  falsePositiveQuestion,
  falsePositiveVerdict,
  isComposite,
  isSilenced,
  liftNote,
  liftQuestion,
  liftRequest,
  signalBreakdown,
  signalClasses,
  sortSuppressions,
  suppressionAnchor,
  suppressionDays,
  suppressionEnds,
  suppressionFor,
  suppressionPeriod,
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

  // A "confirmed" verdict used to stand in for a lift: it records the
  // indicator as a true positive, which nobody said.
  it('lifts exactly one suppression, naming its key, and sends no verdict', () => {
    const req = liftRequest(suppression({}))
    expect(req).toEqual({
      matched_ioc: '203.0.113.9',
      client_ip: '192.168.1.77',
      signal_class: 'ids-signature',
      reason: 'suppression lifted in the web UI',
    })
    expect(req).not.toHaveProperty('verdict')
    // The indicator-wide suppression is named by leaving the client out.
    expect(liftRequest(suppression({ client_ip: '' }))).not.toHaveProperty('client_ip')
  })

  it('says what lifting does, and what stays silenced', () => {
    const device = suppression({ expires_at: '2026-12-16T12:00:00Z' })
    const q = liftQuestion(device, [device])
    expect(q).toContain('on 192.168.1.77')
    expect(q).toContain('reach the killswitch again')
    expect(q).toContain('does not record the indicator as malicious')
    expect(q).not.toContain('confirmed')

    // A suppression on every device keeps silencing the device.
    const wide = suppression({ client_ip: '' })
    const both = liftQuestion(device, [device, wide])
    expect(both).toContain('also suppressed on every device')
    expect(both).not.toContain('reach the killswitch again')
    // And lifting the wide one leaves the per-device ones.
    expect(liftQuestion(wide, [device, wide])).toContain('single devices (192.168.1.77) stay')
  })

  it('takes when a suppression ends from the engine, or estimates it from the default', () => {
    expect(suppressionEnds(suppression({ expires_at: '2026-12-01T00:00:00Z' }))).toEqual({
      at: '2026-12-01T00:00:00Z',
      estimated: false,
    })
    // An engine from before expires_at: the default 30 days, flagged.
    expect(suppressionEnds(suppression({}))).toEqual({
      at: '2026-12-16T12:00:00.000Z',
      estimated: true,
    })
    expect(suppressionEnds(suppression({ timestamp: 'garbage' }))).toBeNull()
  })

  it('reads the engine’s suppression period off a suppression it reported', () => {
    expect(suppressionDays([])).toBeNull()
    expect(suppressionDays([suppression({})])).toBeNull()
    expect(
      suppressionDays([
        suppression({ timestamp: '2026-11-16T12:00:00Z', expires_at: '2026-11-23T12:00:00Z' }),
      ]),
    ).toBe(7)
    expect(suppressionPeriod(7)).toBe('7 days')
    expect(suppressionPeriod(1)).toBe('1 day')
    expect(suppressionPeriod(null)).toBe("30 days (the detection engine's default)")
    expect(falsePositiveQuestion(v2ids, 7)).toContain('For 7 days,')
    expect(falsePositiveQuestion(v2ids)).toContain("For 30 days (the detection engine's default)")
  })

  it('reads `suppressed` as silenced only when it is true', () => {
    expect(isSilenced({ suppressed: true })).toBe(true)
    for (const v of [undefined, false, 'true', 1] as unknown[]) {
      expect(isSilenced({ suppressed: v as boolean }), String(v)).toBe(false)
    }
  })

  it('gives rows stable, id-safe anchors', () => {
    const s = suppression({})
    expect(suppressionAnchor(s)).toMatch(/^suppression-[0-9a-f]{8}$/)
    // The engine's key: case and whitespace do not make another suppression.
    expect(suppressionAnchor(suppression({ matched_ioc: ' 203.0.113.9 ' }))).toBe(
      suppressionAnchor(s),
    )
    expect(suppressionAnchor(suppression({ client_ip: '' }))).not.toBe(suppressionAnchor(s))
    expect(alertAnchor({ id: 'DET "x" <y>' })).toMatch(/^alert-[0-9a-f]{8}$/)
  })
})

describe('signal breakdown', () => {
  const composite: Alert = {
    id: 'DET-c1',
    timestamp: '2026-11-16T12:00:00Z',
    severity: 'critical',
    signal_class: 'composite',
    confidence: 95,
    signals: [
      {
        class: 'ioc',
        confidence: 90,
        indicator: 'evil.example',
        indicator_type: 'domain',
        source: 'threatfox',
      },
      {
        class: 'beacon',
        confidence: 70,
        indicator: '203.0.113.9',
        indicator_type: 'ip',
        source: 'rita',
      },
      { class: 'tls', confidence: 60, source: 'zeek' },
    ],
  }

  it('lists each signal with its own class, confidence, indicator and source', () => {
    expect(isComposite(composite)).toBe(true)
    expect(signalBreakdown(composite)).toEqual([
      {
        class: 'ioc',
        confidence: 90,
        indicator: 'evil.example',
        indicatorType: 'domain',
        source: 'threatfox',
      },
      {
        class: 'beacon',
        confidence: 70,
        indicator: '203.0.113.9',
        indicatorType: 'ip',
        source: 'rita',
      },
      { class: 'tls', confidence: 60, indicator: '', indicatorType: '', source: 'zeek' },
    ])
  })

  it('takes the plain class names of older engines, and skips what is not a signal', () => {
    const old = {
      signal_class: 'ioc',
      signals: ['ioc', '', { class: '' }, null, { class: 'tls', confidence: Number.NaN }],
    } as unknown as Alert
    expect(isComposite(old)).toBe(false)
    expect(signalBreakdown(old)).toEqual([
      { class: 'ioc', confidence: null, indicator: '', indicatorType: '', source: '' },
      { class: 'tls', confidence: null, indicator: '', indicatorType: '', source: '' },
    ])
    expect(signalBreakdown({ signals: undefined } as Alert)).toEqual([])
  })

  it('finds a detection by id', () => {
    expect(alertById([composite], 'DET-c1')).toBe(composite)
    expect(alertById([composite], 'DET-x')).toBeUndefined()
    expect(alertById([composite], '')).toBeUndefined()
  })
})

describe('lifting in words', () => {
  const s: Suppression = {
    matched_ioc: 'evil.example',
    client_ip: '192.168.1.77',
    signal_class: 'ioc',
    verdict: 'false_positive',
    analyst: 'Anna',
    timestamp: '2026-11-16T12:00:00Z',
    expires_at: '2026-12-16T12:00:00Z',
  }

  it('says whether it was lifted, saved, or not there any more', () => {
    expect(liftNote(s, { inForce: true, persisted: true })).toEqual({
      tone: 'ok',
      text: 'Lifted the suppression of evil.example (ioc) on 192.168.1.77. Saved.',
    })
    expect(liftNote(s, { inForce: true, persisted: null }).text).toBe(
      'Lifted the suppression of evil.example (ioc) on 192.168.1.77.',
    )
    const unsaved = liftNote(s, { inForce: true, persisted: false })
    expect(unsaved.tone).toBe('warn')
    expect(unsaved.text).toContain('was NOT saved')
    expect(liftNote({ ...s, client_ip: undefined }, { inForce: false })).toEqual({
      tone: 'warn',
      text: 'Nothing to lift: the suppression of evil.example (ioc) on every device was no longer in force (lifted already, or it expired).',
    })
  })

  it('orders suppressions newest first, stably', () => {
    const older = { ...s, timestamp: '2026-11-15T12:00:00Z' }
    const b = { ...s, matched_ioc: 'b.example' }
    const wide = { ...s, client_ip: undefined }
    expect(sortSuppressions([older, s, b, wide])).toEqual([b, wide, s, older])
  })
})
