import { describe, expect, it } from 'vitest'
import {
  agoWords,
  captureFinding,
  dnsFinding,
  durationWords,
  feedVerdict,
  intelFinding,
  sensorVerdict,
  sensorsFinding,
  type CaptureStatus,
  type DnsStatus,
  type ServiceProbe,
  type ThreatIntelStatus,
} from './status'

const NOW = Date.parse('2026-11-17T12:00:00Z')
const ago = (s: number) => new Date(NOW - s * 1000).toISOString()

function capture(over: Partial<CaptureStatus> = {}): CaptureStatus {
  return {
    ready: true,
    agentReady: true,
    agent: 'netagent-1',
    interface: 'eth0',
    lastSeen: ago(3),
    ageSeconds: 3,
    capture: { dhcp: true, arp: true, mdns: false },
    expected: ['arp', 'dhcp'],
    dropped: 0,
    reason: '',
    required: null,
    knownDevices: 12,
    lastSighting: ago(20),
    framesRecent: null,
    ...over,
  }
}

function dns(over: Partial<DnsStatus> = {}): DnsStatus {
  return {
    pagesRead: 100,
    pollErrors: 0,
    gaps: 0,
    queriesChecked: 1000,
    threatlistSize: 250,
    pagesRecent: null,
    errorsRecent: null,
    queriesRecent: null,
    ...over,
  }
}

const probe = (over: Partial<ServiceProbe> = {}): ServiceProbe => ({
  service: 'threat-intel-sync',
  configured: true,
  urlVar: 'THREAT_INTEL_URL',
  up: true,
  metrics: true,
  error: '',
  ...over,
})

describe('in words', () => {
  it('writes durations and ages', () => {
    expect(durationWords(4)).toBe('4 s')
    expect(durationWords(600)).toBe('10 min')
    expect(durationWords(7200)).toBe('2 h')
    expect(durationWords(5 * 86400)).toBe('5 days')
    expect(agoWords(ago(120), NOW)).toBe('2 min ago')
    expect(agoWords(null, NOW)).toBe('never')
  })
})

describe('does the system see the network', () => {
  it('yes, while the agent reports', () => {
    expect(captureFinding(capture())).toEqual({
      verdict: 'ok',
      text: 'Seeing the network: the network agent netagent-1 on eth0 is reporting, last heard 3 s ago, capturing arp, dhcp.',
    })
  })

  it('no, with device-inventory’s own reason', () => {
    const f = captureFinding(
      capture({ ready: false, agentReady: false, required: true, reason: 'captures down: arp' }),
    )
    expect(f).toEqual({ verdict: 'fail', text: 'NOT seeing the network: captures down: arp.' })
  })

  it('says so when no agent is expected, instead of calling it a failure', () => {
    const f = captureFinding(
      capture({ agentReady: false, required: false, reason: 'no heartbeat from the agent yet' }),
    )
    expect(f.verdict).toBe('off')
    expect(f.text).toContain('NETAGENT_EXPECT_CAPTURE=none')
  })

  it('unknown when device-inventory could not be read', () => {
    const f = captureFinding(
      null,
      probe({ service: 'device-inventory', error: '/readyz: unreachable' }),
    )
    expect(f).toEqual({
      verdict: 'unknown',
      text: 'Unknown: device-inventory could not be read (/readyz: unreachable).',
    })
  })
})

describe('DNS lookups', () => {
  it('judges the recent stretch when there is one', () => {
    const recent = (pages: number, errors: number) =>
      dnsFinding(
        dns({
          pagesRecent: { seconds: 60, value: pages },
          errorsRecent: { seconds: 60, value: errors },
        }),
      )
    expect(recent(4, 0)).toEqual({
      verdict: 'ok',
      text: 'DNS lookups are being checked: 4 query-log pages read in the last 60 s.',
    })
    expect(recent(4, 1).verdict).toBe('warn')
    expect(recent(0, 3)).toEqual({
      verdict: 'fail',
      text: "NOT reading DNS: every poll of AdGuard's query log failed in the last 60 s.",
    })
    expect(recent(0, 0).verdict).toBe('warn')
  })

  it('falls back to the totals on the first read', () => {
    expect(dnsFinding(dns()).verdict).toBe('ok')
    expect(dnsFinding(dns({ pagesRead: 0, pollErrors: 5 })).verdict).toBe('fail')
    expect(dnsFinding(dns({ pagesRead: 0, pollErrors: 0 })).verdict).toBe('warn')
    expect(dnsFinding(dns({ pagesRead: null })).verdict).toBe('unknown')
    expect(dnsFinding(null).verdict).toBe('unknown')
  })
})

describe('packet sensors', () => {
  const sensor = (lag: number | null, errors = 0) => ({
    source: 'suricata_alerts',
    lagSeconds: lag,
    rows: 10,
    errors,
    rowsRecent: null,
    errorsRecent: { seconds: 60, value: errors },
  })

  it('calls a source behind past five minutes or with recent errors', () => {
    expect(sensorVerdict(sensor(30))).toBe('ok')
    expect(sensorVerdict(sensor(301))).toBe('warn')
    expect(sensorVerdict(sensor(30, 2))).toBe('warn')
    expect(sensorVerdict(sensor(null))).toBe('unknown')
  })

  it('tells "no sensors here" from "could not be read"', () => {
    expect(sensorsFinding([]).verdict).toBe('off')
    expect(sensorsFinding(null).verdict).toBe('unknown')
    expect(sensorsFinding([sensor(30)]).verdict).toBe('ok')
    expect(sensorsFinding([sensor(30), { ...sensor(900), source: 'zeek_ssl' }])).toEqual({
      verdict: 'warn',
      text: 'Behind or failing: zeek_ssl.',
    })
  })
})

describe('threat intelligence', () => {
  const ti = (over: Partial<ThreatIntelStatus> = {}): ThreatIntelStatus => ({
    ready: true,
    reason: '',
    indicators: 1300,
    capacity: 100000,
    persistent: true,
    lastCycle: ago(3600),
    sources: [
      { source: 'spamhaus', enabled: true, lastSuccess: ago(3600), indicators: 1300, failures: 0 },
      { source: 'threatfox', enabled: false, lastSuccess: null, indicators: null, failures: null },
    ],
    ...over,
  })
  const engine = { lastSuccess: ago(120), indicators: 1300, failures: {} }

  it('judges each feed by its last success', () => {
    expect(feedVerdict(ti().sources[0], NOW)).toBe('ok')
    expect(feedVerdict({ ...ti().sources[0], lastSuccess: ago(13 * 3600) }, NOW)).toBe('warn')
    expect(feedVerdict({ ...ti().sources[0], lastSuccess: null }, NOW)).toBe('fail')
    expect(feedVerdict(ti().sources[1], NOW)).toBe('off')
  })

  it('sums up threat-intel-sync and what the engine loaded', () => {
    expect(intelFinding(engine, ti(), probe(), NOW)).toEqual({
      verdict: 'ok',
      text: 'Feeds: threat-intel-sync holds 1300 indicators; the detection engine loaded 1300 indicators 2 min ago.',
    })
    const notReady = intelFinding(engine, ti({ ready: false, reason: 'no set yet' }), probe(), NOW)
    expect(notReady.verdict).toBe('fail')
    expect(notReady.text).toContain('NOT ready: no set yet')
    const stale = intelFinding(
      engine,
      ti({ sources: [{ ...ti().sources[0], lastSuccess: null }] }),
      probe(),
      NOW,
    )
    expect(stale.verdict).toBe('warn')
    expect(stale.text).toContain('stale or never synced: spamhaus')
  })

  it('works from the engine alone when threat-intel-sync is not configured', () => {
    const f = intelFinding(engine, null, probe({ configured: false, up: null }), NOW)
    expect(f.verdict).toBe('ok')
    expect(f.text).toContain('THREAT_INTEL_URL is not set')
    expect(intelFinding(null, null, probe({ error: '/readyz: timed out' }), NOW).verdict).toBe(
      'unknown',
    )
  })
})
