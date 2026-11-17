import { describe, expect, it } from 'vitest'
import type { Config } from './config'
import { RecentCounters, gatherStatus } from './status'

const config = (threatIntel = true): Config => ({
  sessionSecret: 's'.repeat(32),
  password: 'p'.repeat(12),
  origin: 'http://192.168.1.5:3000',
  secureCookies: false,
  upstreams: {
    killswitch: {
      url: 'http://ks:8084',
      key: 'ks-key',
      urlVar: 'KILLSWITCH_URL',
      keyVar: 'KILLSWITCH_API_KEY',
    },
    'device-inventory': {
      url: 'http://di:8081',
      key: 'di-key',
      urlVar: 'DEVICE_INVENTORY_URL',
      keyVar: 'DEVICE_API_KEY',
    },
    'detection-engine': {
      url: 'http://de:8080',
      key: 'de-key',
      urlVar: 'DETECTION_ENGINE_URL',
      keyVar: 'DETECTION_API_KEY',
    },
  },
  threatIntel: threatIntel ? { url: 'http://tis:8083', urlVar: 'THREAT_INTEL_URL' } : null,
  notes: [],
})

const NOW = Date.parse('2026-11-17T12:00:00Z')
const unix = (msAgo: number) => (NOW - msAgo) / 1000

const KS_METRICS = `killswitch_actions_pending 2
killswitch_actions_active 1
killswitch_actions_revert_failed 0
killswitch_actions_awaiting_confirmation 0
killswitch_agent_last_poll_timestamp_seconds 0
killswitch_audit_outbox_pending 0
killswitch_audit_outbox_oldest_age_seconds 0
go_goroutines 12
`

const DE_METRICS = (
  pages: number,
  errors: number,
) => `detection_engine_querylog_pages_total ${pages}
detection_engine_poll_errors_total ${errors}
detection_engine_querylog_gaps_total 0
detection_engine_queries_checked_total ${pages * 10}
detection_engine_threatlist_domains_total 250
detection_engine_sensor_cursor_lag_seconds{source="suricata_alerts"} 31
detection_engine_sensor_cursor_lag_seconds{source="zeek_ssl"} 900
detection_engine_sensor_rows_ingested_total{source="suricata_alerts"} 120
detection_engine_sensor_ingest_errors_total{source="zeek_ssl"} 3
detection_engine_ioc_sync_last_success_timestamp_seconds ${unix(120_000)}
detection_engine_ioc_sync_indicators 4100
detection_engine_ioc_sync_failures_total{reason="http"} 2
detection_engine_store_durable 1
detection_engine_outbox_backlog 4
detection_engine_outbox_oldest_age_seconds 75
detection_engine_active_suppressions 1
`

const DI_READY = {
  status: 'ready',
  agent: {
    ready: true,
    agent: 'netagent-1',
    interface: 'eth0',
    last_seen: new Date(NOW - 3000).toISOString(),
    age_seconds: 3,
    capture: { arp: true, dhcp: true, mdns: false },
    dropped: 0,
  },
}

const DI_METRICS = `device_inventory_capture_up{proto="arp"} 1
device_inventory_capture_up{proto="dhcp"} 1
device_inventory_known_devices 17
device_inventory_last_device_event_timestamp_seconds ${unix(45_000)}
device_inventory_frames_received_total{proto="arp"} 100
device_inventory_frames_received_total{proto="dhcp"} 5
`

const TIS_METRICS = `threat_intel_source_enabled{source="spamhaus"} 1
threat_intel_source_enabled{source="threatfox"} 0
threat_intel_source_last_success_timestamp_seconds{source="spamhaus"} ${unix(3_600_000)}
threat_intel_source_indicators{source="spamhaus"} 1300
threat_intel_source_failures_total{source="spamhaus"} 1
threat_intel_store_indicators 1300
threat_intel_store_capacity 100000
threat_intel_store_persistent 1
threat_intel_sync_cycle_last_complete_timestamp_seconds ${unix(3_600_000)}
threat_intel_ready 1
`

type Route = { status: number; body: string } | 'unreachable' | 'timeout'

function fakeFetch(routes: Record<string, Route>) {
  const calls: { url: string; headers: Record<string, string> }[] = []
  const fetchImpl = async (url: string, init: RequestInit & { timeoutMs?: number } = {}) => {
    calls.push({ url, headers: (init.headers ?? {}) as Record<string, string> })
    const r = routes[url]
    if (r === undefined) return new Response('{"error":"not found"}', { status: 404 })
    if (r === 'unreachable') throw new TypeError('fetch failed')
    if (r === 'timeout') throw Object.assign(new Error('aborted'), { name: 'AbortError' })
    return new Response(r.body, { status: r.status })
  }
  return { fetchImpl, calls }
}

function healthy(pages = 40, errors = 0): Record<string, Route> {
  return {
    'http://ks:8084/healthz': { status: 200, body: '{"status":"ok"}' },
    'http://ks:8084/metrics': { status: 200, body: KS_METRICS },
    'http://de:8080/healthz': { status: 200, body: '{"status":"ok"}' },
    'http://de:8080/metrics': { status: 200, body: DE_METRICS(pages, errors) },
    'http://di:8081/readyz': { status: 200, body: JSON.stringify(DI_READY) },
    'http://di:8081/metrics': { status: 200, body: DI_METRICS },
    'http://tis:8083/readyz': { status: 200, body: '{"status":"ready","indicators":1300}' },
    'http://tis:8083/metrics': { status: 200, body: TIS_METRICS },
  }
}

describe('gatherStatus', () => {
  it('composes what every service reports', async () => {
    const { fetchImpl } = fakeFetch(healthy())
    const s = await gatherStatus(config(), 'anna', {
      fetchImpl,
      recent: new RecentCounters(),
      now: () => NOW,
    })
    expect(s.services.map((p) => [p.service, p.up, p.metrics, p.error])).toEqual([
      ['killswitch', true, true, ''],
      ['detection-engine', true, true, ''],
      ['device-inventory', true, true, ''],
      ['threat-intel-sync', true, true, ''],
    ])
    expect(s.capture).toMatchObject({
      ready: true,
      agentReady: true,
      agent: 'netagent-1',
      interface: 'eth0',
      ageSeconds: 3,
      capture: { arp: true, dhcp: true, mdns: false },
      expected: ['arp', 'dhcp'],
      knownDevices: 17,
      lastSighting: new Date(NOW - 45_000).toISOString(),
      required: null,
      // The first read has nothing to compare with.
      framesRecent: null,
    })
    expect(s.dns).toMatchObject({ pagesRead: 40, pollErrors: 0, threatlistSize: 250 })
    expect(s.sensors).toEqual([
      expect.objectContaining({ source: 'suricata_alerts', lagSeconds: 31, rows: 120, errors: 0 }),
      expect.objectContaining({ source: 'zeek_ssl', lagSeconds: 900, rows: null, errors: 3 }),
    ])
    expect(s.detection).toEqual({
      durable: true,
      backlog: 4,
      backlogOldestSeconds: 75,
      activeSuppressions: 1,
    })
    expect(s.engineIntel).toEqual({
      lastSuccess: new Date(NOW - 120_000).toISOString(),
      indicators: 4100,
      failures: { http: 2 },
    })
    expect(s.threatIntel).toMatchObject({
      ready: true,
      indicators: 1300,
      capacity: 100000,
      persistent: true,
      sources: [
        {
          source: 'spamhaus',
          enabled: true,
          lastSuccess: new Date(NOW - 3_600_000).toISOString(),
          indicators: 1300,
          failures: 1,
        },
        {
          source: 'threatfox',
          enabled: false,
          lastSuccess: null,
          indicators: null,
          failures: null,
        },
      ],
    })
    // 0 from the controller means "never since start-up", not the epoch.
    expect(s.enforcement).toMatchObject({ pending: 2, active: 1, agentLastPoll: null })
  })

  it('sends a key and the actor only to the services that take one', async () => {
    const { fetchImpl, calls } = fakeFetch(healthy())
    await gatherStatus(config(), 'anna', {
      fetchImpl,
      recent: new RecentCounters(),
      now: () => NOW,
    })
    const auth = (u: string) => calls.find((c) => c.url === u)?.headers
    expect(auth('http://ks:8084/metrics')).toMatchObject({
      Authorization: 'Bearer ks-key',
      'X-Netsoldier-Actor': 'anna',
    })
    expect(auth('http://di:8081/readyz')?.Authorization).toBe('Bearer di-key')
    expect(auth('http://de:8080/healthz')?.Authorization).toBe('Bearer de-key')
    expect(auth('http://tis:8083/metrics')?.Authorization).toBeUndefined()
    expect(auth('http://tis:8083/readyz')?.['X-Netsoldier-Actor']).toBeUndefined()
  })

  it('reports an unreachable service as unknown, never as zeros', async () => {
    const routes = healthy()
    routes['http://de:8080/healthz'] = 'unreachable'
    routes['http://de:8080/metrics'] = 'timeout'
    const { fetchImpl } = fakeFetch(routes)
    const s = await gatherStatus(config(), 'anna', { fetchImpl, recent: new RecentCounters() })
    const de = s.services.find((p) => p.service === 'detection-engine')!
    expect(de).toMatchObject({ up: false, metrics: false })
    expect(de.error).toBe('/healthz: unreachable; /metrics: timed out')
    expect(s.dns).toBeNull()
    expect(s.sensors).toBeNull()
    expect(s.detection).toBeNull()
    expect(s.engineIntel).toBeNull()
    // The others are unaffected.
    expect(s.capture?.agentReady).toBe(true)
  })

  it('names the key when a service refuses it', async () => {
    const routes = healthy()
    routes['http://di:8081/metrics'] = { status: 401, body: '{"error":"unauthorized"}' }
    const { fetchImpl } = fakeFetch(routes)
    const s = await gatherStatus(config(), 'anna', { fetchImpl, recent: new RecentCounters() })
    const di = s.services.find((p) => p.service === 'device-inventory')!
    expect(di.error).toContain('check DEVICE_API_KEY')
    // /readyz still answered: the capture state is known, the metrics are not.
    expect(s.capture).toMatchObject({ agentReady: true, knownDevices: null, expected: [] })
  })

  it('reads a not-ready device-inventory and threat-intel-sync from their 503 bodies', async () => {
    const routes = healthy()
    routes['http://di:8081/readyz'] = {
      status: 503,
      body: JSON.stringify({
        status: 'not ready',
        agent: {
          ready: false,
          age_seconds: 0,
          dropped: 0,
          reason: 'no heartbeat from the agent yet',
        },
      }),
    }
    routes['http://tis:8083/readyz'] = {
      status: 503,
      body: '{"status":"not ready","indicators":0,"reason":"no successful fetch yet"}',
    }
    const { fetchImpl } = fakeFetch(routes)
    const s = await gatherStatus(config(), 'anna', { fetchImpl, recent: new RecentCounters() })
    expect(s.services.find((p) => p.service === 'device-inventory')).toMatchObject({
      up: true,
      error: '',
    })
    expect(s.capture).toMatchObject({
      ready: false,
      agentReady: false,
      required: true,
      lastSeen: null,
      ageSeconds: null,
      reason: 'no heartbeat from the agent yet',
    })
    expect(s.threatIntel).toMatchObject({ ready: false, reason: 'no successful fetch yet' })
  })

  it('reads nothing from a 503 that is not a readiness answer', async () => {
    const routes = healthy()
    routes['http://di:8081/readyz'] = { status: 503, body: '{"error":"unavailable"}' }
    routes['http://tis:8083/readyz'] = { status: 503, body: 'Service Unavailable' }
    routes['http://tis:8083/metrics'] = { status: 503, body: '' }
    const { fetchImpl } = fakeFetch(routes)
    const s = await gatherStatus(config(), 'anna', { fetchImpl, recent: new RecentCounters() })
    expect(s.services.find((p) => p.service === 'device-inventory')).toMatchObject({
      up: false,
      error: '/readyz: answered HTTP 503',
    })
    expect(s.capture).toBeNull()
    expect(s.threatIntel).toBeNull()
  })

  it('tells an inventory that expects no agent from one whose agent is gone', async () => {
    const routes = healthy()
    routes['http://di:8081/readyz'] = {
      status: 200,
      body: JSON.stringify({
        status: 'ready',
        agent: {
          ready: false,
          age_seconds: 0,
          dropped: 0,
          reason: 'no heartbeat from the agent yet',
        },
      }),
    }
    const { fetchImpl } = fakeFetch(routes)
    const s = await gatherStatus(config(), 'anna', { fetchImpl, recent: new RecentCounters() })
    expect(s.capture?.required).toBe(false)
  })

  it('does not read threat-intel-sync without THREAT_INTEL_URL', async () => {
    const { fetchImpl, calls } = fakeFetch(healthy())
    const s = await gatherStatus(config(false), 'anna', { fetchImpl, recent: new RecentCounters() })
    expect(calls.some((c) => c.url.startsWith('http://tis'))).toBe(false)
    expect(s.services.at(-1)).toMatchObject({
      service: 'threat-intel-sync',
      configured: false,
      urlVar: 'THREAT_INTEL_URL',
    })
    expect(s.threatIntel).toBeNull()
  })

  it('refuses a metrics answer that is too large', async () => {
    const routes = healthy()
    routes['http://ks:8084/metrics'] = { status: 200, body: 'x'.repeat(5 * 1024 * 1024) }
    const { fetchImpl } = fakeFetch(routes)
    const s = await gatherStatus(config(), 'anna', { fetchImpl, recent: new RecentCounters() })
    expect(s.services[0].error).toBe('/metrics: answered with too much data')
    expect(s.enforcement).toBeNull()
  })

  it('says what happened since the previous read, once one is old enough', async () => {
    const recent = new RecentCounters()
    let now = NOW
    let pages = 40
    let errors = 0
    const run = async () => {
      const { fetchImpl } = fakeFetch(healthy(pages, errors))
      return gatherStatus(config(), 'anna', { fetchImpl, recent, now: () => now })
    }
    expect((await run()).dns?.pagesRecent).toBeNull()
    now += 30_000
    pages = 52
    errors = 1
    const s = await run()
    expect(s.dns?.pagesRecent).toEqual({ seconds: 30, value: 12 })
    expect(s.dns?.errorsRecent).toEqual({ seconds: 30, value: 1 })
    expect(s.dns?.queriesRecent).toEqual({ seconds: 30, value: 120 })
  })
})

describe('RecentCounters', () => {
  it('compares with the oldest read in the window that is old enough', () => {
    const r = new RecentCounters(5 * 60_000, 20_000)
    expect(r.observe('k', 10, 0)).toBeNull()
    expect(r.observe('k', 12, 10_000)).toBeNull() // too close to compare
    expect(r.observe('k', 15, 30_000)).toEqual({ seconds: 30, value: 5 })
    expect(r.observe('k', 20, 60_000)).toEqual({ seconds: 60, value: 10 })
    // Past the window the first reads drop out.
    expect(r.observe('k', 30, 320_000)).toEqual({ seconds: 290, value: 15 })
  })

  it('treats a counter that went down as reset by a restart', () => {
    const r = new RecentCounters()
    r.observe('k', 500, 0)
    expect(r.observe('k', 7, 30_000)).toEqual({ seconds: 30, value: 7 })
  })

  it('ignores values a service did not report', () => {
    const r = new RecentCounters()
    expect(r.observe('k', null, 0)).toBeNull()
    expect(r.observe('k', NaN, 30_000)).toBeNull()
  })
})
