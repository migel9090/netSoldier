import { describe, expect, it } from 'vitest'
import { byLabel, parseMetrics, single } from './promtext'

// Shaped like client_golang's text output.
const SCRAPE = `# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 23
# HELP detection_engine_sensor_cursor_lag_seconds How far behind.
# TYPE detection_engine_sensor_cursor_lag_seconds gauge
detection_engine_sensor_cursor_lag_seconds{source="suricata_alerts"} 31.5
detection_engine_sensor_cursor_lag_seconds{source="zeek_ssl"} 1.2e+03
detection_engine_store_durable 1
detection_engine_outbox_oldest_age_seconds 0
weird_label{a="x\\"y",b="line\\nbreak",c="back\\\\slash"} 7
with_timestamp{a="1"} 4 1700000000000
not_a_number{a="1"} NaN
infinite +Inf
broken{a="1" 5
broken2{a=1} 5
broken3 five
`

describe('parseMetrics', () => {
  it('keeps only the families asked for, with their labels and values', () => {
    const m = parseMetrics(
      SCRAPE,
      new Set(['detection_engine_sensor_cursor_lag_seconds', 'detection_engine_store_durable']),
    )
    expect([...m.keys()].sort()).toEqual([
      'detection_engine_sensor_cursor_lag_seconds',
      'detection_engine_store_durable',
    ])
    expect(byLabel(m, 'detection_engine_sensor_cursor_lag_seconds', 'source')).toEqual(
      new Map([
        ['suricata_alerts', 31.5],
        ['zeek_ssl', 1200],
      ]),
    )
    expect(single(m, 'detection_engine_store_durable')).toBe(1)
  })

  it('reads escaped label values and an optional timestamp', () => {
    const m = parseMetrics(SCRAPE, new Set(['weird_label', 'with_timestamp']))
    expect(m.get('weird_label')).toEqual([
      { labels: { a: 'x"y', b: 'line\nbreak', c: 'back\\slash' }, value: 7 },
    ])
    expect(single(m, 'with_timestamp')).toBe(4)
  })

  it('skips malformed lines instead of failing the scrape', () => {
    const m = parseMetrics(SCRAPE, new Set(['broken', 'broken2', 'broken3', 'go_goroutines']))
    expect(m.has('broken')).toBe(false)
    expect(m.has('broken2')).toBe(false)
    expect(m.has('broken3')).toBe(false)
    expect(single(m, 'go_goroutines')).toBe(23)
  })

  it('reports a NaN series as missing and keeps infinities', () => {
    const m = parseMetrics(SCRAPE, new Set(['not_a_number', 'infinite']))
    expect(single(m, 'not_a_number')).toBeNull()
    expect(byLabel(m, 'not_a_number', 'a').size).toBe(0)
    expect(single(m, 'infinite')).toBe(Infinity)
  })

  it('says null for a series that is not there, and 0 when the service reports 0', () => {
    const m = parseMetrics(SCRAPE, new Set(['detection_engine_outbox_oldest_age_seconds']))
    expect(single(m, 'detection_engine_outbox_oldest_age_seconds')).toBe(0)
    expect(single(m, 'detection_engine_outbox_backlog')).toBeNull()
  })
})
