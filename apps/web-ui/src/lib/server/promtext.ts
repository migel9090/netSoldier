/**
 * A reader for the Prometheus text exposition format (version 0.0.4), just
 * enough for the system-status page to take a few series out of the
 * services' /metrics.
 *
 * The services have no status endpoint of their own beyond /healthz and
 * /readyz; their metrics are the only place that says whether a sensor
 * source is behind or when a feed last synced. Only the names asked for are
 * kept, so a large scrape never turns into a large object, and nothing of
 * the raw text reaches the browser.
 */

export interface Sample {
  labels: Record<string, string>
  value: number
}

export type Series = Map<string, Sample[]>

/** The largest /metrics body read; the services' are a few hundred kB at most. */
export const MAX_METRICS_BYTES = 4 * 1024 * 1024

/**
 * The samples of the metric families in `wanted`, by name. Comment lines,
 * other families and lines that do not parse are skipped: one odd line must
 * not cost the page every other value.
 */
export function parseMetrics(text: string, wanted: ReadonlySet<string>): Series {
  const out: Series = new Map()
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const name = line.match(/^[A-Za-z_:][A-Za-z0-9_:]*/)?.[0]
    if (!name || !wanted.has(name)) continue
    const sample = parseSample(line.slice(name.length))
    if (!sample) continue
    const list = out.get(name)
    if (list) list.push(sample)
    else out.set(name, [sample])
  }
  return out
}

/** `{a="1",b="x\"y"} 12.5 [timestamp]` → labels and value; null when malformed. */
function parseSample(rest: string): Sample | null {
  let i = 0
  const labels: Record<string, string> = {}
  if (rest[i] === '{') {
    i++
    for (;;) {
      while (rest[i] === ' ' || rest[i] === ',') i++
      if (rest[i] === '}') {
        i++
        break
      }
      const key = rest.slice(i).match(/^[A-Za-z_][A-Za-z0-9_]*/)?.[0]
      if (!key) return null
      i += key.length
      if (rest[i] !== '=' || rest[i + 1] !== '"') return null
      i += 2
      let value = ''
      for (;;) {
        const c = rest[i]
        if (c === undefined) return null
        if (c === '"') {
          i++
          break
        }
        if (c === '\\') {
          const n = rest[i + 1]
          value += n === 'n' ? '\n' : n === '"' ? '"' : n === '\\' ? '\\' : `\\${n ?? ''}`
          i += 2
          continue
        }
        value += c
        i++
      }
      labels[key] = value
    }
  }
  const fields = rest.slice(i).trim().split(/\s+/)
  if (fields.length < 1 || fields.length > 2 || fields[0] === '') return null
  const value = parseValue(fields[0])
  return value === null ? null : { labels, value }
}

function parseValue(s: string): number | null {
  switch (s) {
    case 'NaN':
      return NaN
    case '+Inf':
    case 'Inf':
      return Infinity
    case '-Inf':
      return -Infinity
  }
  if (!/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return null
  return Number(s)
}

/** The value of an unlabelled series, or null when it is not there. */
export function single(series: Series, name: string): number | null {
  const v = series.get(name)?.[0]?.value
  return v === undefined || Number.isNaN(v) ? null : v
}

/** One value per value of `label`, for a labelled family; empty when it is not there. */
export function byLabel(series: Series, name: string, label: string): Map<string, number> {
  const out = new Map<string, number>()
  for (const s of series.get(name) ?? []) {
    const key = s.labels[label]
    if (key !== undefined && !Number.isNaN(s.value)) out.set(key, s.value)
  }
  return out
}
