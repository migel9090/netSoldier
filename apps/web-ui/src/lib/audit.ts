import type { AuditEntry } from './types'

/**
 * Searching the killswitch's audit log by who and what.
 *
 * GET /audit pages back by sequence number (?before=) and narrows to one
 * action (?action_id=), but filters by nothing else. A search by actor or by
 * transition therefore reads the log newest first, in batches, and keeps
 * what matches — bounded, so one search never reads the whole log; the page
 * says how far back it looked and lets the operator go on.
 */

export interface AuditFilter {
  /** Exact actor name, compared case-insensitively; '' for anyone. */
  actor: string
  /** The state the entry moved the action to (`to_state`); '' for any. */
  what: string
}

/** What each `to_state` is called in the filter, in lifecycle order. */
export const AUDIT_WHAT: readonly { value: string; label: string }[] = [
  { value: 'pending', label: 'proposed' },
  { value: 'approved', label: 'approved' },
  { value: 'active', label: 'enforced' },
  { value: 'rejected', label: 'rejected' },
  { value: 'expired', label: 'expired unapproved' },
  { value: 'reverted', label: 'reverted (lifted)' },
  { value: 'apply_failed', label: 'apply failed' },
  { value: 'revert_failed', label: 'revert failed' },
]

const KNOWN_WHAT = new Set(AUDIT_WHAT.map((w) => w.value))

/** The filter from a URL's ?actor= and ?what=; anything unknown in `what` is dropped. */
export function auditFilterFrom(params: Pick<URLSearchParams, 'get'>): AuditFilter {
  const actor = (params.get('actor') ?? '').trim().slice(0, 64)
  const what = params.get('what') ?? ''
  return { actor, what: KNOWN_WHAT.has(what) ? what : '' }
}

export function isFiltered(f: AuditFilter): boolean {
  return f.actor !== '' || f.what !== ''
}

export function auditMatches(e: AuditEntry, f: AuditFilter): boolean {
  if (f.actor && e.actor.toLowerCase() !== f.actor.toLowerCase()) return false
  if (f.what && e.to_state !== f.what) return false
  return true
}

/** Reads one batch: entries older than `before` (all when undefined), newest first. */
export type AuditPageReader = (before: number | undefined, limit: number) => Promise<AuditEntry[]>

export interface AuditScan {
  /** The matching entries, newest first, at most `want`. */
  entries: AuditEntry[]
  /**
   * Where the next page starts (?before=), or undefined when the log has
   * been read to its first entry.
   */
  next: number | undefined
  /** How many entries were read to find these. */
  scanned: number
  /** The time of the oldest entry read; null when none was. */
  oldestScanned: string | null
  /** The batch limit ran out before `want` matches were found (more may be older). */
  stopped: boolean
}

export const AUDIT_BATCH = 500
export const AUDIT_MAX_BATCHES = 10

/**
 * One page of the (filtered) log, starting before `before`. Without a
 * filter this is one request of `want` entries, as the log pages anyway.
 */
export async function scanAudit(
  read: AuditPageReader,
  filter: AuditFilter,
  before: number | undefined,
  want: number,
  { batch = AUDIT_BATCH, maxBatches = AUDIT_MAX_BATCHES } = {},
): Promise<AuditScan> {
  if (!isFiltered(filter)) {
    const entries = await read(before, want)
    return {
      entries,
      next: entries.length === want ? entries.at(-1)!.seq : undefined,
      scanned: entries.length,
      oldestScanned: entries.at(-1)?.timestamp ?? null,
      stopped: false,
    }
  }
  const found: AuditEntry[] = []
  let cursor = before
  let scanned = 0
  let oldest: string | null = null
  for (let i = 0; i < maxBatches; i++) {
    const page = await read(cursor, batch)
    for (const e of page) {
      scanned++
      oldest = e.timestamp
      if (!auditMatches(e, filter)) continue
      found.push(e)
      if (found.length === want) {
        // The next page goes on from just below this entry; the rest of
        // this batch is read again then.
        return { entries: found, next: e.seq, scanned, oldestScanned: oldest, stopped: false }
      }
    }
    if (page.length < batch) {
      return { entries: found, next: undefined, scanned, oldestScanned: oldest, stopped: false }
    }
    cursor = page.at(-1)!.seq
  }
  return { entries: found, next: cursor, scanned, oldestScanned: oldest, stopped: true }
}

/** Actor names in `entries`, for the filter's suggestions; sorted, case-folded duplicates dropped. */
export function actorsIn(entries: readonly AuditEntry[]): string[] {
  const seen = new Map<string, string>()
  for (const e of entries) {
    if (e.actor && !seen.has(e.actor.toLowerCase())) seen.set(e.actor.toLowerCase(), e.actor)
  }
  return [...seen.values()].sort((a, b) => a.localeCompare(b))
}
