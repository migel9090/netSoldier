/**
 * Deterministic ordering for lists that are re-fetched on a timer.
 *
 * The killswitch controller returns actions in Go map order, which differs on
 * every call; re-rendering in arrival order made rows swap under the cursor
 * every 10 s, next to an Approve button. Every list is therefore sorted on
 * the client by a timestamp with the id as tie-break, whatever order the
 * backend promises.
 */

function millis(value: string | null | undefined): number {
  if (!value) return 0
  const t = Date.parse(value)
  return Number.isNaN(t) ? 0 : t
}

function byId(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

type TimeOf<T> = (item: T) => string | null | undefined

export function oldestFirst<T extends { id: string }>(
  items: readonly T[],
  timeOf: TimeOf<T> = (i) => (i as { timestamp?: string }).timestamp,
): T[] {
  return [...items].sort((a, b) => millis(timeOf(a)) - millis(timeOf(b)) || byId(a.id, b.id))
}

export function newestFirst<T extends { id: string }>(
  items: readonly T[],
  timeOf: TimeOf<T> = (i) => (i as { timestamp?: string }).timestamp,
): T[] {
  return [...items].sort((a, b) => millis(timeOf(b)) - millis(timeOf(a)) || byId(a.id, b.id))
}

/** Concatenates lists keeping the first occurrence of each id. */
export function mergeById<T extends { id: string }>(...lists: readonly (readonly T[])[]): T[] {
  const seen = new Set<string>()
  const out: T[] = []
  for (const list of lists) {
    for (const item of list) {
      if (seen.has(item.id)) continue
      seen.add(item.id)
      out.push(item)
    }
  }
  return out
}
