<script lang="ts">
  import { page } from '$app/state'
  import { onMount, untrack } from 'svelte'
  import { fetchAudit, fetchDevices, formatActionType, formatTime, isActionId } from '#lib/api.ts'
  import {
    AUDIT_WHAT,
    actorsIn,
    auditFilterFrom,
    isFiltered,
    scanAudit,
    type AuditScan,
  } from '#lib/audit.ts'
  import KillswitchNav from '#lib/components/KillswitchNav.svelte'
  import {
    describeActor,
    describeBlock,
    describeTransition,
    deviceOf,
    isSystemActor,
  } from '#lib/killswitch.ts'
  import type { AuditEntry } from '#lib/types.ts'

  const PAGE = 50
  /** The controller's own actors, always offered as suggestions. */
  const SYSTEM_ACTORS = ['auto-policy', 'ttl', 'reconcile', 'netagent', 'system']

  let entries: AuditEntry[] = $state([])
  /** The `before` cursor of every page above the one shown; empty on the newest. */
  let cursors: number[] = $state([])
  let before: number | undefined = $state(undefined)
  let scan = $state<AuditScan | null>(null)
  let loading = $state(true)
  let error = $state('')
  let names: Map<string, string> = $state(new Map())
  /** Every actor seen on a page so far, for the filter's suggestions. */
  let seenActors: string[] = $state([])

  let actionFilter = $derived.by(() => {
    const id = page.url.searchParams.get('action') ?? ''
    return isActionId(id) ? id : ''
  })
  let filter = $derived(auditFilterFrom(page.url.searchParams))
  let filtered = $derived(isFiltered(filter))
  let hasOlder = $derived(scan?.next !== undefined)
  let suggestions = $derived(
    [...new Set([...seenActors, ...SYSTEM_ACTORS])].sort((a, b) => a.localeCompare(b)),
  )

  async function load() {
    loading = true
    try {
      // Only ?action_id= narrows the log on the controller; actor and
      // transition are matched here, over a bounded number of batches.
      const result = await scanAudit(
        (b, limit) => fetchAudit({ limit, before: b, actionId: actionFilter || undefined }),
        filter,
        before,
        PAGE,
      )
      scan = result
      entries = result.entries
      seenActors = [...new Set([...seenActors, ...actorsIn(result.entries)])]
      error = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load the audit log'
    } finally {
      loading = false
    }
  }

  async function older() {
    if (scan?.next === undefined) return
    cursors = [...cursors, before ?? 0]
    before = scan.next
    await load()
  }

  async function newer() {
    const prev = cursors.at(-1)
    cursors = cursors.slice(0, -1)
    before = prev ? prev : undefined
    await load()
  }

  async function newest() {
    cursors = []
    before = undefined
    await load()
  }

  // Reload from the newest entry whenever a filter changes, including when
  // it arrives by client-side navigation.
  let shownFilter: string | null = null
  $effect(() => {
    const key = `${actionFilter}|${filter.actor}|${filter.what}`
    untrack(() => {
      if (key === shownFilter) return
      shownFilter = key
      cursors = []
      before = undefined
      void load()
    })
  })

  onMount(() => {
    fetchDevices()
      .then(({ devices }) => {
        names = new Map(
          devices.filter((d) => d.hostname).map((d) => [d.mac.toLowerCase(), d.hostname]),
        )
      })
      .catch(() => {})
  })
</script>

<h1>Killswitch Audit Log</h1>
<KillswitchNav />

<p class="muted">
  Every change of every action, newest first: who caused it, when, to which device, and under which
  policy rule. Names in <em>italics</em> are the killswitch's own automatic steps.
  {#if actionFilter}
    Showing action <span class="mono">{actionFilter}</span> only —
    <a href="/killswitch/audit">show all</a>.
  {/if}
</p>

<form class="filter" method="GET" action="/killswitch/audit" data-testid="audit-filter">
  {#if actionFilter}<input type="hidden" name="action" value={actionFilter} />{/if}
  <label for="audit-actor">Who</label>
  <input
    id="audit-actor"
    name="actor"
    list="audit-actors"
    value={filter.actor}
    placeholder="anyone"
    autocomplete="off"
    maxlength="64"
  />
  <datalist id="audit-actors">
    {#each suggestions as a (a)}
      <option value={a}>{describeActor(a)}</option>
    {/each}
  </datalist>
  <label for="audit-what">What</label>
  <select id="audit-what" name="what" value={filter.what}>
    <option value="">anything</option>
    {#each AUDIT_WHAT as w (w.value)}
      <option value={w.value}>{w.label}</option>
    {/each}
  </select>
  <button type="submit">Search</button>
  {#if filtered}
    <a
      href={actionFilter
        ? `/killswitch/audit?action=${encodeURIComponent(actionFilter)}`
        : '/killswitch/audit'}>clear</a
    >
  {/if}
</form>

{#if filtered && scan && !error}
  <p class="muted scope" data-testid="audit-scope">
    {scan.entries.length} matching {scan.entries.length === 1 ? 'entry' : 'entries'} among the {scan.scanned}
    read{scan.oldestScanned ? `, back to ${formatTime(scan.oldestScanned)}` : ''}.
    {#if scan.stopped}
      The search stopped there; “Older” goes on from there.
    {:else if scan.next === undefined}
      That is the start of the log.
    {/if}
  </p>
{/if}

{#if loading && entries.length === 0}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if entries.length === 0}
  <p class="empty">
    {filtered
      ? 'No entry matches.'
      : cursors.length > 0
        ? 'No older entries.'
        : 'The audit log is empty.'}
  </p>
{:else}
  <table data-testid="audit-table">
    <thead>
      <tr>
        <th scope="col">When</th>
        <th scope="col">Who</th>
        <th scope="col">What</th>
        <th scope="col">Device</th>
        <th scope="col">Action</th>
        <th scope="col">Policy rule</th>
        <th scope="col">Detection</th>
        <th scope="col">Reason</th>
      </tr>
    </thead>
    <tbody>
      {#each entries as e (e.seq)}
        {@const d = deviceOf(e, names)}
        <tr data-seq={e.seq} data-action-id={e.action_id} data-to-state={e.to_state}>
          <td class="nowrap">{formatTime(e.timestamp)}</td>
          <td data-testid="audit-actor" class:system={isSystemActor(e.actor)}
            >{describeActor(e.actor)}</td
          >
          <td data-testid="audit-what">{describeTransition(e)}</td>
          <td class="target">
            <span class="device-name">{d.name || 'unknown device'}</span>
            <span class="mono">{d.mac || '—'}</span>
            {#if d.ip}<span class="mono">{d.ip}</span>{/if}
          </td>
          <td>
            <a class="mono" href="/killswitch/audit?action={encodeURIComponent(e.action_id)}"
              >{e.action_id}</a
            >
            <span class="secondary">{formatActionType(e.action_type)}: {describeBlock(e)}</span>
            <a class="secondary" href="/killswitch/actions/{encodeURIComponent(e.action_id)}"
              >details</a
            >
          </td>
          <td class="clip" title={e.policy_rule}>{e.policy_rule || '—'}</td>
          <td class="clip" title={e.detection_summary}>{e.detection_summary || '—'}</td>
          <td class="clip" title={e.reason}>{e.reason || '—'}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

{#if !error && (cursors.length > 0 || hasOlder)}
  <p class="paging">
    {#if cursors.length > 0}
      <button onclick={newest} disabled={loading}>Newest</button>
      <button onclick={newer} disabled={loading}>Newer</button>
    {/if}
    {#if hasOlder}
      <button onclick={older} disabled={loading}>Older</button>
    {/if}
  </p>
{/if}

<style>
  .muted {
    margin-bottom: 1rem;
  }
  .muted a,
  td a,
  .filter a {
    color: var(--accent);
    text-decoration: none;
  }
  .target span,
  td a {
    display: block;
  }
  .device-name {
    font-weight: 600;
  }
  .nowrap {
    white-space: nowrap;
  }
  .system {
    font-style: italic;
    color: var(--text-secondary);
  }
  .clip {
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .filter {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
  }
  .filter input,
  .filter select,
  .filter button,
  .paging button {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 0.6rem;
    font-size: 0.8125rem;
    font-family: inherit;
  }
  .filter button,
  .paging button {
    cursor: pointer;
  }
  .scope {
    margin-top: -0.5rem;
  }
  .paging {
    margin-top: 1rem;
    display: flex;
    gap: 0.5rem;
  }
  .paging button:disabled {
    opacity: 0.5;
    cursor: wait;
  }
</style>
