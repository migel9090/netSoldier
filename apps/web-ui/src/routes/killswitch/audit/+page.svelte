<script lang="ts">
  import { page } from '$app/state'
  import { onMount, untrack } from 'svelte'
  import { fetchAudit, fetchDevices, formatActionType, formatTime, isActionId } from '$lib/api'
  import KillswitchNav from '$lib/components/KillswitchNav.svelte'
  import {
    describeActor,
    describeBlock,
    describeTransition,
    deviceOf,
    isSystemActor,
  } from '$lib/killswitch'
  import type { AuditEntry } from '$lib/types'

  const PAGE = 50

  let entries: AuditEntry[] = $state([])
  /** The `before` cursor of every page above the one shown; empty on the newest. */
  let cursors: number[] = $state([])
  let before: number | undefined = $state(undefined)
  let loading = $state(true)
  let error = $state('')
  let names: Map<string, string> = $state(new Map())

  let actionFilter = $derived.by(() => {
    const id = page.url.searchParams.get('action') ?? ''
    return isActionId(id) ? id : ''
  })
  // A full page may have older entries behind it.
  let hasOlder = $derived(entries.length === PAGE)

  async function load() {
    loading = true
    try {
      entries = await fetchAudit({ limit: PAGE, before, actionId: actionFilter || undefined })
      error = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load the audit log'
    } finally {
      loading = false
    }
  }

  async function older() {
    const last = entries.at(-1)
    if (!last) return
    cursors = [...cursors, before ?? 0]
    before = last.seq
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

  // Reload from the newest entry whenever the action filter changes,
  // including when it arrives by client-side navigation.
  let shownFilter: string | null = null
  $effect(() => {
    const f = actionFilter
    untrack(() => {
      if (f === shownFilter) return
      shownFilter = f
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

{#if loading && entries.length === 0}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if entries.length === 0}
  <p class="empty">{cursors.length > 0 ? 'No older entries.' : 'The audit log is empty.'}</p>
{:else}
  <table data-testid="audit-table">
    <thead>
      <tr>
        <th>When</th>
        <th>Who</th>
        <th>What</th>
        <th>Device</th>
        <th>Action</th>
        <th>Policy rule</th>
        <th>Detection</th>
        <th>Reason</th>
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
  td a {
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
  .paging {
    margin-top: 1rem;
    display: flex;
    gap: 0.5rem;
  }
  .paging button {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
    font-size: 0.8125rem;
  }
  .paging button:disabled {
    opacity: 0.5;
    cursor: wait;
  }
</style>
