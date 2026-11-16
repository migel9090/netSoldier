<script lang="ts">
  import { onMount } from 'svelte'
  import {
    HISTORY_MAX_LIMIT,
    fetchActionHistory,
    fetchDevices,
    formatActionType,
    formatTime,
  } from '$lib/api'
  import KillswitchNav from '$lib/components/KillswitchNav.svelte'
  import { describeActor, describeBlock, deviceOf, endedBy, stateWords } from '$lib/killswitch'
  import type { EnforcementAction } from '$lib/types'

  const PAGE = 50

  let actions: EnforcementAction[] = $state([])
  let limit = $state(PAGE)
  let loading = $state(true)
  let error = $state('')
  let names: Map<string, string> = $state(new Map())

  // The controller pages history only by ?limit= (at most 500, most
  // recently finished first), so "more" asks for a longer list.
  let more = $derived(actions.length >= limit && limit < HISTORY_MAX_LIMIT)
  let capped = $derived(actions.length >= HISTORY_MAX_LIMIT)

  async function load() {
    try {
      // Kept in the controller's order: most recently finished first. The
      // actions carry no time for a rejection, expiry or failed apply, so
      // the client could not re-sort them correctly.
      actions = await fetchActionHistory(limit)
      error = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load history'
    }
  }

  async function showMore() {
    limit = Math.min(HISTORY_MAX_LIMIT, limit + PAGE)
    await load()
  }

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    fetchDevices()
      .then(({ devices }) => {
        names = new Map(
          devices.filter((d) => d.hostname).map((d) => [d.mac.toLowerCase(), d.hostname]),
        )
      })
      .catch(() => {})
  })
</script>

<h1>Killswitch History</h1>
<KillswitchNav />

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if actions.length === 0}
  <p class="empty">No finished actions yet.</p>
{:else}
  <p class="muted">
    Finished actions, most recently finished first: lifted, rejected, expired before anyone approved
    them, or never applied. Who did what and when is in the
    <a href="/killswitch/audit">audit log</a>.
  </p>
  <table data-testid="history-table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Proposed</th>
        <th>Device</th>
        <th>Action</th>
        <th>Outcome</th>
        <th>Approved by</th>
        <th>Ended by</th>
        <th>Policy rule</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each actions as a (a.id)}
        {@const d = deviceOf(a, names)}
        <tr data-action-id={a.id} data-state={a.state}>
          <td class="mono">{a.id}</td>
          <td class="nowrap">{formatTime(a.timestamp)}</td>
          <td class="target">
            <span class="device-name">{d.name || 'unknown device'}</span>
            <span class="mono">{d.mac || '—'}</span>
            {#if d.ip}<span class="mono">{d.ip}</span>{/if}
          </td>
          <td>
            {formatActionType(a.action_type)}
            <span class="secondary" title={a.detection_summary}>{describeBlock(a)}</span>
          </td>
          <td>
            <span data-testid="outcome-state">{stateWords(a)}</span>
            {#if a.reverted_at}<span class="secondary">{formatTime(a.reverted_at)}</span>{/if}
            {#if a.failure_reason || a.reason}
              <span class="secondary reason" title={a.failure_reason || a.reason}
                >{a.failure_reason || a.reason}</span
              >
            {/if}
          </td>
          <td>{a.approved_by ? describeActor(a.approved_by) : '—'}</td>
          <td data-testid="ended-by">{endedBy(a)}</td>
          <td class="reason" title={a.policy_rule}>{a.policy_rule || '—'}</td>
          <td><a href="/killswitch/audit?action={encodeURIComponent(a.id)}">audit trail</a></td>
        </tr>
      {/each}
    </tbody>
  </table>
  <p class="paging">
    {#if more}
      <button class="more" onclick={showMore}>Show {PAGE} more</button>
    {:else if capped}
      <span class="muted"
        >The controller lists at most the {HISTORY_MAX_LIMIT} most recently finished actions; older ones
        are in the audit log.</span
      >
    {/if}
  </p>
{/if}

<style>
  .target span {
    display: block;
  }
  .device-name {
    font-weight: 600;
  }
  .nowrap {
    white-space: nowrap;
  }
  .reason {
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .muted {
    margin-bottom: 1rem;
  }
  .muted a,
  td a {
    color: var(--accent);
    text-decoration: none;
  }
  .paging {
    margin-top: 1rem;
  }
  .more {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
    font-size: 0.8125rem;
  }
</style>
