<script lang="ts">
  import { onMount, untrack } from 'svelte'
  import { page } from '$app/state'
  import {
    HISTORY_MAX_LIMIT,
    fetchActionHistory,
    fetchDevices,
    formatActionType,
    formatTime,
  } from '#lib/api.ts'
  import KillswitchNav from '#lib/components/KillswitchNav.svelte'
  import {
    HISTORY_OUTCOMES,
    approverWords,
    describeBlock,
    deviceOf,
    endedBy,
    historyOutcomeFrom,
    pageOf,
    stateWords,
  } from '#lib/killswitch.ts'
  import type { EnforcementAction } from '#lib/types.ts'

  const PAGE = 50

  let actions: EnforcementAction[] = $state([])
  /** How many the controller was asked for; it returns at most this many. */
  let limit = $state(PAGE)
  let pageNo = $state(0)
  let loading = $state(true)
  let busy = $state(false)
  let error = $state('')
  let names: Map<string, string> = $state(new Map())

  let outcome = $derived(historyOutcomeFrom(page.url.searchParams))
  let matching = $derived(outcome ? actions.filter((a) => a.state === outcome) : actions)
  let shown = $derived(pageOf(matching, pageNo, PAGE))
  // The controller pages history only by ?limit= (at most 500, most
  // recently finished first): a full answer may have more behind it.
  let truncated = $derived(actions.length >= limit)
  let canAskMore = $derived(truncated && limit < HISTORY_MAX_LIMIT)
  let hasOlder = $derived(matching.length > (shown.page + 1) * PAGE || canAskMore)
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

  async function older() {
    const next = shown.page + 1
    if (matching.length <= next * PAGE && canAskMore) {
      busy = true
      // With an outcome chosen, everything the controller keeps is read
      // at once (see the effect below); without, fifty more each time.
      limit = outcome ? HISTORY_MAX_LIMIT : Math.min(HISTORY_MAX_LIMIT, (next + 1) * PAGE)
      await load()
      busy = false
    }
    if (matching.length > next * PAGE) pageNo = next
  }

  function newer() {
    pageNo = Math.max(0, shown.page - 1)
  }

  // An outcome filter needs every finished action the controller keeps:
  // the matches can be anywhere in its list. Back to the first page on
  // every change.
  let shownOutcome: string | null = null
  $effect(() => {
    const o = outcome
    untrack(() => {
      if (o === shownOutcome) return
      const first = shownOutcome === null
      shownOutcome = o
      pageNo = 0
      if (o && limit < HISTORY_MAX_LIMIT) limit = HISTORY_MAX_LIMIT
      else if (!first) return
      busy = true
      void load().finally(() => {
        busy = false
        loading = false
      })
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

<h1>Killswitch History</h1>
<KillswitchNav />

<form class="filter" method="GET" action="/killswitch/history" data-testid="history-filter">
  <label for="outcome">Outcome</label>
  <select id="outcome" name="outcome" value={outcome}>
    {#each HISTORY_OUTCOMES as o (o.value)}
      <option value={o.value}>{o.label}</option>
    {/each}
  </select>
  <button type="submit">Show</button>
</form>

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if matching.length === 0}
  <p class="empty">
    {actions.length === 0 ? 'No finished actions yet.' : 'No finished action has this outcome.'}
  </p>
{:else}
  <p class="muted">
    Finished actions, most recently finished first: lifted, rejected, expired before anyone approved
    them, or never applied. A block still in force after a failed revert is on the
    <a href="/killswitch">approvals page</a>. Who did what and when is in the
    <a href="/killswitch/audit">audit log</a>.
  </p>
  <table data-testid="history-table">
    <thead>
      <tr>
        <th scope="col">ID</th>
        <th scope="col">Proposed</th>
        <th scope="col">Device</th>
        <th scope="col">Action</th>
        <th scope="col">Outcome</th>
        <th scope="col">Approved by</th>
        <th scope="col">Ended by</th>
        <th scope="col">Policy rule</th>
        <th scope="col"><span class="visually-hidden">Audit trail</span></th>
      </tr>
    </thead>
    <tbody>
      {#each shown.items as a (a.id)}
        {@const d = deviceOf(a, names)}
        <tr data-action-id={a.id} data-state={a.state}>
          <td class="mono"><a href="/killswitch/actions/{encodeURIComponent(a.id)}">{a.id}</a></td>
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
          <td>{approverWords(a)}</td>
          <td data-testid="ended-by">{endedBy(a)}</td>
          <td class="reason" title={a.policy_rule}>{a.policy_rule || '—'}</td>
          <td><a href="/killswitch/audit?action={encodeURIComponent(a.id)}">audit trail</a></td>
        </tr>
      {/each}
    </tbody>
  </table>
  <p class="paging" data-testid="history-paging">
    <span class="muted" data-testid="history-range"
      >{shown.page * PAGE + 1}–{shown.page * PAGE + shown.items.length} of {matching.length}{truncated &&
      !capped
        ? '+'
        : ''}</span
    >
    {#if shown.page > 0}
      <button onclick={newer} disabled={busy}>Newer</button>
    {/if}
    {#if hasOlder}
      <button onclick={older} disabled={busy}>Older</button>
    {/if}
    {#if capped && !hasOlder}
      <span class="muted"
        >The controller lists at most the {HISTORY_MAX_LIMIT} most recently finished actions; older ones
        are in the audit log.</span
      >
    {/if}
  </p>
{/if}

<style>
  .filter {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 1rem;
    font-size: 0.875rem;
  }
  .filter select,
  .filter button,
  .paging button {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 0.6rem;
    font-size: 0.8125rem;
    cursor: pointer;
  }
  .paging button:disabled {
    opacity: 0.5;
    cursor: wait;
  }
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
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  .paging .muted {
    margin-bottom: 0;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
