<script lang="ts">
  import { onMount } from 'svelte'
  import {
    fetchPendingActions,
    fetchActiveActions,
    fetchFailedActions,
    fetchActionHistory,
    fetchAction,
    fetchDevices,
    approveAction,
    rejectAction,
    revertAction,
    formatTime,
    formatActionType,
    type ActionResult,
  } from '$lib/api'
  import {
    approveConfirmText,
    describeBlock,
    describeDevice,
    describeOutcome,
    deviceOf,
    endedAt,
    enforcedSince,
    failureKind,
    isFailure,
    isStillEnforced,
    revertLeftEnforced,
    type Outcome,
    type Verb,
  } from '$lib/killswitch'
  import { mergeById, newestFirst, oldestFirst } from '$lib/order'
  import type { EnforcementAction } from '$lib/types'

  /** A contract v2 list an older controller may not serve (it answers 404). */
  type OptionalList =
    | { kind: 'ok'; items: EnforcementAction[] }
    | { kind: 'unavailable' }
    | { kind: 'error'; message: string }

  let pendingRaw: EnforcementAction[] = $state([])
  let activeRaw: EnforcementAction[] = $state([])
  let failedList: OptionalList = $state({ kind: 'ok', items: [] })
  let historyList: OptionalList = $state({ kind: 'ok', items: [] })
  let loading: boolean = $state(true)
  let error: string = $state('')
  /** MAC → hostname from the device inventory, for actions without a client_name. */
  let names: Map<string, string> = $state(new Map())
  /** Apply failures reported by approvals made on this page (terminal, never stale). */
  let applyFailures: Map<string, EnforcementAction> = $state(new Map())
  /**
   * Actions whose revert failed. Older controllers drop them from
   * /actions/active although the block is still in place, so they are kept
   * here — re-read on every refresh — until the controller lists them again
   * or reports a state that no longer enforces.
   */
  let revertFailures: Map<string, EnforcementAction> = $state(new Map())
  let outcomes: (Outcome & { key: number; at: Date })[] = $state([])
  let busy: Set<string> = $state(new Set())
  let outcomeSeq = 0

  // Sorted on the client whatever order the controller sends: rows must not
  // swap under the cursor on each refresh.
  let pending = $derived(oldestFirst(pendingRaw))
  let enforced = $derived(
    newestFirst(mergeById(activeRaw, [...revertFailures.values()]), enforcedSince),
  )
  let failures = $derived(
    newestFirst(
      mergeById(
        failedList.kind === 'ok' ? failedList.items : [],
        enforced.filter((a) => failureKind(a) === 'revert'),
        [...applyFailures.values()],
      ).filter(isFailure),
    ),
  )
  let history = $derived(historyList.kind === 'ok' ? newestFirst(historyList.items, endedAt) : [])

  function device(a: EnforcementAction) {
    return deviceOf(a, names)
  }

  function optional(r: PromiseSettledResult<EnforcementAction[] | null>): OptionalList {
    if (r.status === 'rejected') {
      return { kind: 'error', message: r.reason instanceof Error ? r.reason.message : 'failed' }
    }
    return r.value === null ? { kind: 'unavailable' } : { kind: 'ok', items: r.value }
  }

  // A controller without the v2 lists answers 404; ask again every few
  // minutes rather than on every 10 s refresh.
  const RECHECK_UNAVAILABLE_MS = 5 * 60_000
  let failedRecheckAt = 0
  let historyRecheckAt = 0

  // One refresh at a time. A request made while one is in flight (say, right
  // after an approve) queues exactly one more pass, so the tables never show
  // a read that started before the change.
  let inFlight: Promise<void> | null = null
  let again = false

  function load(): Promise<void> {
    if (inFlight) {
      again = true
      return inFlight
    }
    inFlight = (async () => {
      do {
        again = false
        await loadOnce()
      } while (again)
    })().finally(() => {
      inFlight = null
    })
    return inFlight
  }

  async function loadOnce() {
    const now = Date.now()
    const [p, a, f, h] = await Promise.allSettled([
      fetchPendingActions(),
      fetchActiveActions(),
      now < failedRecheckAt ? Promise.resolve(null) : fetchFailedActions(),
      now < historyRecheckAt ? Promise.resolve(null) : fetchActionHistory(),
    ])
    if (p.status === 'rejected' || a.status === 'rejected') {
      // An outage is shown as an error, never as empty tables.
      const reason = p.status === 'rejected' ? p.reason : (a as PromiseRejectedResult).reason
      error = reason instanceof Error ? reason.message : 'Failed to load actions'
    } else {
      pendingRaw = p.value
      activeRaw = a.value
      error = ''
      await reconcileRevertFailures(a.value)
    }
    failedList = optional(f)
    historyList = optional(h)
    if (failedList.kind === 'unavailable' && now >= failedRecheckAt) {
      failedRecheckAt = now + RECHECK_UNAVAILABLE_MS
    }
    if (historyList.kind === 'unavailable' && now >= historyRecheckAt) {
      historyRecheckAt = now + RECHECK_UNAVAILABLE_MS
    }
  }

  async function reconcileRevertFailures(active: EnforcementAction[]) {
    if (revertFailures.size === 0) return
    const listed = new Set(active.map((a) => a.id))
    const next = new Map<string, EnforcementAction>()
    for (const [id, known] of revertFailures) {
      if (listed.has(id)) continue // the controller reports it itself now
      try {
        const current = await fetchAction(id)
        if (current && isStillEnforced(current)) next.set(id, current)
      } catch {
        next.set(id, known) // keep what we know rather than hide a live block
      }
    }
    revertFailures = next
  }

  function record(o: Outcome) {
    outcomes = [{ ...o, key: ++outcomeSeq, at: new Date() }, ...outcomes].slice(0, 8)
  }

  async function act(a: EnforcementAction, verb: Verb, call: () => Promise<ActionResult>) {
    busy = new Set(busy).add(a.id)
    try {
      const result = await call()
      record(describeOutcome(verb, a, device(a), result))
      if (verb === 'approve' && result.action && failureKind(result.action) === 'apply') {
        applyFailures = new Map(applyFailures).set(a.id, result.action)
      }
      if (verb === 'revert' && revertLeftEnforced(result)) {
        const still = result.action ?? {
          ...a,
          state: 'revert_failed',
          failure_reason: result.error || a.failure_reason,
        }
        revertFailures = new Map(revertFailures).set(a.id, still)
      } else if (verb === 'revert' && result.ok && revertFailures.has(a.id)) {
        const next = new Map(revertFailures)
        next.delete(a.id)
        revertFailures = next
      }
    } catch (e) {
      record({
        tone: 'fail',
        state: 'error',
        text: `${verb} ${a.id}: ${e instanceof Error ? e.message : 'request failed'}`,
      })
    } finally {
      const next = new Set(busy)
      next.delete(a.id)
      busy = next
      await load()
    }
  }

  async function handleApprove(a: EnforcementAction) {
    if (!confirm(approveConfirmText(a, device(a)))) return
    await act(a, 'approve', () => approveAction(a.id))
  }

  async function handleReject(a: EnforcementAction) {
    const reason = prompt(
      `Reject the proposed block on ${describeDevice(device(a))}?\n` +
        `It would have blocked ${describeBlock(a)}.\n\nReason for rejection:`,
      'False positive',
    )
    if (reason === null) return
    await act(a, 'reject', () => rejectAction(a.id, reason))
  }

  async function handleRevert(a: EnforcementAction) {
    const reason = prompt(
      `Lift the block on ${describeDevice(device(a))}?\n` +
        `It blocks ${describeBlock(a)}.\n\nReason for revert:`,
      'Manual revert',
    )
    if (reason === null) return
    await act(a, 'revert', () => revertAction(a.id, reason))
  }

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    // Best effort: names make the confirmation readable for actions from
    // controllers that do not carry client_name yet.
    fetchDevices()
      .then((devices) => {
        names = new Map(
          devices.filter((d) => d.hostname).map((d) => [d.mac.toLowerCase(), d.hostname]),
        )
      })
      .catch(() => {})
    const interval = setInterval(load, 10_000)
    return () => clearInterval(interval)
  })
</script>

<h1>Killswitch</h1>

{#if outcomes.length > 0}
  <section class="outcomes" aria-live="polite">
    <h2>What just happened</h2>
    <ul>
      {#each outcomes as o (o.key)}
        <li class="outcome outcome-{o.tone}" data-testid="outcome" data-state={o.state}>
          <span class="outcome-time">{o.at.toLocaleTimeString()}</span>
          {o.text}
        </li>
      {/each}
    </ul>
  </section>
{/if}

{#snippet target(a: EnforcementAction)}
  {@const d = device(a)}
  <td class="target">
    <span class="device-name">{d.name || 'unknown device'}</span>
    <span class="mono">{d.mac || '—'}</span>
    {#if d.ip}<span class="mono">{d.ip}</span>{/if}
  </td>
{/snippet}

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else}
  <section>
    <h2>Pending Approvals ({pending.length})</h2>
    {#if pending.length === 0}
      <p class="empty">No pending actions.</p>
    {:else}
      <table data-testid="pending-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Domain / IoC</th>
            <th>Target</th>
            <th>Action</th>
            <th>TTL</th>
            <th>Reason</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each pending as a (a.id)}
            <tr data-action-id={a.id} data-state={a.state}>
              <td class="mono">{a.id}</td>
              <td>{formatTime(a.timestamp)}</td>
              <td class="mono" title={a.detection_summary}>{a.blocked_domain || a.detection_id}</td>
              {@render target(a)}
              <td><span class="badge badge-medium">{formatActionType(a.action_type)}</span></td>
              <td>{a.ttl_seconds ? `${Math.round(a.ttl_seconds / 60)}m` : '—'}</td>
              <td class="reason">{a.policy_rule}</td>
              <td class="actions-cell">
                <button
                  class="btn-approve"
                  disabled={busy.has(a.id)}
                  onclick={() => handleApprove(a)}>Approve</button
                >
                <button class="btn-reject" disabled={busy.has(a.id)} onclick={() => handleReject(a)}
                  >Reject</button
                >
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  {#if failures.length > 0 || failedList.kind !== 'ok'}
    <section class="failed-section">
      <h2>Enforcement Failures ({failures.length})</h2>
      <p class="warn">
        An <strong>apply</strong> failure means the block was never put in place: the device is
        <strong>not</strong> blocked. A <strong>revert</strong> failure means the block could not be
        lifted: it is <strong>still in force</strong>. Check the driver before relying on either.
      </p>
      {#if failedList.kind === 'unavailable'}
        <p class="muted">
          This killswitch controller does not report past failures yet; only failures from actions
          taken on this page are listed.
        </p>
      {:else if failedList.kind === 'error'}
        <p class="error">{failedList.message}</p>
      {/if}
      {#if failures.length > 0}
        <table data-testid="failures-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Target</th>
              <th>Action</th>
              <th>What failed</th>
              <th>Why it failed</th>
            </tr>
          </thead>
          <tbody>
            {#each failures as a (a.id)}
              <tr data-action-id={a.id} data-state={a.state}>
                <td class="mono">{a.id}</td>
                {@render target(a)}
                <td>{formatActionType(a.action_type)}</td>
                <td>
                  {#if failureKind(a) === 'revert'}
                    <span class="badge badge-high">revert failed — still enforced</span>
                  {:else}
                    <span class="badge badge-medium">apply failed — not enforced</span>
                  {/if}
                </td>
                <td class="reason" title={a.failure_reason}>{a.failure_reason || 'unknown'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}

  <section>
    <h2>Active Blocks ({enforced.length})</h2>
    {#if enforced.length === 0}
      <p class="empty">No active enforcement.</p>
    {:else}
      <table data-testid="active-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Since</th>
            <th>Domain / IoC</th>
            <th>Target</th>
            <th>Action</th>
            <th>Expires</th>
            <th>Approved by</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each enforced as a (a.id)}
            <tr data-action-id={a.id} data-state={a.state}>
              <td class="mono">{a.id}</td>
              <td>{formatTime(enforcedSince(a))}</td>
              <td class="mono" title={a.detection_summary}>{a.blocked_domain || a.detection_id}</td>
              {@render target(a)}
              <td>
                <span class="badge badge-high">{formatActionType(a.action_type)}</span>
                {#if failureKind(a) === 'revert'}
                  <span class="badge badge-high" title={a.failure_reason}
                    >revert failed — still enforced</span
                  >
                {/if}
              </td>
              <td>{a.expires_at ? formatTime(a.expires_at) : 'never'}</td>
              <td>{a.auto_approved ? 'auto-policy' : a.approved_by || '—'}</td>
              <td class="actions-cell">
                <button class="btn-revert" disabled={busy.has(a.id)} onclick={() => handleRevert(a)}
                  >Revert</button
                >
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section>
    <h2>History ({history.length})</h2>
    {#if historyList.kind === 'unavailable'}
      <p class="muted">History is not available from this killswitch controller yet.</p>
    {:else if historyList.kind === 'error'}
      <p class="error">{historyList.message}</p>
    {:else if history.length === 0}
      <p class="empty">No finished actions yet.</p>
    {:else}
      <table data-testid="history-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Ended</th>
            <th>Domain / IoC</th>
            <th>Target</th>
            <th>Action</th>
            <th>Outcome</th>
            <th>By</th>
          </tr>
        </thead>
        <tbody>
          {#each history as a (a.id)}
            <tr data-action-id={a.id} data-state={a.state}>
              <td class="mono">{a.id}</td>
              <td>{formatTime(endedAt(a))}</td>
              <td class="mono" title={a.detection_summary}>{a.blocked_domain || a.detection_id}</td>
              {@render target(a)}
              <td>{formatActionType(a.action_type)}</td>
              <td title={a.failure_reason || a.reason}>{a.state.replace('_', ' ')}</td>
              <td>{a.reverted_by || a.rejected_by || a.approved_by || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}

<style>
  .failed-section {
    border-left: 3px solid #c0392b;
    padding-left: 1rem;
  }
  .warn {
    color: #c0392b;
    max-width: 48rem;
  }
  section {
    margin-bottom: 2rem;
  }
  h2 {
    font-size: 1.1rem;
    margin-bottom: 0.5rem;
  }
  .outcomes ul {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .outcome {
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    border-left: 3px solid var(--border);
    background: var(--bg-secondary);
    font-size: 0.875rem;
  }
  .outcome-ok {
    border-left-color: var(--success);
  }
  .outcome-warn {
    border-left-color: var(--warning);
  }
  .outcome-fail {
    border-left-color: var(--danger);
    color: var(--danger);
  }
  .outcome-time {
    color: var(--text-secondary);
    margin-right: 0.5rem;
    font-size: 0.75rem;
  }
  .target span {
    display: block;
  }
  .device-name {
    font-weight: 600;
  }
  .actions-cell {
    white-space: nowrap;
  }
  .reason {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  button {
    padding: 0.25rem 0.75rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 600;
  }
  button:disabled {
    opacity: 0.5;
    cursor: wait;
  }
  .btn-approve {
    background: var(--color-success, #238636);
    color: #fff;
  }
  .btn-approve:hover {
    filter: brightness(1.2);
  }
  .btn-reject {
    background: var(--color-danger, #da3633);
    color: #fff;
    margin-left: 0.25rem;
  }
  .btn-reject:hover {
    filter: brightness(1.2);
  }
  .btn-revert {
    background: var(--color-warning, #d29922);
    color: #fff;
  }
  .btn-revert:hover {
    filter: brightness(1.2);
  }
</style>
