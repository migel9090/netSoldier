<script lang="ts">
  import { onMount, tick } from 'svelte'
  import {
    fetchPendingActions,
    fetchActiveActions,
    fetchFailedActions,
    fetchAction,
    fetchAudit,
    fetchDevices,
    fetchPolicy,
    approveAction,
    rejectAction,
    revertAction,
    formatTime,
    formatActionType,
    type ActionResult,
  } from '$lib/api'
  import KillswitchNav from '$lib/components/KillswitchNav.svelte'
  import {
    actionTypeChoices,
    approveQuestion,
    awaitingConfirmation,
    defaultChoice,
    describeActor,
    describeBlock,
    describeDevice,
    describeOutcome,
    describeSettled,
    deviceOf,
    enforcedSince,
    failureKind,
    hasSettled,
    type ActionTypeChoice,
    type Outcome,
    type Verb,
  } from '$lib/killswitch'
  import { newestFirst, oldestFirst } from '$lib/order'
  import type { EnforcementAction, KillswitchPolicy } from '$lib/types'

  let pendingRaw: EnforcementAction[] = $state([])
  let activeRaw: EnforcementAction[] = $state([])
  let failedRaw: EnforcementAction[] = $state([])
  let failedError: string = $state('')
  let loading: boolean = $state(true)
  let error: string = $state('')
  /** MAC → hostname from the device inventory, for actions without a client_name. */
  let names: Map<string, string> = $state(new Map())
  let policy: KillswitchPolicy | null = $state(null)
  let policyError: string = $state('')
  let outcomes: (Outcome & { key: number; at: Date })[] = $state([])
  let busy: Set<string> = $state(new Set())
  let outcomeSeq = 0

  /**
   * Operations the controller answered with 202, and approvals found in the
   * audit log that have no outcome yet. An `approved` action is in no list
   * (GET /actions/active leaves it out), so it is read by id until it
   * settles. `ours`: started on this page, so its outcome is reported.
   */
  interface Tracked {
    verb: Verb
    action: EnforcementAction
    since: Date
    ours: boolean
  }
  let tracking: Map<string, Tracked> = $state(new Map())

  // Sorted on the client whatever order the controller sends: rows must not
  // swap under the cursor on each refresh.
  let pending = $derived(oldestFirst(pendingRaw))
  let enforced = $derived(newestFirst(activeRaw, enforcedSince))
  let failures = $derived(newestFirst(failedRaw))
  let inProgress = $derived(
    [...tracking.values()].sort((a, b) => a.since.getTime() - b.since.getTime()),
  )

  function device(a: EnforcementAction) {
    return deviceOf(a, names)
  }

  function message(e: unknown, fallback: string): string {
    return e instanceof Error ? e.message : fallback
  }

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
    const [p, a, f, audit] = await Promise.allSettled([
      fetchPendingActions(),
      fetchActiveActions(),
      fetchFailedActions(),
      fetchAudit({ limit: 100 }),
    ])
    if (p.status === 'rejected' || a.status === 'rejected') {
      // An outage is shown as an error, never as empty tables.
      const reason = p.status === 'rejected' ? p.reason : (a as PromiseRejectedResult).reason
      error = message(reason, 'Failed to load actions')
    } else {
      pendingRaw = p.value
      activeRaw = a.value
      error = ''
    }
    if (f.status === 'fulfilled') {
      failedRaw = f.value
      failedError = ''
    } else {
      failedError = message(f.reason, 'Failed to load failures')
    }
    if (audit.status === 'fulfilled') {
      const found = awaitingConfirmation(audit.value).filter((id) => !tracking.has(id))
      if (found.length > 0) {
        const next = new Map(tracking)
        for (const id of found) {
          next.set(id, { verb: 'approve', action: placeholder(id), since: new Date(), ours: false })
        }
        tracking = next
        await pollTracked()
      }
    }
  }

  function placeholder(id: string): EnforcementAction {
    return {
      id,
      timestamp: '',
      detection_id: '',
      action_type: '',
      state: 'approved',
      target_mac: '',
      policy_rule: '',
      auto_approved: false,
    }
  }

  let polling = false

  /** Reads every tracked action by id; reports and drops those that settled. */
  async function pollTracked() {
    if (polling || tracking.size === 0) return
    polling = true
    let settled = false
    try {
      // What each entry polled became: null when it is done. Applied to the
      // map as it is afterwards, and only to entries nobody replaced in the
      // meantime (an operation started while this ran is kept).
      const updates = new Map<Tracked, Tracked | null>()
      for (const [id, t] of tracking) {
        let current: EnforcementAction | null
        try {
          current = await fetchAction(id)
        } catch {
          continue // keep it; try again on the next tick
        }
        if (!current) {
          updates.set(t, null)
        } else if (hasSettled(t.verb, current)) {
          updates.set(t, null)
          settled = true
          if (t.ours) record(describeSettled(t.verb, current, device(current)))
        } else {
          updates.set(t, { ...t, action: current })
        }
      }
      const next = new Map(tracking)
      for (const [id, t] of tracking) {
        if (!updates.has(t)) continue
        const u = updates.get(t)
        if (u) next.set(id, u)
        else next.delete(id)
      }
      tracking = next
    } finally {
      polling = false
    }
    if (settled) await load()
  }

  function record(o: Outcome) {
    outcomes = [{ ...o, key: ++outcomeSeq, at: new Date() }, ...outcomes].slice(0, 8)
  }

  async function act(a: EnforcementAction, verb: Verb, call: () => Promise<ActionResult>) {
    busy = new Set(busy).add(a.id)
    try {
      const result = await call()
      const outcome = describeOutcome(verb, a, device(a), result)
      record(outcome)
      if (outcome.settling && result.action) {
        tracking = new Map(tracking).set(a.id, {
          verb,
          action: result.action,
          since: new Date(),
          ours: true,
        })
      }
      if (result.status === 422) void refreshPolicy()
    } catch (e) {
      record({
        tone: 'fail',
        state: 'error',
        text: `${verb} ${a.id}: ${message(e, 'request failed')}`,
        settling: false,
      })
    } finally {
      const next = new Set(busy)
      next.delete(a.id)
      busy = next
      await load()
    }
  }

  async function refreshPolicy() {
    try {
      policy = await fetchPolicy()
      policyError = ''
    } catch (e) {
      policyError = message(e, 'could not read the killswitch policy')
    }
  }

  // ── Approval dialog ────────────────────────────────────────────────

  interface Approving {
    action: EnforcementAction
    choices: ActionTypeChoice[]
    selected: string
    defaultType: string
  }
  let approving: Approving | null = $state(null)
  let dialog: HTMLDialogElement | undefined = $state()
  let chosen = $derived.by(() => {
    const open = approving as Approving | null
    return open?.choices.find((c) => c.type === open.selected && c.usable)
  })

  async function handleApprove(a: EnforcementAction) {
    await refreshPolicy()
    const d = device(a)
    // Without a current policy only the proposed type can be offered; the
    // controller still refuses it (422) if it cannot carry it out.
    const available = policy && !policyError ? policy.available_action_types : [a.action_type]
    const choices = actionTypeChoices(a, d, available)
    const defaultType = defaultChoice(choices)
    approving = { action: a, choices, selected: defaultType, defaultType }
    await tick()
    dialog?.showModal()
  }

  function closeDialog() {
    dialog?.close()
    approving = null
  }

  async function confirmApprove(e: Event) {
    e.preventDefault()
    const current = approving
    const type = chosen?.type
    if (!current || !type) return
    closeDialog()
    await act(current.action, 'approve', () => approveAction(current.action.id, type))
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

  function approver(a: EnforcementAction): string {
    if (a.approved_by) return describeActor(a.approved_by)
    return a.auto_approved ? describeActor('auto-policy') : '—'
  }

  function progressText(t: Tracked): string {
    const a = t.action
    if (t.verb === 'revert') return 'being lifted — still in force until the controller confirms'
    if (!a.action_type) return 'approved — checking…'
    return `being applied as ${formatActionType(a.action_type)} — not enforced until confirmed`
  }

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    void refreshPolicy()
    // Best effort: names make the confirmation readable for actions that
    // carry no client_name.
    fetchDevices()
      .then(({ devices }) => {
        names = new Map(
          devices.filter((d) => d.hostname).map((d) => [d.mac.toLowerCase(), d.hostname]),
        )
      })
      .catch(() => {})
    const refresh = setInterval(load, 10_000)
    // Unconfirmed operations are read more often, until they settle.
    const settle = setInterval(() => void pollTracked(), 2_000)
    return () => {
      clearInterval(refresh)
      clearInterval(settle)
    }
  })
</script>

<h1>Killswitch</h1>
<KillswitchNav />

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

<dialog bind:this={dialog} data-testid="approve-dialog" onclose={() => (approving = null)}>
  {#if approving}
    {@const a = approving.action}
    {@const d = device(a)}
    <form onsubmit={confirmApprove}>
      <h2>Approve {a.id}?</h2>
      <dl class="facts">
        <dt>Device</dt>
        <dd>{d.name || 'unknown name'}</dd>
        <dt>MAC</dt>
        <dd class="mono">{d.mac || 'unknown'}</dd>
        <dt>IP</dt>
        <dd class="mono">{d.ip || 'unknown'}</dd>
        {#if a.detection_summary}
          <dt>Detection</dt>
          <dd>{a.detection_summary}</dd>
        {/if}
        <dt>Proposed</dt>
        <dd>{formatActionType(a.action_type)} — {a.policy_rule || 'no rule recorded'}</dd>
        {#if a.ttl_seconds}
          <dt>Lifted after</dt>
          <dd>{Math.round(a.ttl_seconds / 60)} min</dd>
        {/if}
      </dl>

      {#if policyError}
        <p class="warn">
          Could not read which enforcement types are available ({policyError}); only the proposed
          one is offered.
        </p>
      {/if}

      <fieldset>
        <legend>How to enforce it</legend>
        {#if approving.choices.length === 0}
          <p class="warn">The killswitch reports no enforcement type available right now.</p>
        {/if}
        {#each approving.choices as c (c.type)}
          <label class="choice" class:strong={c.strong} class:unusable={!c.usable}>
            <input
              type="radio"
              name="action_type"
              value={c.type}
              bind:group={approving.selected}
              disabled={!c.usable}
            />
            <span class="choice-text">
              <span class="choice-name"
                >{c.name}{c.type === approving.defaultType ? ' (default)' : ''}</span
              >
              <span class="choice-does">{c.does}</span>
              <span class="choice-needs">{c.needs}</span>
              {#if !c.usable}<span class="choice-why">{c.why}</span>{/if}
            </span>
          </label>
        {/each}
      </fieldset>

      {#if chosen}
        <p class="question" class:strong={chosen.strong} data-testid="approve-question">
          {approveQuestion(chosen, d)}
          {chosen.strong ? '' : `It blocks ${describeBlock({ ...a, action_type: chosen.type })}.`}
        </p>
      {:else}
        <p class="question">Choose how to enforce it.</p>
      {/if}

      <div class="dialog-buttons">
        <button type="button" class="btn-cancel" onclick={closeDialog}>Cancel</button>
        <button type="submit" class="btn-approve" disabled={!chosen}
          >{chosen ? `Approve: ${chosen.name}` : 'Approve'}</button
        >
      </div>
    </form>
  {/if}
</dialog>

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
              <td class="reason" title={a.policy_rule}>{a.policy_rule}</td>
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

  {#if inProgress.length > 0}
    <section class="progress-section">
      <h2>In Progress ({inProgress.length})</h2>
      <p class="muted">
        The controller has not confirmed these yet. An approval is <strong>not</strong> enforced
        until it is confirmed; a block being lifted stays <strong>in force</strong> until then. This page
        keeps checking.
      </p>
      <table data-testid="progress-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Since</th>
            <th>Target</th>
            <th>Action</th>
            <th>What is happening</th>
            <th>Approved by</th>
          </tr>
        </thead>
        <tbody>
          {#each inProgress as t (t.action.id)}
            {@const a = t.action}
            <tr data-action-id={a.id} data-state={a.state} data-verb={t.verb}>
              <td class="mono">{a.id}</td>
              <td>{t.since.toLocaleTimeString()}</td>
              {@render target(a)}
              <td>{a.action_type ? formatActionType(a.action_type) : '—'}</td>
              <td><span class="badge badge-medium">in progress</span> {progressText(t)}</td>
              <td>{approver(a)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  {#if failures.length > 0 || failedError}
    <section class="failed-section">
      <h2>Enforcement Failures ({failures.length})</h2>
      <p class="warn">
        An <strong>apply</strong> failure means the block was never put in place: the device is
        <strong>not</strong> blocked. A <strong>revert</strong> failure means the block could not be
        lifted: it is <strong>still in force</strong>, and the controller keeps retrying. Check the
        driver before relying on either.
      </p>
      {#if failedError}
        <p class="error">{failedError}</p>
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
            {@const reverting = tracking.get(a.id)?.verb === 'revert'}
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
                {#if reverting}
                  <span class="badge badge-medium">revert in progress</span>
                {/if}
              </td>
              <td>{a.expires_at ? formatTime(a.expires_at) : 'never'}</td>
              <td data-testid="approved-by">{approver(a)}</td>
              <td class="actions-cell">
                <button
                  class="btn-revert"
                  disabled={busy.has(a.id) || reverting}
                  onclick={() => handleRevert(a)}>Revert</button
                >
              </td>
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
  .progress-section {
    border-left: 3px solid var(--warning);
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
  .outcome-warn,
  .outcome-progress {
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
    cursor: not-allowed;
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
  .btn-cancel {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
  }

  dialog {
    max-width: 40rem;
    width: calc(100% - 2rem);
    margin: auto;
    padding: 1.25rem 1.5rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
  }
  dialog::backdrop {
    background: rgba(0, 0, 0, 0.6);
  }
  dialog h2 {
    margin-top: 0;
    color: var(--text-primary);
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    font-size: 0.875rem;
    margin-bottom: 1rem;
  }
  .facts dt {
    color: var(--text-secondary);
  }
  fieldset {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    margin-bottom: 1rem;
  }
  legend {
    padding: 0 0.25rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
    font-weight: 600;
  }
  .choice {
    display: flex;
    gap: 0.75rem;
    align-items: flex-start;
    padding: 0.5rem 0;
    cursor: pointer;
  }
  .choice + .choice {
    border-top: 1px solid var(--border);
  }
  .choice input {
    margin-top: 0.3rem;
  }
  .choice-text span {
    display: block;
  }
  .choice-name {
    font-weight: 600;
  }
  .choice.strong .choice-name {
    color: var(--danger);
  }
  .choice-does {
    font-size: 0.875rem;
  }
  .choice-needs,
  .choice-why {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  .choice.unusable {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .question {
    font-weight: 600;
    margin-bottom: 1rem;
  }
  .question.strong {
    color: var(--danger);
  }
  .dialog-buttons {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
</style>
