<script lang="ts">
  import { onMount, untrack } from 'svelte'
  import { page } from '$app/state'
  import { alertAnchor, alertById, isComposite, signalBreakdown } from '#lib/alerts.ts'
  import {
    ALERTS_MAX_LIMIT,
    fetchAction,
    fetchAlerts,
    fetchAudit,
    fetchDevices,
    formatActionType,
    formatTime,
    isActionId,
  } from '#lib/api.ts'
  import KillswitchNav from '#lib/components/KillswitchNav.svelte'
  import SignalTable from '#lib/components/SignalTable.svelte'
  import {
    approverWords,
    describeActor,
    describeBlock,
    describeTransition,
    deviceOf,
    isStillEnforced,
    operationInFlight,
    stateWords,
  } from '#lib/killswitch.ts'
  import type { Alert, AuditEntry, EnforcementAction } from '#lib/types.ts'

  /**
   * One enforcement action: what it blocks and on which device, why the
   * policy proposed it (its rule and the detection's signals), who approved,
   * rejected or lifted it, and every change in the audit log.
   */

  let id = $derived(page.params.id ?? '')
  let valid = $derived(isActionId(id))

  let action = $state<EnforcementAction | null>(null)
  let missing = $state(false)
  let error = $state('')
  let trail: AuditEntry[] = $state([])
  let trailError = $state('')
  let alert = $state<Alert | null>(null)
  /** '' while looking; 'found', 'absent' or an error message once done. */
  let alertLookup = $state('')
  let names: Map<string, string> = $state(new Map())
  let loading = $state(true)

  let device = $derived(action ? deviceOf(action, names) : null)
  let signals = $derived(alert ? signalBreakdown(alert) : [])

  async function load() {
    if (!valid) return
    const [a, t] = await Promise.allSettled([
      fetchAction(id),
      fetchAudit({ actionId: id, limit: 100 }),
    ])
    if (a.status === 'fulfilled') {
      action = a.value
      missing = a.value === null
      error = ''
    } else {
      error = a.reason instanceof Error ? a.reason.message : 'Failed to load the action'
    }
    if (t.status === 'fulfilled') {
      trail = t.value
      trailError = ''
    } else {
      trailError = t.reason instanceof Error ? t.reason.message : 'Failed to load the audit trail'
    }
  }

  // The detection, once: GET /alerts has no lookup by id, so the newest
  // alerts are searched for it.
  async function findDetection(detectionId: string) {
    try {
      const found = alertById(await fetchAlerts(ALERTS_MAX_LIMIT), detectionId)
      alert = found ?? null
      alertLookup = found ? 'found' : 'absent'
    } catch (e) {
      alertLookup = e instanceof Error ? e.message : 'the detection engine could not be read'
    }
  }

  let looked = ''
  $effect(() => {
    const det = action?.detection_id ?? ''
    untrack(() => {
      if (!det || det === looked) return
      looked = det
      void findDetection(det)
    })
  })

  // From the start whenever the id changes, client-side navigation included.
  let shown: string | null = null
  $effect(() => {
    const current = id
    untrack(() => {
      if (current === shown) return
      shown = current
      action = null
      alert = null
      alertLookup = ''
      looked = ''
      trail = []
      loading = true
      void load().finally(() => {
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
    const interval = setInterval(() => void load(), 10_000)
    return () => clearInterval(interval)
  })
</script>

<h1>Action {valid ? id : ''}</h1>
<KillswitchNav />

{#if !valid}
  <p class="error">“{id}” is not an action id.</p>
{:else if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if missing || !action}
  <p class="empty">The killswitch does not know an action {id} (any more).</p>
{:else}
  {@const a = action}
  {@const d = device!}
  {@const op = operationInFlight(a)}
  <section aria-labelledby="what-heading">
    <h2 id="what-heading">What it does</h2>
    <dl class="facts" data-testid="action-facts" data-state={a.state}>
      <dt>State</dt>
      <dd data-testid="action-state">
        <strong class:enforced={isStillEnforced(a)}>{stateWords(a)}</strong>
        {#if op}<span class="secondary">A driver {op} is under way.</span>{/if}
      </dd>
      <dt>Device</dt>
      <dd data-testid="action-device">
        {d.name || 'unknown device'}
        <span class="mono">{d.mac || '—'}</span>{#if d.ip}, <span class="mono">{d.ip}</span>{/if}
      </dd>
      <dt>Enforcement</dt>
      <dd>{formatActionType(a.action_type)}: {describeBlock(a)}</dd>
      <dt>Proposed</dt>
      <dd>{formatTime(a.timestamp)}</dd>
      {#if a.activated_at}
        <dt>Enforced since</dt>
        <dd>{formatTime(a.activated_at)}</dd>
      {/if}
      {#if a.expires_at && isStillEnforced(a)}
        <dt>Lifted on its own at</dt>
        <dd>{formatTime(a.expires_at)}</dd>
      {/if}
      {#if a.reverted_at}
        <dt>Lifted</dt>
        <dd>{formatTime(a.reverted_at)}</dd>
      {/if}
      {#if a.failure_reason}
        <dt>Why the driver failed</dt>
        <dd class="fail">{a.failure_reason}</dd>
      {/if}
    </dl>
  </section>

  <section aria-labelledby="who-heading">
    <h2 id="who-heading">Who decided</h2>
    <dl class="facts" data-testid="action-who">
      <dt>Approved by</dt>
      <dd data-testid="action-approved-by">{approverWords(a)}</dd>
      {#if a.rejected_by}
        <dt>Rejected by</dt>
        <dd>{describeActor(a.rejected_by)}</dd>
      {/if}
      {#if a.reverted_by}
        <dt>Lifted by</dt>
        <dd>{describeActor(a.reverted_by)}</dd>
      {/if}
      {#if a.reason}
        <dt>Reason given</dt>
        <dd>{a.reason}</dd>
      {/if}
    </dl>
  </section>

  <section aria-labelledby="why-heading">
    <h2 id="why-heading">Why</h2>
    <dl class="facts" data-testid="action-why">
      <dt>Policy rule</dt>
      <dd class="mono" data-testid="action-rule">{a.policy_rule || 'none recorded'}</dd>
      <dt>Detection</dt>
      <dd>
        {a.detection_summary || '—'}
        <span class="secondary mono">{a.detection_id}</span>
      </dd>
    </dl>
    <h3>Signals of the detection</h3>
    {#if alertLookup === ''}
      <p class="muted">Looking the detection up in the detection engine…</p>
    {:else if alertLookup === 'found' && alert}
      <SignalTable rows={signals} composite={isComposite(alert)} />
      <p class="muted">
        <a href="/alerts#{alertAnchor(alert)}">The detection on the alerts page</a>
      </p>
    {:else if alertLookup === 'absent'}
      <p class="muted" data-testid="detection-absent">
        The detection engine no longer lists {a.detection_id} among its newest {ALERTS_MAX_LIMIT} alerts,
        so its signals cannot be shown.
      </p>
    {:else}
      <p class="error-inline">The detection could not be looked up: {alertLookup}</p>
    {/if}
  </section>

  <section aria-labelledby="trail-heading">
    <h2 id="trail-heading">Audit trail</h2>
    {#if trailError}
      <p class="error">{trailError}</p>
    {:else if trail.length === 0}
      <p class="empty">The audit log has no entry for this action.</p>
    {:else}
      <table data-testid="action-trail">
        <thead>
          <tr>
            <th scope="col">When</th>
            <th scope="col">Who</th>
            <th scope="col">What</th>
            <th scope="col">Reason</th>
          </tr>
        </thead>
        <tbody>
          {#each trail as e (e.seq)}
            <tr data-seq={e.seq} data-to-state={e.to_state}>
              <td class="nowrap">{formatTime(e.timestamp)}</td>
              <td data-testid="audit-actor">{describeActor(e.actor)}</td>
              <td data-testid="audit-what">{describeTransition(e)}</td>
              <td>{e.reason || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="muted more">
        <a href="/killswitch/audit?action={encodeURIComponent(a.id)}">In the audit log</a>
      </p>
    {/if}
  </section>
{/if}

<style>
  section {
    margin-bottom: 2rem;
  }
  h3 {
    font-size: 0.9375rem;
    font-weight: 600;
    color: var(--text-secondary);
    margin: 1rem 0 0.5rem;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1.25rem;
    font-size: 0.875rem;
    max-width: 56rem;
  }
  .facts dt {
    color: var(--text-secondary);
  }
  .enforced {
    color: var(--danger);
  }
  .fail,
  .error-inline {
    color: var(--danger);
  }
  .nowrap {
    white-space: nowrap;
  }
  a {
    color: var(--accent);
  }
  .more {
    margin-top: 0.5rem;
  }
</style>
