<script lang="ts">
  import { onMount, tick } from 'svelte'
  import { page } from '$app/state'
  import {
    SUPPRESSION_DAYS,
    alertAnchor,
    alertClient,
    alertClientText,
    alertHeadline,
    alertObservedDomain,
    falsePositiveQuestion,
    falsePositiveVerdict,
    isSilenced,
    liftQuestion,
    liftRequest,
    signalClasses,
    suppressionAnchor,
    suppressionDays,
    suppressionEnds,
    suppressionFor,
    suppressionPeriod,
    suppressionScope,
  } from '$lib/alerts'
  import {
    ALERTS_LIMIT,
    ALERTS_MAX_LIMIT,
    fetchAlerts,
    fetchSuppressions,
    formatTime,
    formatTimeLeft,
    liftSuppression,
    normaliseMac,
    submitFeedback,
  } from '$lib/api'
  import { newestFirst } from '$lib/order'
  import type { Alert, Suppression } from '$lib/types'

  const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const

  let allAlerts: Alert[] = $state([])
  let loading: boolean = $state(true)
  let error: string = $state('')

  let sevFilter: Set<string> = $state(new Set(SEVERITIES))
  let deviceFilter: string = $state('')
  let sourceFilter: string = $state('')
  let timeFilter: string = $state('all')

  let filtered: Alert[] = $derived.by(() => {
    let result = allAlerts

    if (sevFilter.size < SEVERITIES.length) {
      result = result.filter((a) => sevFilter.has(a.severity))
    }

    if (deviceFilter.trim()) {
      const q = deviceFilter.trim().toLowerCase()
      result = result.filter((a) => alertClientText(a).includes(q))
    }

    if (sourceFilter) {
      result = result.filter((a) => a.source === sourceFilter)
    }

    if (timeFilter !== 'all') {
      const hours = parseInt(timeFilter)
      const cutoff = Date.now() - hours * 3600_000
      result = result.filter((a) => {
        const t = new Date(a.timestamp).getTime()
        return !isNaN(t) && t >= cutoff
      })
    }

    return result
  })

  let silencedCount = $derived(filtered.filter(isSilenced).length)

  let sources: string[] = $derived(
    [...new Set(allAlerts.map((a) => a.source ?? '').filter(Boolean))].sort(),
  )

  function toggleSeverity(sev: string) {
    const next = new Set(sevFilter)
    if (next.has(sev)) {
      if (next.size > 1) next.delete(sev)
    } else {
      next.add(sev)
    }
    sevFilter = next
  }

  function clearFilters() {
    sevFilter = new Set(SEVERITIES)
    deviceFilter = ''
    sourceFilter = ''
    timeFilter = 'all'
  }

  let hasActiveFilters: boolean = $derived(
    sevFilter.size < SEVERITIES.length ||
      deviceFilter.trim() !== '' ||
      sourceFilter !== '' ||
      timeFilter !== 'all',
  )

  // False-positive feedback (step 118). The engine's active suppressions
  // say which alerts are silenced; a verdict made here shows at once.
  let suppressions: Suppression[] = $state([])
  let suppressionsError: string = $state('')
  let feedbackNotes: { key: number; tone: 'ok' | 'warn' | 'fail'; text: string }[] = $state([])
  let feedbackSeq = 0
  let sending: Set<string> = $state(new Set())

  function note(tone: 'ok' | 'warn' | 'fail', text: string) {
    feedbackNotes = [{ key: ++feedbackSeq, tone, text }, ...feedbackNotes].slice(0, 5)
  }

  /** How long a new verdict suppresses: read off the engine's own suppressions when it has any. */
  let ttlDays = $derived(suppressionDays(suppressions))

  /** "until 16/12/2026, 18:04:00 (30 days left)", or an estimate when the engine sends no end. */
  function endWords(s: Suppression): string {
    const end = suppressionEnds(s)
    if (!end) return ''
    const left = formatTimeLeft(end.at)
    return end.estimated
      ? `until about ${formatTime(end.at)} if the engine uses its default ${SUPPRESSION_DAYS} days`
      : `until ${formatTime(end.at)}${left ? ` (${left})` : ''}`
  }

  async function markFalsePositive(a: Alert) {
    if (!a.matched_ioc || isSilenced(a)) return
    if (!confirm(falsePositiveQuestion(a, ttlDays))) return
    sending = new Set(sending).add(a.id)
    let done: boolean | null | undefined
    try {
      done = (await submitFeedback(falsePositiveVerdict(a))).persisted
    } catch (e) {
      note('fail', e instanceof Error ? e.message : 'Failed to submit feedback')
    } finally {
      const next = new Set(sending)
      next.delete(a.id)
      sending = next
      await loadSuppressions()
    }
    if (done === undefined) return
    // The list just read back says when it ends.
    const made = suppressionFor(a, suppressions)
    const until = made ? endWords(made) : `for ${suppressionPeriod(ttlDays)}`
    note(
      done === false ? 'warn' : 'ok',
      `Marked ${a.matched_ioc} as a false positive: silenced ${until}.` +
        (done === false
          ? ' It applies now but was NOT saved: the detection engine could not record it, so it is forgotten when the engine restarts.'
          : done
            ? ' Saved.'
            : ''),
    )
  }

  async function lift(s: Suppression) {
    if (!confirm(liftQuestion(s, suppressions))) return
    const what = `the suppression of ${s.matched_ioc} (${s.signal_class}) ${suppressionScope(s)}`
    try {
      const r = await liftSuppression(liftRequest(s))
      if (!r.inForce) {
        note(
          'warn',
          `Nothing to lift: ${what} was no longer in force (lifted already, or it expired).`,
        )
      } else if (r.persisted === false) {
        const end = suppressionEnds(s)
        note(
          'warn',
          `Lifted ${what}. It applies now but was NOT saved: when the detection engine restarts, ` +
            `the suppression comes back${end ? ` (until ${formatTime(end.at)})` : ''}.`,
        )
      } else {
        note('ok', `Lifted ${what}.${r.persisted ? ' Saved.' : ''}`)
      }
    } catch (e) {
      note('fail', e instanceof Error ? e.message : 'Failed to lift the suppression')
    } finally {
      await loadSuppressions()
    }
  }

  async function loadSuppressions() {
    try {
      // GET /feedback comes in map order: newest first, stably.
      suppressions = (await fetchSuppressions()).sort(
        (x, y) =>
          Date.parse(y.timestamp) - Date.parse(x.timestamp) ||
          x.matched_ioc.localeCompare(y.matched_ioc) ||
          (x.client_ip ?? '').localeCompare(y.client_ip ?? ''),
      )
      suppressionsError = ''
    } catch (e) {
      suppressionsError = e instanceof Error ? e.message : 'Failed to load suppressions'
    }
  }

  // A link to a row — #suppression-… from a silenced alert, #alert-… from
  // the dashboard — names a row that only exists once the lists are loaded:
  // scroll to it then, once, and mark it while it is the URL's target.
  let target = $derived(page.url.hash.slice(1))
  let scrolledTo = ''
  $effect(() => {
    const id = target
    if (!id || id === scrolledTo || loading) return
    if (allAlerts.length === 0 && suppressions.length === 0) return
    void tick().then(() => {
      const el = document.getElementById(id)
      if (!el) return
      scrolledTo = id
      el.scrollIntoView({ block: 'center' })
    })
  })

  // GET /alerts returns the newest `limit` alerts; "show more" asks for more.
  let limit = $state(ALERTS_LIMIT)
  let more = $derived(allAlerts.length >= limit && limit < ALERTS_MAX_LIMIT)

  async function showMore() {
    limit = Math.min(ALERTS_MAX_LIMIT, limit * 2)
    await load()
  }

  async function load() {
    try {
      allAlerts = newestFirst(await fetchAlerts(limit))
      error = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load alerts'
    }
  }

  onMount(() => {
    // Not async: an async onMount cannot return a cleanup function, so
    // the interval below would never be cleared on navigation.
    void load().finally(() => {
      loading = false
    })
    void loadSuppressions()
    const interval = setInterval(() => {
      void load()
      void loadSuppressions()
    }, 30_000)
    return () => clearInterval(interval)
  })
</script>

<div class="alerts-header">
  <h1>Alerts</h1>
  <span class="alert-count"
    >{filtered.length}{filtered.length !== allAlerts.length ? ` / ${allAlerts.length}` : ''}</span
  >
  {#if silencedCount > 0}
    <span class="alert-count" data-testid="silenced-count"
      >{silencedCount} silenced by a suppression (not sent to the killswitch)</span
    >
  {/if}
</div>

{#if feedbackNotes.length > 0}
  <ul class="notes" aria-live="polite">
    {#each feedbackNotes as n (n.key)}
      <li class="note note-{n.tone}" data-testid="feedback-note">{n.text}</li>
    {/each}
  </ul>
{/if}

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else}
  <div class="filters">
    <div class="filter-row">
      <div class="filter-group">
        <span class="filter-label">Severity</span>
        <div class="sev-toggles">
          {#each SEVERITIES as sev}
            <button
              class="sev-btn sev-{sev}"
              class:active={sevFilter.has(sev)}
              onclick={() => toggleSeverity(sev)}
            >
              {sev}
            </button>
          {/each}
        </div>
      </div>

      <div class="filter-group">
        <span class="filter-label">Device</span>
        <input
          type="text"
          class="filter-input"
          placeholder="Name, MAC or IP…"
          bind:value={deviceFilter}
        />
      </div>

      <div class="filter-group">
        <span class="filter-label">Source</span>
        <select class="filter-select" bind:value={sourceFilter}>
          <option value="">All sources</option>
          {#each sources as s}
            <option value={s}>{s}</option>
          {/each}
        </select>
      </div>

      <div class="filter-group">
        <span class="filter-label">Time</span>
        <select class="filter-select" bind:value={timeFilter}>
          <option value="all">All time</option>
          <option value="1">Last 1h</option>
          <option value="6">Last 6h</option>
          <option value="24">Last 24h</option>
          <option value="168">Last 7d</option>
        </select>
      </div>

      {#if hasActiveFilters}
        <button class="clear-btn" onclick={clearFilters}>Clear</button>
      {/if}
    </div>
  </div>

  {#if filtered.length === 0}
    <p class="empty">
      {allAlerts.length === 0 ? 'No alerts detected.' : 'No alerts match the current filters.'}
    </p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Alert</th>
          <th>Client</th>
          <th>Matched IoC</th>
          <th>Threat</th>
          <th>MITRE</th>
          <th>Source</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as a}
          {@const client = alertClient(a)}
          {@const mac = normaliseMac(client.mac)}
          {@const observed = alertObservedDomain(a)}
          {@const classes = signalClasses(a)}
          {@const suppressed = suppressionFor(a, suppressions)}
          {@const silenced = isSilenced(a)}
          {@const anchor = alertAnchor(a)}
          <tr
            id={anchor}
            data-alert-id={a.id}
            data-silenced={silenced ? 'true' : undefined}
            class:silenced
            class:targeted={target === anchor}
          >
            <td class="nowrap">{formatTime(a.timestamp)}</td>
            <td>
              <span class="badge badge-{a.severity}">{a.severity}</span>
              {#if a.confidence}<span class="confidence">{a.confidence}%</span>{/if}
            </td>
            <td class="headline" data-testid="alert-headline">
              <span class="headline-text" title={alertHeadline(a)}>{alertHeadline(a)}</span>
              {#if observed || classes.length > 0}
                <span class="secondary">
                  {#if observed}<span class="mono" title={observed}>{observed}</span>{/if}
                  {#if classes.length > 0}<span>{classes.join(' + ')}</span>{/if}
                </span>
              {/if}
            </td>
            <td class="client" data-testid="alert-client">
              {#if client.name}<span class="client-name">{client.name}</span>{/if}
              {#if client.mac}
                {#if mac}
                  <a href="/devices/{encodeURIComponent(mac)}" class="ip-link mono">{client.mac}</a>
                {:else}
                  <span class="mono">{client.mac}</span>
                {/if}
              {/if}
              {#if client.ip}<span class="mono">{client.ip}</span>{/if}
              {#if !client.name && !client.mac && !client.ip}—{/if}
            </td>
            <td class="mono truncate" title={a.matched_ioc}>{a.matched_ioc || '—'}</td>
            <td class="truncate">{a.threat || '—'}</td>
            <td class="truncate">
              {#if a.mitre_id}
                <span class="mitre" title={a.mitre_name}>{a.mitre_id}</span>
              {:else}
                —
              {/if}
            </td>
            <td>{a.source || '—'}</td>
            <td class="nowrap">
              {#if silenced}
                <!-- Recorded while silenced: it never reached the killswitch.
                     Not offered for a verdict again. -->
                <span
                  class="silenced-label"
                  data-testid="silenced"
                  title="Recorded while a false-positive suppression applied: it was not sent to the killswitch, and nothing was blocked for it."
                  >Silenced</span
                >
                {#if suppressed}
                  <a
                    class="secondary silenced-link"
                    href="#{suppressionAnchor(suppressed)}"
                    data-testid="silenced-by"
                    title="Suppressed as a false positive by {suppressed.analyst ||
                      'someone'}, in force {endWords(suppressed)}."
                    >see the suppression ({formatTimeLeft(suppressionEnds(suppressed)?.at)})</a
                  >
                {:else}
                  <span class="secondary" data-testid="silenced-by"
                    >the suppression has ended since</span
                  >
                {/if}
              {:else if suppressed}
                <a
                  class="fp-marked"
                  href="#{suppressionAnchor(suppressed)}"
                  data-testid="fp-marked"
                  title="Suppressed as a false positive by {suppressed.analyst ||
                    'someone'} on {formatTime(suppressed.timestamp)}, {endWords(
                    suppressed,
                  )}: detections of it no longer reach the killswitch">✓ FP</a
                >
                <span class="secondary">{formatTimeLeft(suppressionEnds(suppressed)?.at)}</span>
              {:else if a.matched_ioc}
                <button
                  class="fp-btn"
                  title="Mark as false positive — suppresses this indicator on this device for {suppressionPeriod(
                    ttlDays,
                  )}"
                  disabled={sending.has(a.id)}
                  onclick={() => markFalsePositive(a)}
                >
                  Mark FP
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if more}
      <p class="paging">
        <span class="muted">The newest {allAlerts.length} alerts.</span>
        <button class="more-btn" onclick={showMore}>Show older alerts</button>
      </p>
    {/if}
  {/if}
{/if}

<section class="suppressions">
  <h2>Active suppressions ({suppressions.length})</h2>
  <p class="muted">
    A false-positive verdict keeps detections of that indicator and signal from reaching the
    killswitch — on one device, or on every device when none is named — until the time in the Ends
    column ({ttlDays === null ? `by default ${SUPPRESSION_DAYS} days` : suppressionPeriod(ttlDays)} after
    it was made). Detections it silences are still listed above, dimmed and marked Silenced. Lifting one
    ends it at once.
  </p>
  {#if suppressionsError}
    <p class="error">{suppressionsError}</p>
  {:else if suppressions.length === 0}
    <p class="empty">Nothing is suppressed.</p>
  {:else}
    <table data-testid="suppressions-table">
      <thead>
        <tr>
          <th>Indicator</th>
          <th>Signal</th>
          <th>Device</th>
          <th>Marked by</th>
          <th>Marked</th>
          <th>Ends</th>
          <th>Reason</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each suppressions as s (`${s.matched_ioc}|${s.client_ip ?? ''}|${s.signal_class}`)}
          {@const anchor = suppressionAnchor(s)}
          {@const end = suppressionEnds(s)}
          <tr id={anchor} data-ioc={s.matched_ioc} class:targeted={target === anchor}>
            <td class="mono truncate" title={s.matched_ioc}>{s.matched_ioc}</td>
            <td>{s.signal_class}</td>
            <td class="mono">{s.client_ip || 'every device'}</td>
            <td>{s.analyst || '—'}</td>
            <td class="nowrap">{formatTime(s.timestamp)}</td>
            <td class="nowrap" data-testid="suppression-ends">
              {#if end}
                {end.estimated ? `about ${formatTime(end.at)}` : formatTime(end.at)}
                <span class="secondary"
                  >{end.estimated
                    ? `estimated: the engine did not say; ${SUPPRESSION_DAYS} days is its default`
                    : formatTimeLeft(end.at)}</span
                >
              {:else}
                —
              {/if}
            </td>
            <td class="truncate" title={s.reason}>{s.reason || '—'}</td>
            <td><button class="fp-btn" onclick={() => lift(s)}>Lift</button></td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<style>
  .headline {
    max-width: 320px;
  }
  .headline-text {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .client span,
  .client a {
    display: block;
  }
  .secondary span + span::before {
    content: ' · ';
  }
  .secondary {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .client-name {
    font-weight: 600;
  }
  .alerts-header {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
    margin-bottom: 1rem;
  }
  .alerts-header h1 {
    margin-bottom: 0;
  }
  .alert-count {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .filters {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
  }
  .filter-row {
    display: flex;
    align-items: flex-end;
    gap: 1.25rem;
    flex-wrap: wrap;
  }
  .filter-group {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .filter-label {
    font-size: 0.6875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
    font-weight: 600;
  }

  .sev-toggles {
    display: flex;
    gap: 0.25rem;
  }
  .sev-btn {
    padding: 0.2rem 0.6rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    cursor: pointer;
    background: transparent;
    color: var(--text-secondary);
    opacity: 0.4;
    transition:
      opacity 0.15s,
      background 0.15s;
  }
  .sev-btn.active {
    opacity: 1;
  }
  .sev-btn.sev-critical.active {
    background: rgba(248, 81, 73, 0.2);
    color: #f85149;
    border-color: #f85149;
  }
  .sev-btn.sev-high.active {
    background: rgba(248, 81, 73, 0.12);
    color: #f47067;
    border-color: #f47067;
  }
  .sev-btn.sev-medium.active {
    background: rgba(210, 153, 34, 0.15);
    color: var(--warning);
    border-color: var(--warning);
  }
  .sev-btn.sev-low.active {
    background: rgba(63, 185, 80, 0.12);
    color: var(--success);
    border-color: var(--success);
  }

  .filter-input,
  .filter-select {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 0.5rem;
    font-size: 0.8125rem;
    font-family: inherit;
  }
  .filter-input {
    width: 140px;
  }
  .filter-input::placeholder {
    color: var(--text-secondary);
  }

  .clear-btn {
    background: transparent;
    color: var(--accent);
    border: none;
    font-size: 0.8125rem;
    cursor: pointer;
    padding: 0.3rem 0;
    align-self: flex-end;
  }
  .clear-btn:hover {
    text-decoration: underline;
  }

  .nowrap {
    white-space: nowrap;
  }
  .confidence {
    font-size: 0.6875rem;
    color: var(--text-secondary);
    margin-left: 0.35rem;
  }
  .ip-link {
    color: var(--accent);
    text-decoration: none;
  }
  .ip-link:hover {
    text-decoration: underline;
  }
  .mitre {
    font-size: 0.75rem;
    font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace;
    color: var(--text-secondary);
  }

  .fp-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.6875rem;
    padding: 0.2rem 0.5rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .fp-btn:hover {
    color: var(--warning);
    border-color: var(--warning);
  }
  .fp-marked {
    font-size: 0.6875rem;
    color: var(--success);
    font-weight: 600;
    text-decoration: none;
  }
  /* Recorded while silenced: kept visible, but clearly not an open detection. */
  tr.silenced td {
    opacity: 0.55;
  }
  tr.silenced:hover td {
    opacity: 0.8;
  }
  .silenced-label {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
  }
  .silenced-link {
    color: var(--accent);
    text-decoration: none;
  }
  .silenced-link:hover {
    text-decoration: underline;
  }
  tr.targeted td,
  tr.targeted:hover td {
    background: rgba(88, 166, 255, 0.12);
  }
  .fp-btn:disabled {
    opacity: 0.5;
    cursor: wait;
  }

  .notes {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-bottom: 1rem;
  }
  .note {
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    border-left: 3px solid var(--success);
    background: var(--bg-secondary);
    font-size: 0.875rem;
  }
  .note-warn {
    border-left-color: var(--warning);
  }
  .note-fail {
    border-left-color: var(--danger);
    color: var(--danger);
  }
  .paging {
    margin-top: 1rem;
    display: flex;
    gap: 1rem;
    align-items: center;
  }
  .more-btn {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
    font-size: 0.8125rem;
  }
  .suppressions {
    margin-top: 2rem;
  }
  .suppressions .muted {
    max-width: 48rem;
    margin-bottom: 1rem;
  }

  .badge-critical {
    background: rgba(248, 81, 73, 0.2);
    color: #f85149;
  }
  .badge-low {
    background: rgba(63, 185, 80, 0.12);
    color: var(--success);
  }
</style>
