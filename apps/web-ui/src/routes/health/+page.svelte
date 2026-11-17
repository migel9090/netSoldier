<script lang="ts">
  import { onMount } from 'svelte'
  import { fetchPolicy, fetchStatus, formatTime } from '#lib/api.ts'
  import ModePanel from '#lib/components/ModePanel.svelte'
  import {
    agoWords,
    captureFinding,
    dnsFinding,
    durationWords,
    feedVerdict,
    intelFinding,
    recentWords,
    sensorVerdict,
    sensorsFinding,
    type Finding,
    type ServiceProbe,
    type StatusService,
    type SystemStatus,
    type Verdict,
  } from '#lib/status.ts'
  import type { KillswitchPolicy } from '#lib/types.ts'

  /**
   * Whether the system sees the network and is acting on what it sees, from
   * what each service reports about itself (GET /api/status, composed by the
   * UI's server from their probes and metrics), and what mode it is in.
   */

  let status = $state<SystemStatus | null>(null)
  let error = $state('')
  let policy = $state<KillswitchPolicy | null>(null)
  let policyError = $state('')
  let loading = $state(true)
  let refreshing = $state(false)

  const SERVICE_NAMES: Record<StatusService, string> = {
    killswitch: 'killswitch-controller',
    'detection-engine': 'detection-engine',
    'device-inventory': 'device-inventory',
    'threat-intel-sync': 'threat-intel-sync',
  }

  function probe(s: StatusService): ServiceProbe | undefined {
    return status?.services.find((p) => p.service === s)
  }

  let findings = $derived.by((): [string, string, Finding][] => {
    if (!status) return []
    return [
      [
        'capture',
        'Devices on the network',
        captureFinding(status.capture, probe('device-inventory')),
      ],
      ['dns', 'DNS lookups', dnsFinding(status.dns, probe('detection-engine'))],
      ['sensors', 'Packet sensors', sensorsFinding(status.sensors, probe('detection-engine'))],
      [
        'intel',
        'Threat intelligence',
        intelFinding(status.engineIntel, status.threatIntel, probe('threat-intel-sync')),
      ],
    ]
  })

  const VERDICT_WORDS: Record<Verdict, string> = {
    ok: 'working',
    warn: 'check',
    fail: 'not working',
    unknown: 'unknown',
    off: 'not in use',
  }

  function n(v: number | null | undefined): string {
    return v === null || v === undefined ? '—' : String(v)
  }

  function message(e: unknown, fallback: string): string {
    return e instanceof Error ? e.message : fallback
  }

  async function load() {
    refreshing = true
    const [s, p] = await Promise.allSettled([fetchStatus(), fetchPolicy()])
    if (s.status === 'fulfilled') {
      status = s.value
      error = ''
    } else {
      // An outage of the UI's own status endpoint is an error, not "all quiet".
      error = message(s.reason, 'Failed to load the system status')
    }
    if (p.status === 'fulfilled') {
      policy = p.value
      policyError = ''
    } else {
      policyError = message(p.reason, 'could not be read')
    }
    refreshing = false
  }

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    const interval = setInterval(() => void load(), 30_000)
    return () => clearInterval(interval)
  })
</script>

<h1>System Health</h1>

<ModePanel {policy} error={policyError} />

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error" data-testid="status-error">{error}</p>
{:else if status}
  <p class="muted updated">
    As the services reported it at {formatTime(status.generatedAt)}; refreshed every 30 s.
    <button class="refresh" onclick={() => void load()} disabled={refreshing}
      >{refreshing ? 'Refreshing…' : 'Refresh now'}</button
    >
  </p>

  <section aria-labelledby="sees-heading">
    <h2 id="sees-heading">Does the system see the network?</h2>
    <ul class="findings">
      {#each findings as [key, label, f] (key)}
        <li
          class="finding finding-{f.verdict}"
          data-testid="finding-{key}"
          data-verdict={f.verdict}
        >
          <span class="finding-label">{label}</span>
          <span class="verdict">{VERDICT_WORDS[f.verdict]}</span>
          <span class="finding-text">{f.text}</span>
        </li>
      {/each}
    </ul>
  </section>

  {#each status.notes as note (note)}
    <p class="warn" data-testid="status-note">{note}</p>
  {/each}

  <section aria-labelledby="services-heading">
    <h2 id="services-heading">Services</h2>
    <table data-testid="services-table">
      <thead>
        <tr>
          <th scope="col">Service</th>
          <th scope="col">Answering</th>
          <th scope="col">Metrics</th>
          <th scope="col">Problem</th>
        </tr>
      </thead>
      <tbody>
        {#each status.services as s (s.service)}
          <tr data-service={s.service} data-up={s.up === null ? undefined : String(s.up)}>
            <td>{SERVICE_NAMES[s.service]}</td>
            {#if !s.configured}
              <td colspan="3" class="muted"
                >Not read: {s.urlVar} is not set in the web UI's configuration.</td
              >
            {:else}
              <td>{s.up ? 'yes' : 'NO'}</td>
              <td>{s.metrics ? 'read' : 'not read'}</td>
              <td class="problem">{s.error || '—'}</td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  </section>

  <section aria-labelledby="capture-heading">
    <h2 id="capture-heading">Network capture (device-inventory)</h2>
    {#if !status.capture}
      <p class="error">
        Not known: device-inventory could not be read ({probe('device-inventory')?.error ||
          'no answer'}).
      </p>
    {:else}
      {@const c = status.capture}
      <dl class="facts" data-testid="capture-facts">
        <dt>Network agent</dt>
        <dd data-testid="capture-agent">
          {c.agent || 'none has reported'}{c.interface ? ` on ${c.interface}` : ''}
          {#if c.agentReady}— healthy{:else if c.reason}— {c.reason}{/if}
        </dd>
        <dt>Last heartbeat</dt>
        <dd data-testid="capture-heartbeat">
          {c.lastSeen ? `${agoWords(c.lastSeen)} (${formatTime(c.lastSeen)})` : 'never'}
        </dd>
        <dt>Capturing</dt>
        <dd data-testid="capture-protocols">
          {#if Object.keys(c.capture).length === 0}
            nothing reported
          {:else}
            {#each Object.entries(c.capture).sort( ([a], [b]) => a.localeCompare(b) ) as [proto, up], i (proto)}
              {i > 0 ? ', ' : ''}<span class:down={!up}>{proto} {up ? 'up' : 'DOWN'}</span>
            {/each}
          {/if}
          {#if c.expected.length > 0}
            <span class="secondary">Expected by device-inventory: {c.expected.join(', ')}.</span>
          {:else if c.required === false}
            <span class="secondary">No capture is expected (NETAGENT_EXPECT_CAPTURE=none).</span>
          {/if}
        </dd>
        <dt>Frames dropped by the agent</dt>
        <dd>{n(c.dropped)}</dd>
        <dt>Frames received</dt>
        <dd>
          {c.framesRecent ? recentWords(c.framesRecent, 'frame') : 'measured from the next refresh'}
        </dd>
        <dt>Devices known</dt>
        <dd data-testid="capture-devices">{n(c.knownDevices)}</dd>
        <dt>Newest sighting</dt>
        <dd data-testid="capture-sighting">
          {c.lastSighting
            ? `${agoWords(c.lastSighting)} (${formatTime(c.lastSighting)})`
            : 'none since device-inventory started'}
        </dd>
      </dl>
    {/if}
  </section>

  <section aria-labelledby="dns-heading">
    <h2 id="dns-heading">DNS lookups (detection-engine, AdGuard query log)</h2>
    {#if !status.dns}
      <p class="error">
        Not known: the detection engine's metrics could not be read ({probe('detection-engine')
          ?.error || 'no answer'}).
      </p>
    {:else}
      {@const d = status.dns}
      <dl class="facts" data-testid="dns-facts">
        <dt>Query-log pages read</dt>
        <dd data-testid="dns-pages">
          {n(d.pagesRead)} since the engine started{d.pagesRecent
            ? `; ${recentWords(d.pagesRecent, 'page')}`
            : ''}
        </dd>
        <dt>Failed polls</dt>
        <dd data-testid="dns-errors">
          {n(d.pollErrors)} since the engine started{d.errorsRecent
            ? `; ${recentWords(d.errorsRecent, 'failed poll')}`
            : ''}
        </dd>
        <dt>Polls that hit the page limit</dt>
        <dd>
          {n(d.gaps)}
          <span class="secondary"
            >queries in such a gap may have gone unchecked (QUERYLOG_MAX_PAGES)</span
          >
        </dd>
        <dt>Lookups checked</dt>
        <dd>
          {n(d.queriesChecked)}{d.queriesRecent
            ? `; ${recentWords(d.queriesRecent, 'lookup')}`
            : ''}
        </dd>
        <dt>Indicators matched against</dt>
        <dd>{n(d.threatlistSize)}</dd>
      </dl>
    {/if}
  </section>

  <section aria-labelledby="sensors-heading">
    <h2 id="sensors-heading">Packet sensors (detection-engine ingest)</h2>
    {#if !status.sensors}
      <p class="error">Not known: the detection engine's metrics could not be read.</p>
    {:else if status.sensors.length === 0}
      <p class="muted" data-testid="sensors-none">
        The detection engine reports no sensor source: Suricata, Zeek and the ML workers are read
        from ClickHouse, which this installation does not have (or the engine has not polled it
        yet).
      </p>
    {:else}
      <table data-testid="sensors-table">
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Behind by</th>
            <th scope="col">Rows read</th>
            <th scope="col">Errors</th>
            <th scope="col">State</th>
          </tr>
        </thead>
        <tbody>
          {#each status.sensors as s (s.source)}
            {@const v = sensorVerdict(s)}
            <tr data-source={s.source} data-verdict={v}>
              <td class="mono">{s.source}</td>
              <td>{s.lagSeconds === null ? '—' : durationWords(s.lagSeconds)}</td>
              <td>{s.rowsRecent ? recentWords(s.rowsRecent, 'row') : `${n(s.rows)} in all`}</td>
              <td
                >{s.errorsRecent
                  ? recentWords(s.errorsRecent, 'error')
                  : `${n(s.errors)} in all`}</td
              >
              <td>{VERDICT_WORDS[v]}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section aria-labelledby="intel-heading">
    <h2 id="intel-heading">Threat intelligence</h2>
    {#if status.engineIntel}
      {@const e = status.engineIntel}
      <dl class="facts" data-testid="engine-intel">
        <dt>Detection engine's feed set</dt>
        <dd>
          {e.lastSuccess
            ? `${n(e.indicators)} indicators, loaded ${agoWords(e.lastSuccess)}`
            : 'no feed set loaded since the engine started (or it has no THREAT_INTEL_URL)'}
          {#if Object.keys(e.failures).length > 0}
            <span class="secondary"
              >Failed syncs: {Object.entries(e.failures)
                .map(([r, c]) => `${r} ${c}`)
                .join(', ')}</span
            >
          {/if}
        </dd>
      </dl>
    {/if}
    {#if !probe('threat-intel-sync')?.configured}
      <p class="muted" data-testid="intel-not-configured">
        threat-intel-sync is not read: THREAT_INTEL_URL is not set in the web UI's configuration.
      </p>
    {:else if !status.threatIntel}
      <p class="error" data-testid="intel-error">
        threat-intel-sync could not be read ({probe('threat-intel-sync')?.error || 'no answer'}).
      </p>
    {:else}
      {@const t = status.threatIntel}
      <dl class="facts" data-testid="intel-facts">
        <dt>threat-intel-sync</dt>
        <dd data-testid="intel-ready">
          {t.ready === true
            ? 'ready'
            : t.ready === false
              ? `NOT ready${t.reason ? `: ${t.reason}` : ''}`
              : 'unknown'}
        </dd>
        <dt>Indicators held</dt>
        <dd>
          {n(t.indicators)}{t.capacity ? ` of at most ${t.capacity}` : ''}{t.persistent === false
            ? ' (in memory only: lost on restart)'
            : ''}
        </dd>
        <dt>Last complete sync cycle</dt>
        <dd>
          {t.lastCycle
            ? `${agoWords(t.lastCycle)} (${formatTime(t.lastCycle)})`
            : 'none since it started'}
        </dd>
      </dl>
      {#if t.sources.length > 0}
        <table data-testid="feeds-table">
          <thead>
            <tr>
              <th scope="col">Feed</th>
              <th scope="col">Last successful sync</th>
              <th scope="col">Indicators</th>
              <th scope="col">Failures</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {#each t.sources as f (f.source)}
              {@const v = feedVerdict(f)}
              <tr data-source={f.source} data-verdict={v}>
                <td>{f.source}</td>
                <td
                  >{f.enabled
                    ? f.lastSuccess
                      ? `${agoWords(f.lastSuccess)} (${formatTime(f.lastSuccess)})`
                      : 'never'
                    : '—'}</td
                >
                <td>{f.enabled ? n(f.indicators) : '—'}</td>
                <td>{f.enabled ? n(f.failures) : '—'}</td>
                <td>{f.enabled ? VERDICT_WORDS[v] : 'disabled (its start-up log says why)'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    {/if}
  </section>

  <section aria-labelledby="acting-heading">
    <h2 id="acting-heading">Detections and enforcement</h2>
    <dl class="facts" data-testid="acting-facts">
      {#if status.detection}
        {@const d = status.detection}
        <dt>Detection engine's store</dt>
        <dd data-testid="detection-durable">
          {d.durable === true
            ? 'on disk'
            : d.durable === false
              ? 'IN MEMORY ONLY: alerts, undelivered detections and verdicts are lost on restart'
              : '—'}
        </dd>
        <dt>Detections not yet delivered to the killswitch</dt>
        <dd data-testid="detection-backlog">
          {n(d.backlog)}{d.backlog && d.backlogOldestSeconds
            ? `, the oldest waiting ${durationWords(d.backlogOldestSeconds)}`
            : ''}
        </dd>
        <dt>Suppressions in force</dt>
        <dd><a href="/suppressions">{n(d.activeSuppressions)}</a></dd>
      {:else}
        <dt>Detection engine</dt>
        <dd class="error-inline">not known: its metrics could not be read</dd>
      {/if}
      {#if status.enforcement}
        {@const k = status.enforcement}
        <dt>Waiting for approval</dt>
        <dd data-testid="pending-count"><a href="/killswitch">{n(k.pending)}</a></dd>
        <dt>Enforced now</dt>
        <dd data-testid="enforced-now">
          {n(k.active)}{k.revertFailed
            ? `, ${k.revertFailed} of them after a failed revert`
            : ''}{k.awaitingConfirmation
            ? `; ${k.awaitingConfirmation} approved and waiting for the driver`
            : ''}
        </dd>
        <dt>Network agent polling for isolations</dt>
        <dd>
          {k.agentLastPoll ? agoWords(k.agentLastPoll) : 'not since the killswitch started'}
        </dd>
        {#if k.auditOutboxPending}
          <dt>Audit entries waiting for ClickHouse</dt>
          <dd class="warn-inline">
            {k.auditOutboxPending}{k.auditOutboxOldestSeconds
              ? `, the oldest for ${durationWords(k.auditOutboxOldestSeconds)}`
              : ''} (the killswitch's own audit log has them)
          </dd>
        {/if}
      {:else}
        <dt>Killswitch</dt>
        <dd class="error-inline">not known: its metrics could not be read</dd>
      {/if}
    </dl>
  </section>
{/if}

<style>
  section {
    margin-bottom: 2rem;
  }
  .updated {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
  }
  .refresh {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.2rem 0.7rem;
    cursor: pointer;
    font-size: 0.8125rem;
  }
  .refresh:disabled {
    opacity: 0.6;
    cursor: wait;
  }
  .findings {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    max-width: 56rem;
  }
  .finding {
    display: grid;
    grid-template-columns: 12rem 7rem 1fr;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    border-left: 3px solid var(--border);
    background: var(--bg-secondary);
    border-radius: 4px;
    font-size: 0.875rem;
  }
  .finding-ok {
    border-left-color: var(--success);
  }
  .finding-warn {
    border-left-color: var(--warning);
  }
  .finding-fail {
    border-left-color: var(--danger);
  }
  .finding-fail .verdict {
    color: var(--danger);
    font-weight: 600;
  }
  .finding-warn .verdict {
    color: var(--warning);
  }
  .finding-label {
    font-weight: 600;
  }
  .verdict {
    color: var(--text-secondary);
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1.25rem;
    font-size: 0.875rem;
    max-width: 56rem;
    margin-bottom: 1rem;
  }
  .facts dt {
    color: var(--text-secondary);
  }
  .facts a {
    color: var(--accent);
  }
  .down {
    color: var(--danger);
    font-weight: 600;
  }
  .problem {
    max-width: 28rem;
  }
  .warn {
    color: var(--warning);
    max-width: 48rem;
    margin-bottom: 1rem;
  }
  .warn-inline {
    color: var(--warning);
  }
  .error-inline {
    color: var(--danger);
  }
</style>
