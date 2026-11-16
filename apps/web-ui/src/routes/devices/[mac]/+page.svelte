<script lang="ts">
  import { page } from '$app/state'
  import { onMount } from 'svelte'
  import {
    ApiError,
    fetchDevice,
    fetchDeviceConnections,
    fetchDeviceDNS,
    fetchDeviceAlerts,
    formatTime,
    normaliseMac,
  } from '$lib/api'
  import { alertHeadline, alertObservedDomain } from '$lib/alerts'
  import {
    CONFLICTS_SHOWN,
    bindingWords,
    conflictCount,
    describeConflict,
    sourceName,
  } from '$lib/devices'
  import { newestFirst } from '$lib/order'
  import type { Device, DeviceConnection, DeviceDNS, DeviceAlert } from '$lib/types'

  let device: Device | null = $state(null)
  let connections: DeviceConnection[] = $state([])
  let dns: DeviceDNS[] = $state([])
  let alerts: DeviceAlert[] = $state([])
  let loading: boolean = $state(true)
  let error: string = $state('')
  // Per-section errors: a ClickHouse outage behind /connections must read as
  // "could not load", not as "no connection data".
  let connectionsError: string = $state('')
  let dnsError: string = $state('')
  let alertsError: string = $state('')

  function message(reason: unknown): string {
    return reason instanceof Error ? reason.message : 'request failed'
  }

  function protoName(p: number): string {
    switch (p) {
      case 1:
        return 'ICMP'
      case 6:
        return 'TCP'
      case 17:
        return 'UDP'
      default:
        return String(p)
    }
  }

  function formatBytes(b: number): string {
    if (b >= 1_000_000_000) return (b / 1_000_000_000).toFixed(1) + ' GB'
    if (b >= 1_000_000) return (b / 1_000_000).toFixed(1) + ' MB'
    if (b >= 1_000) return (b / 1_000).toFixed(1) + ' KB'
    return b + ' B'
  }

  onMount(async () => {
    try {
      // page.params is already decoded by SvelteKit.
      const m = normaliseMac(page.params.mac ?? '')
      if (!m) {
        error = `"${page.params.mac ?? ''}" is not a MAC address`
        return
      }
      const [d, c, dn, a] = await Promise.allSettled([
        fetchDevice(m),
        fetchDeviceConnections(m),
        fetchDeviceDNS(m),
        fetchDeviceAlerts(m),
      ])

      if (d.status === 'fulfilled') device = d.value
      else if (d.reason instanceof ApiError && d.reason.status === 404) error = 'Device not found'
      else error = message(d.reason)

      if (c.status === 'fulfilled') connections = c.value
      else connectionsError = message(c.reason)
      if (dn.status === 'fulfilled') dns = dn.value
      else dnsError = message(dn.reason)
      if (a.status === 'fulfilled') alerts = newestFirst(a.value)
      else alertsError = message(a.reason)
    } finally {
      loading = false
    }
  })
</script>

<p class="back"><a href="/devices">&larr; All Devices</a></p>

{#if loading}
  <p class="loading">Loading device…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if device}
  {@const conflicts = device.conflicts ?? []}
  {@const conflictTotal = conflictCount(device)}
  <!-- A single-device read attaches at most CONFLICTS_SHOWN, and counts only those. -->
  {@const atLeast = conflicts.length >= CONFLICTS_SHOWN ? 'at least ' : ''}
  <h1>{device.hostname || device.mac}</h1>

  {#if conflictTotal > 0}
    <section class="conflicts" data-testid="device-conflicts" role="alert">
      <h2>
        ⚠ Something on the network is claiming to be this device ({atLeast}{conflictTotal}
        {conflictTotal === 1 ? 'conflict' : 'conflicts'} in the last 24 h)
      </h2>
      <p>
        The inventory refused these claims because they contradict what it knows about this device.
        A device that forges its MAC or address can make a detection, or a block, land on the wrong
        device — check the claims before approving anything for this one.
      </p>
      <table>
        <thead>
          <tr>
            <th>What happened</th>
            <th>What it means</th>
            <th>Seen</th>
            <th>Times</th>
          </tr>
        </thead>
        <tbody>
          {#each conflicts as c, i (i)}
            {@const t = describeConflict(c, device.mac)}
            <tr data-testid="conflict" data-kind={c.kind}>
              <td>
                {t.what}
                {#if t.other && normaliseMac(t.other)}
                  <a class="mono" href="/devices/{encodeURIComponent(t.other)}">{t.other}</a>
                {/if}
              </td>
              <td>{t.meaning}</td>
              <td class="nowrap">
                {formatTime(c.first_seen)}
                {#if c.last_seen !== c.first_seen}<span class="secondary"
                    >last {formatTime(c.last_seen)}</span
                  >{/if}
              </td>
              <td class="mono">{c.count}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if conflicts.length >= CONFLICTS_SHOWN}
        <p class="muted">The inventory shows the {CONFLICTS_SHOWN} most recent conflicts.</p>
      {/if}
    </section>
  {/if}

  <section class="info-grid">
    <div class="info-card">
      <span class="info-label">MAC Address</span>
      <span class="info-value mono">{device.mac}</span>
      {#if device.randomized_mac}
        <span class="info-note">randomised (private) MAC address</span>
      {/if}
      {#if device.rotation_of && normaliseMac(device.rotation_of)}
        <span class="info-note"
          >probably the same device as <a
            class="mono"
            href="/devices/{encodeURIComponent(device.rotation_of)}">{device.rotation_of}</a
          > before a MAC change</span
        >
      {/if}
    </div>
    <div class="info-card" data-testid="ip-card">
      <span class="info-label">IP Address</span>
      <span class="info-value mono">{device.ip || '—'}</span>
      {#if device.ip}
        <span class="info-note"
          >{bindingWords(device)}; from {sourceName(device.ip_source)}{#if device.ip_since}, since {formatTime(
              device.ip_since,
            )}{/if}</span
        >
        {#if device.ip_confirmed_at}
          <span class="info-note">last confirmed {formatTime(device.ip_confirmed_at)}</span>
        {/if}
      {/if}
    </div>
    <div class="info-card">
      <span class="info-label">Hostname</span>
      <span class="info-value">{device.hostname || '—'}</span>
      {#if device.hostname}
        <span class="info-note">from {sourceName(device.hostname_source)}</span>
      {/if}
    </div>
    <div class="info-card">
      <span class="info-label">Vendor</span>
      <span class="info-value">{device.vendor || '—'}</span>
    </div>
    <div class="info-card">
      <span class="info-label">OS</span>
      <span class="info-value">{device.os || '—'}</span>
    </div>
    <div class="info-card">
      <span class="info-label">Device Type</span>
      <span class="info-value">{device.device_type || '—'}</span>
    </div>
    <div class="info-card">
      <span class="info-label">DHCP Fingerprint</span>
      <span class="info-value mono">{device.dhcp_fingerprint || '—'}</span>
    </div>
    <div class="info-card">
      <span class="info-label">First Seen</span>
      <span class="info-value">{formatTime(device.first_seen)}</span>
    </div>
    <div class="info-card">
      <span class="info-label">Last Seen</span>
      <span class="info-value">{formatTime(device.last_seen)}</span>
      {#if device.established}
        <span class="info-note">established: its name and profile are no longer replaced</span>
      {/if}
    </div>
  </section>

  {#if device.labels && device.labels.length > 0}
    <div class="labels">
      {#each device.labels as label}
        <span class="label-tag">{label}</span>
      {/each}
    </div>
  {/if}

  {#if alertsError}
    <section>
      <h2>Alerts</h2>
      <p class="error">{alertsError}</p>
    </section>
  {:else if alerts.length > 0}
    <section>
      <h2>Alerts ({alerts.length})</h2>
      <table data-testid="device-alerts">
        <thead>
          <tr>
            <th>Time</th>
            <th>Alert</th>
            <th>Matched IoC</th>
            <th>Severity</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {#each alerts as a}
            {@const observed = alertObservedDomain(a)}
            <tr>
              <td>{formatTime(a.timestamp)}</td>
              <td class="truncate" data-testid="alert-headline" title={alertHeadline(a)}>
                {alertHeadline(a)}
                {#if observed}<span class="secondary mono">{observed}</span>{/if}
              </td>
              <td class="mono truncate">{a.matched_ioc || '—'}</td>
              <td><span class="badge badge-{a.severity}">{a.severity}</span></td>
              <td>{a.source || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}

  <section>
    <h2>Connection History ({connections.length})</h2>
    {#if connectionsError}
      <p class="error">{connectionsError}</p>
    {:else if connections.length === 0}
      <p class="empty">No connection data available.</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Destination</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>In</th>
            <th>Out</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>
          {#each connections as c}
            <tr>
              <td>{formatTime(c.timestamp)}</td>
              <td class="mono truncate" title={c.dst_ip}>{c.dst_domain || c.dst_ip}</td>
              <td class="mono">{c.dst_port}</td>
              <td>{protoName(c.protocol)}</td>
              <td class="mono">{formatBytes(c.bytes_in)}</td>
              <td class="mono">{formatBytes(c.bytes_out)}</td>
              <td>{c.duration_ms ? (c.duration_ms / 1000).toFixed(1) + 's' : '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section>
    <h2>DNS Queries ({dns.length})</h2>
    {#if dnsError}
      <p class="error">{dnsError}</p>
    {:else if dns.length === 0}
      <p class="empty">No DNS data available.</p>
    {:else}
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Domain</th>
            <th>Type</th>
            <th>Answer</th>
            <th>Status</th>
            <th>ms</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each dns as d}
            <tr>
              <td>{formatTime(d.timestamp)}</td>
              <td class="mono truncate">{d.domain}</td>
              <td>{d.query_type}</td>
              <td class="mono truncate">{d.answer || '—'}</td>
              <td>{d.status}</td>
              <td class="mono">{d.response_ms}</td>
              <td
                >{#if d.blocked}<span class="badge badge-high">blocked</span>{/if}</td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}

<style>
  .back {
    margin-bottom: 1rem;
  }
  .back a {
    color: var(--accent);
    text-decoration: none;
    font-size: 0.875rem;
  }
  .back a:hover {
    text-decoration: underline;
  }

  .info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .info-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .info-label {
    font-size: 0.6875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
    font-weight: 600;
  }
  .info-value {
    font-size: 0.875rem;
    word-break: break-all;
  }
  .info-note {
    font-size: 0.75rem;
    color: var(--text-secondary);
  }
  .info-note a,
  .conflicts a {
    color: var(--accent);
    text-decoration: none;
  }

  .conflicts {
    border-left: 3px solid var(--danger);
    padding-left: 1rem;
  }
  .conflicts h2 {
    color: var(--danger);
    margin-top: 0;
  }
  .conflicts p {
    max-width: 48rem;
    margin-bottom: 0.75rem;
  }
  .nowrap {
    white-space: nowrap;
  }

  .labels {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
  }
  .label-tag {
    background: rgba(88, 166, 255, 0.15);
    color: var(--accent);
    padding: 0.125rem 0.625rem;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  section {
    margin-bottom: 2rem;
  }
</style>
