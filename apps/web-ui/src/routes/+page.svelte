<script lang="ts">
  import { onMount } from 'svelte'
  import { alertClient, alertHeadline, alertObservedDomain } from '$lib/alerts'
  import { fetchDevices, fetchAlerts, formatTime } from '$lib/api'
  import { newestFirst } from '$lib/order'
  import type { Alert } from '$lib/types'

  // The detection engine reports no total; the count is of this many at most.
  const ALERT_COUNT_LIMIT = 1000

  let deviceCount: number | null = $state(null)
  let alertCount: string | null = $state(null)
  let recentAlerts: Alert[] = $state([])
  let errors: string[] = $state([])
  let loading: boolean = $state(true)

  onMount(async () => {
    // A backend outage is an error on the card, not a zero: "0 alerts" from
    // a detection engine that is down reads as "all quiet".
    const [devices, alerts] = await Promise.allSettled([
      fetchDevices(),
      fetchAlerts(ALERT_COUNT_LIMIT),
    ])
    const problems: string[] = []
    if (devices.status === 'fulfilled') deviceCount = devices.value.total
    else problems.push(message(devices.reason))
    if (alerts.status === 'fulfilled') {
      const n = alerts.value.length
      alertCount = n >= ALERT_COUNT_LIMIT ? `${ALERT_COUNT_LIMIT}+` : String(n)
      // Newest first already; sorted anyway so the order never depends on it.
      recentAlerts = newestFirst(alerts.value).slice(0, 5)
    } else {
      problems.push(message(alerts.reason))
    }
    errors = problems
    loading = false
  })

  function message(e: unknown): string {
    return e instanceof Error ? e.message : 'request failed'
  }
</script>

<h1>Dashboard</h1>

{#if loading}
  <p class="loading">Loading…</p>
{:else}
  {#each errors as e}
    <p class="error" data-testid="dashboard-error">{e}</p>
  {/each}

  <div class="stats">
    <div class="stat-card">
      <span class="stat-value" data-testid="device-count">{deviceCount ?? '—'}</span>
      <span class="stat-label">Devices discovered</span>
    </div>
    <div class="stat-card">
      <span class="stat-value" data-testid="alert-count">{alertCount ?? '—'}</span>
      <span class="stat-label">Detection alerts</span>
    </div>
  </div>

  {#if recentAlerts.length > 0}
    <h2>Recent Alerts</h2>
    <table data-testid="recent-alerts">
      <thead>
        <tr>
          <th>Time</th>
          <th>Alert</th>
          <th>Client</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody>
        {#each recentAlerts as a}
          {@const client = alertClient(a)}
          {@const observed = alertObservedDomain(a)}
          <tr>
            <td>{formatTime(a.timestamp)}</td>
            <td data-testid="alert-headline">
              {alertHeadline(a)}
              {#if observed}<span class="secondary mono">{observed}</span>{/if}
            </td>
            <td data-testid="alert-client">
              {client.name || client.ip || client.mac || '—'}
              {#if client.name && (client.ip || client.mac)}
                <span class="secondary mono">{client.ip || client.mac}</span>
              {/if}
            </td>
            <td><span class="badge badge-{a.severity}">{a.severity}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
{/if}
