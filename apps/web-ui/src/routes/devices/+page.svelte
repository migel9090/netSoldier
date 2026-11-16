<script lang="ts">
  import { onMount } from 'svelte'
  import { fetchDevices, formatTime } from '$lib/api'
  import { bindingWords, conflictCount, sourceName } from '$lib/devices'
  import type { Device } from '$lib/types'

  let devices: Device[] = $state([])
  let total: number = $state(0)
  let loading: boolean = $state(true)
  let error: string = $state('')

  let withConflicts = $derived(devices.filter((d) => conflictCount(d) > 0).length)

  async function load() {
    try {
      const page = await fetchDevices()
      devices = page.devices
      total = page.total
      error = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load devices'
    }
  }

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    const interval = setInterval(load, 30_000)
    return () => clearInterval(interval)
  })
</script>

<h1>Devices</h1>

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if devices.length === 0}
  <p class="empty">No devices discovered yet.</p>
{:else}
  {#if withConflicts > 0}
    <p class="conflict-note" data-testid="conflict-note">
      ⚠ {withConflicts}
      {withConflicts === 1 ? 'device has' : 'devices have'} open conflicts: something on the network is
      claiming to be {withConflicts === 1 ? 'it' : 'one of them'}. Open the device to see what.
    </p>
  {/if}
  {#if total > devices.length}
    <p class="muted" data-testid="device-total">
      Showing {devices.length} of {total} devices: labelled, long-known and active devices first.
    </p>
  {/if}
  <table data-testid="device-table">
    <thead>
      <tr>
        <th>MAC</th>
        <th>IP</th>
        <th>Hostname</th>
        <th>DHCP Fingerprint</th>
        <th>Vendor Class</th>
        <th>First Seen</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
      {#each devices as d (d.mac)}
        {@const conflicts = conflictCount(d)}
        <tr data-mac={d.mac} class:conflicted={conflicts > 0}>
          <td class="mono">
            <a href="/devices/{encodeURIComponent(d.mac)}">{d.mac}</a>
            {#if conflicts > 0}
              <span
                class="badge badge-high"
                data-testid="conflict-badge"
                title="Something on the network is claiming to be this device"
                >⚠ {conflicts} {conflicts === 1 ? 'conflict' : 'conflicts'}</span
              >
            {/if}
          </td>
          <td
            class="mono"
            title={d.ip ? `${bindingWords(d)}, from ${sourceName(d.ip_source)}` : ''}
          >
            {d.ip || '—'}
            {#if d.ip && d.ip_state && d.ip_state !== 'live'}
              <span class="secondary" data-testid="ip-state">{d.ip_state}</span>
            {/if}
          </td>
          <td>{d.hostname || '—'}</td>
          <td class="mono truncate" title={d.dhcp_fingerprint}>{d.dhcp_fingerprint || '—'}</td>
          <td>{d.vendor_class || '—'}</td>
          <td>{formatTime(d.first_seen)}</td>
          <td>{formatTime(d.last_seen)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<style>
  .conflict-note {
    color: var(--danger);
    border-left: 3px solid var(--danger);
    padding: 0.5rem 0.75rem;
    margin-bottom: 1rem;
    background: var(--bg-secondary);
  }
  .muted {
    margin-bottom: 1rem;
  }
  tr.conflicted td:first-child {
    box-shadow: inset 3px 0 0 var(--danger);
  }
  td a {
    color: var(--accent);
    text-decoration: none;
  }
  td .badge {
    margin-left: 0.5rem;
    text-transform: none;
  }
</style>
