<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchDevices, formatTime } from '$lib/api';
	import type { Device } from '$lib/types';

	let devices: Device[] = $state([]);
	let loading: boolean = $state(true);
	let error: string = $state('');

	async function load() {
		try {
			devices = await fetchDevices();
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load devices';
		}
	}

	onMount(async () => {
		await load();
		loading = false;
		const interval = setInterval(load, 30_000);
		return () => clearInterval(interval);
	});
</script>

<h1>Devices</h1>

{#if loading}
	<p class="loading">Loading…</p>
{:else if error}
	<p class="error">{error}</p>
{:else if devices.length === 0}
	<p class="empty">No devices discovered yet.</p>
{:else}
	<table>
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
			{#each devices as d}
				<tr>
					<td class="mono"><a href="/devices/{encodeURIComponent(d.mac)}">{d.mac}</a></td>
					<td class="mono">{d.ip || '—'}</td>
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
