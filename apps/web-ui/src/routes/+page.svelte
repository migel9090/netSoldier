<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchDevices, fetchAlerts, formatTime } from '$lib/api';
	import type { Device, Alert } from '$lib/types';

	let deviceCount: number = $state(0);
	let alertCount: number = $state(0);
	let recentAlerts: Alert[] = $state([]);
	let loading: boolean = $state(true);

	onMount(async () => {
		try {
			const [devices, alerts] = await Promise.all([fetchDevices(), fetchAlerts()]);
			deviceCount = devices.length;
			alertCount = alerts.length;
			recentAlerts = alerts.slice(0, 5);
		} catch {
			/* dashboard degrades gracefully */
		} finally {
			loading = false;
		}
	});
</script>

<h1>Dashboard</h1>

{#if loading}
	<p class="loading">Loading…</p>
{:else}
	<div class="stats">
		<div class="stat-card">
			<span class="stat-value">{deviceCount}</span>
			<span class="stat-label">Devices discovered</span>
		</div>
		<div class="stat-card">
			<span class="stat-value">{alertCount}</span>
			<span class="stat-label">Detection alerts</span>
		</div>
	</div>

	{#if recentAlerts.length > 0}
		<h2>Recent Alerts</h2>
		<table>
			<thead>
				<tr>
					<th>Time</th>
					<th>Domain</th>
					<th>Client</th>
					<th>Severity</th>
				</tr>
			</thead>
			<tbody>
				{#each recentAlerts as a}
					<tr>
						<td>{formatTime(a.timestamp)}</td>
						<td class="mono">{a.domain}</td>
						<td class="mono">{a.client_ip}</td>
						<td><span class="badge badge-{a.severity}">{a.severity}</span></td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
{/if}
