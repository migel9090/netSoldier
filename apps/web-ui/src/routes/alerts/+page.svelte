<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchAlerts, formatTime } from '$lib/api';
	import type { Alert } from '$lib/types';

	let alerts: Alert[] = $state([]);
	let loading: boolean = $state(true);
	let error: string = $state('');

	async function load() {
		try {
			alerts = await fetchAlerts();
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load alerts';
		}
	}

	onMount(async () => {
		await load();
		loading = false;
		const interval = setInterval(load, 30_000);
		return () => clearInterval(interval);
	});
</script>

<h1>Alerts</h1>

{#if loading}
	<p class="loading">Loading…</p>
{:else if error}
	<p class="error">{error}</p>
{:else if alerts.length === 0}
	<p class="empty">No alerts detected.</p>
{:else}
	<table>
		<thead>
			<tr>
				<th>ID</th>
				<th>Time</th>
				<th>Domain</th>
				<th>Client IP</th>
				<th>Type</th>
				<th>Matched IoC</th>
				<th>Severity</th>
				<th>Source</th>
			</tr>
		</thead>
		<tbody>
			{#each alerts as a}
				<tr>
					<td class="mono">{a.id}</td>
					<td>{formatTime(a.timestamp)}</td>
					<td class="mono">{a.domain}</td>
					<td class="mono">{a.client_ip}</td>
					<td>{a.query_type}</td>
					<td class="mono">{a.matched_ioc}</td>
					<td><span class="badge badge-{a.severity}">{a.severity}</span></td>
					<td>{a.source}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}
