<script lang="ts">
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import {
		fetchDevice,
		fetchDeviceConnections,
		fetchDeviceDNS,
		fetchDeviceAlerts,
		formatTime
	} from '$lib/api';
	import type { Device, DeviceConnection, DeviceDNS, DeviceAlert } from '$lib/types';

	let device: Device | null = $state(null);
	let connections: DeviceConnection[] = $state([]);
	let dns: DeviceDNS[] = $state([]);
	let alerts: DeviceAlert[] = $state([]);
	let loading: boolean = $state(true);
	let error: string = $state('');

	function mac(): string {
		return decodeURIComponent(page.params.mac);
	}

	function protoName(p: number): string {
		switch (p) {
			case 1: return 'ICMP';
			case 6: return 'TCP';
			case 17: return 'UDP';
			default: return String(p);
		}
	}

	function formatBytes(b: number): string {
		if (b >= 1_000_000_000) return (b / 1_000_000_000).toFixed(1) + ' GB';
		if (b >= 1_000_000) return (b / 1_000_000).toFixed(1) + ' MB';
		if (b >= 1_000) return (b / 1_000).toFixed(1) + ' KB';
		return b + ' B';
	}

	onMount(async () => {
		try {
			const m = mac();
			const [d, c, dn, a] = await Promise.allSettled([
				fetchDevice(m),
				fetchDeviceConnections(m),
				fetchDeviceDNS(m),
				fetchDeviceAlerts(m)
			]);

			if (d.status === 'fulfilled') device = d.value;
			else error = 'Device not found';

			if (c.status === 'fulfilled') connections = c.value;
			if (dn.status === 'fulfilled') dns = dn.value;
			if (a.status === 'fulfilled') alerts = a.value;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load device';
		} finally {
			loading = false;
		}
	});
</script>

<p class="back"><a href="/devices">&larr; All Devices</a></p>

{#if loading}
	<p class="loading">Loading device…</p>
{:else if error}
	<p class="error">{error}</p>
{:else if device}

<h1>{device.hostname || device.mac}</h1>

<section class="info-grid">
	<div class="info-card">
		<span class="info-label">MAC Address</span>
		<span class="info-value mono">{device.mac}</span>
	</div>
	<div class="info-card">
		<span class="info-label">IP Address</span>
		<span class="info-value mono">{device.ip || '—'}</span>
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
	</div>
</section>

{#if device.labels && device.labels.length > 0}
	<div class="labels">
		{#each device.labels as label}
			<span class="label-tag">{label}</span>
		{/each}
	</div>
{/if}

{#if alerts.length > 0}
<section>
	<h2>Alerts ({alerts.length})</h2>
	<table>
		<thead>
			<tr>
				<th>Time</th>
				<th>Domain</th>
				<th>Matched IoC</th>
				<th>Severity</th>
				<th>Source</th>
			</tr>
		</thead>
		<tbody>
			{#each alerts as a}
				<tr>
					<td>{formatTime(a.timestamp)}</td>
					<td class="mono truncate">{a.domain}</td>
					<td class="mono truncate">{a.matched_ioc}</td>
					<td><span class="badge badge-{a.severity}">{a.severity}</span></td>
					<td>{a.source}</td>
				</tr>
			{/each}
		</tbody>
	</table>
</section>
{/if}

<section>
	<h2>Connection History ({connections.length})</h2>
	{#if connections.length === 0}
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
	{#if dns.length === 0}
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
						<td>{#if d.blocked}<span class="badge badge-high">blocked</span>{/if}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</section>

{/if}

<style>
	.back { margin-bottom: 1rem; }
	.back a {
		color: var(--accent);
		text-decoration: none;
		font-size: 0.875rem;
	}
	.back a:hover { text-decoration: underline; }

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

	section { margin-bottom: 2rem; }
</style>
