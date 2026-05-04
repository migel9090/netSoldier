<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchAlerts, formatTime } from '$lib/api';
	import type { Alert } from '$lib/types';

	const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

	let allAlerts: Alert[] = $state([]);
	let loading: boolean = $state(true);
	let error: string = $state('');

	let sevFilter: Set<string> = $state(new Set(SEVERITIES));
	let deviceFilter: string = $state('');
	let sourceFilter: string = $state('');
	let timeFilter: string = $state('all');

	let filtered: Alert[] = $derived.by(() => {
		let result = allAlerts;

		if (sevFilter.size < SEVERITIES.length) {
			result = result.filter((a) => sevFilter.has(a.severity));
		}

		if (deviceFilter.trim()) {
			const q = deviceFilter.trim().toLowerCase();
			result = result.filter((a) => a.client_ip.toLowerCase().includes(q));
		}

		if (sourceFilter) {
			result = result.filter((a) => a.source === sourceFilter);
		}

		if (timeFilter !== 'all') {
			const hours = parseInt(timeFilter);
			const cutoff = Date.now() - hours * 3600_000;
			result = result.filter((a) => {
				const t = new Date(a.timestamp).getTime();
				return !isNaN(t) && t >= cutoff;
			});
		}

		return result;
	});

	let sources: string[] = $derived(
		[...new Set(allAlerts.map((a) => a.source).filter(Boolean))].sort()
	);

	function toggleSeverity(sev: string) {
		const next = new Set(sevFilter);
		if (next.has(sev)) {
			if (next.size > 1) next.delete(sev);
		} else {
			next.add(sev);
		}
		sevFilter = next;
	}

	function clearFilters() {
		sevFilter = new Set(SEVERITIES);
		deviceFilter = '';
		sourceFilter = '';
		timeFilter = 'all';
	}

	let hasActiveFilters: boolean = $derived(
		sevFilter.size < SEVERITIES.length || deviceFilter.trim() !== '' || sourceFilter !== '' || timeFilter !== 'all'
	);

	async function load() {
		try {
			allAlerts = await fetchAlerts();
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

<div class="alerts-header">
	<h1>Alerts</h1>
	<span class="alert-count">{filtered.length}{filtered.length !== allAlerts.length ? ` / ${allAlerts.length}` : ''}</span>
</div>

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
				placeholder="Filter by IP…"
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
	<p class="empty">{allAlerts.length === 0 ? 'No alerts detected.' : 'No alerts match the current filters.'}</p>
{:else}
	<table>
		<thead>
			<tr>
				<th>Time</th>
				<th>Severity</th>
				<th>Domain</th>
				<th>Client</th>
				<th>Matched IoC</th>
				<th>Threat</th>
				<th>MITRE</th>
				<th>Source</th>
			</tr>
		</thead>
		<tbody>
			{#each filtered as a}
				<tr>
					<td class="nowrap">{formatTime(a.timestamp)}</td>
					<td>
						<span class="badge badge-{a.severity}">{a.severity}</span>
						{#if a.confidence}<span class="confidence">{a.confidence}%</span>{/if}
					</td>
					<td class="mono truncate" title={a.domain}>{a.domain}</td>
					<td class="mono"><a href="/devices" class="ip-link">{a.client_ip}</a></td>
					<td class="mono truncate" title={a.matched_ioc}>{a.matched_ioc}</td>
					<td class="truncate">{a.threat || '—'}</td>
					<td class="truncate">
						{#if a.mitre_id}
							<span class="mitre" title={a.mitre_name}>{a.mitre_id}</span>
						{:else}
							—
						{/if}
					</td>
					<td>{a.source}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

{/if}

<style>
	.alerts-header {
		display: flex;
		align-items: baseline;
		gap: 0.75rem;
		margin-bottom: 1rem;
	}
	.alerts-header h1 { margin-bottom: 0; }
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
		transition: opacity 0.15s, background 0.15s;
	}
	.sev-btn.active { opacity: 1; }
	.sev-btn.sev-critical.active { background: rgba(248, 81, 73, 0.2); color: #f85149; border-color: #f85149; }
	.sev-btn.sev-high.active { background: rgba(248, 81, 73, 0.12); color: #f47067; border-color: #f47067; }
	.sev-btn.sev-medium.active { background: rgba(210, 153, 34, 0.15); color: var(--warning); border-color: var(--warning); }
	.sev-btn.sev-low.active { background: rgba(63, 185, 80, 0.12); color: var(--success); border-color: var(--success); }

	.filter-input, .filter-select {
		background: var(--bg-tertiary);
		color: var(--text-primary);
		border: 1px solid var(--border);
		border-radius: 4px;
		padding: 0.3rem 0.5rem;
		font-size: 0.8125rem;
		font-family: inherit;
	}
	.filter-input { width: 140px; }
	.filter-input::placeholder { color: var(--text-secondary); }

	.clear-btn {
		background: transparent;
		color: var(--accent);
		border: none;
		font-size: 0.8125rem;
		cursor: pointer;
		padding: 0.3rem 0;
		align-self: flex-end;
	}
	.clear-btn:hover { text-decoration: underline; }

	.nowrap { white-space: nowrap; }
	.confidence {
		font-size: 0.6875rem;
		color: var(--text-secondary);
		margin-left: 0.35rem;
	}
	.ip-link {
		color: var(--accent);
		text-decoration: none;
	}
	.ip-link:hover { text-decoration: underline; }
	.mitre {
		font-size: 0.75rem;
		font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace;
		color: var(--text-secondary);
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
