<script lang="ts">
	import { onMount } from 'svelte';
	import {
		fetchPendingActions,
		fetchActiveActions,
		approveAction,
		rejectAction,
		revertAction,
		formatTime,
		formatActionType
	} from '$lib/api';
	import type { EnforcementAction } from '$lib/types';

	let pending: EnforcementAction[] = $state([]);
	let active: EnforcementAction[] = $state([]);
	let loading: boolean = $state(true);
	let error: string = $state('');

	async function load() {
		try {
			[pending, active] = await Promise.all([
				fetchPendingActions(),
				fetchActiveActions()
			]);
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load actions';
		}
	}

	async function handleApprove(id: string) {
		if (!confirm(`Approve enforcement action ${id}? This will apply the block immediately.`)) return;
		try {
			await approveAction(id);
			await load();
		} catch (e) {
			alert(e instanceof Error ? e.message : 'Approve failed');
		}
	}

	async function handleReject(id: string) {
		const reason = prompt('Reason for rejection:', 'False positive');
		if (reason === null) return;
		try {
			await rejectAction(id, reason);
			await load();
		} catch (e) {
			alert(e instanceof Error ? e.message : 'Reject failed');
		}
	}

	async function handleRevert(id: string) {
		const reason = prompt('Reason for revert:', 'Manual revert');
		if (reason === null) return;
		try {
			await revertAction(id, reason);
			await load();
		} catch (e) {
			alert(e instanceof Error ? e.message : 'Revert failed');
		}
	}

	onMount(async () => {
		await load();
		loading = false;
		const interval = setInterval(load, 10_000);
		return () => clearInterval(interval);
	});
</script>

<h1>Killswitch</h1>

{#if loading}
	<p class="loading">Loading…</p>
{:else if error}
	<p class="error">{error}</p>
{:else}

<section>
	<h2>Pending Approvals ({pending.length})</h2>
	{#if pending.length === 0}
		<p class="empty">No pending actions.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th>ID</th>
					<th>Time</th>
					<th>Domain / IoC</th>
					<th>Target</th>
					<th>Action</th>
					<th>TTL</th>
					<th>Reason</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each pending as a}
					<tr>
						<td class="mono">{a.id}</td>
						<td>{formatTime(a.timestamp)}</td>
						<td class="mono">{a.blocked_domain || a.detection_id}</td>
						<td class="mono">{a.target_ip || a.target_mac}</td>
						<td><span class="badge badge-medium">{formatActionType(a.action_type)}</span></td>
						<td>{a.ttl_seconds ? `${Math.round(a.ttl_seconds / 60)}m` : '—'}</td>
						<td class="reason">{a.policy_rule}</td>
						<td class="actions-cell">
							<button class="btn-approve" onclick={() => handleApprove(a.id)}>Approve</button>
							<button class="btn-reject" onclick={() => handleReject(a.id)}>Reject</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</section>

<section>
	<h2>Active Blocks ({active.length})</h2>
	{#if active.length === 0}
		<p class="empty">No active enforcement.</p>
	{:else}
		<table>
			<thead>
				<tr>
					<th>ID</th>
					<th>Since</th>
					<th>Domain / IoC</th>
					<th>Target</th>
					<th>Action</th>
					<th>Expires</th>
					<th>Approved by</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each active as a}
					<tr>
						<td class="mono">{a.id}</td>
						<td>{formatTime(a.timestamp)}</td>
						<td class="mono">{a.blocked_domain || a.detection_id}</td>
						<td class="mono">{a.target_ip || a.target_mac}</td>
						<td><span class="badge badge-high">{formatActionType(a.action_type)}</span></td>
						<td>{a.expires_at ? formatTime(a.expires_at) : 'never'}</td>
						<td>{a.auto_approved ? 'auto-policy' : a.approved_by || '—'}</td>
						<td class="actions-cell">
							<button class="btn-revert" onclick={() => handleRevert(a.id)}>Revert</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</section>

{/if}

<style>
	section { margin-bottom: 2rem; }
	h2 { font-size: 1.1rem; margin-bottom: 0.5rem; }
	.actions-cell { white-space: nowrap; }
	.reason { max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
	button {
		padding: 0.25rem 0.75rem;
		border: none;
		border-radius: 4px;
		cursor: pointer;
		font-size: 0.85rem;
		font-weight: 600;
	}
	.btn-approve { background: var(--color-success, #238636); color: #fff; }
	.btn-approve:hover { filter: brightness(1.2); }
	.btn-reject { background: var(--color-danger, #da3633); color: #fff; margin-left: 0.25rem; }
	.btn-reject:hover { filter: brightness(1.2); }
	.btn-revert { background: var(--color-warning, #d29922); color: #fff; }
	.btn-revert:hover { filter: brightness(1.2); }
</style>
