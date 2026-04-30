<script lang="ts">
	import { onMount } from 'svelte';
	import { fetchTopology } from '$lib/api';
	import type { TopologyNode, TopologyEdge } from '$lib/types';

	let loading: boolean = $state(true);
	let error: string = $state('');
	let hours: number = $state(1);

	interface SimNode extends TopologyNode {
		x: number;
		y: number;
		vx: number;
		vy: number;
		radius: number;
	}

	let simNodes: SimNode[] = $state([]);
	let edges: TopologyEdge[] = $state([]);
	let viewBox: string = $state('-400 -300 800 600');
	let hoveredNode: SimNode | null = $state(null);
	let animFrame = 0;
	let tickCount = 0;

	let panX = $state(0);
	let panY = $state(0);
	let zoom = $state(1);
	let dragging: SimNode | null = null;
	let panning = false;
	let panStart = { x: 0, y: 0 };

	$effect(() => {
		viewBox = `${-400 * zoom + panX} ${-300 * zoom + panY} ${800 * zoom} ${600 * zoom}`;
	});

	async function load() {
		try {
			const data = await fetchTopology(hours);
			edges = data.edges ?? [];
			initSimulation(data.nodes ?? []);
			error = '';
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load topology';
		} finally {
			loading = false;
		}
	}

	function initSimulation(nodes: TopologyNode[]) {
		cancelAnimationFrame(animFrame);
		tickCount = 0;

		const count = nodes.length || 1;
		simNodes = nodes.map((n, i) => {
			const angle = (2 * Math.PI * i) / count;
			const r = Math.min(200, count * 15);
			return {
				...n,
				x: Math.cos(angle) * r,
				y: Math.sin(angle) * r,
				vx: 0,
				vy: 0,
				radius: nodeRadius(n.connection_count)
			};
		});

		if (simNodes.length > 0) {
			animate();
		}
	}

	function nodeRadius(conns: number): number {
		return Math.max(6, Math.min(24, 4 + Math.log2(conns + 1) * 4));
	}

	function animate() {
		tick();
		tickCount++;
		if (tickCount < 400) {
			animFrame = requestAnimationFrame(animate);
		}
	}

	function tick() {
		const nodeMap = new Map<string, SimNode>();
		for (const n of simNodes) nodeMap.set(n.id, n);

		for (let i = 0; i < simNodes.length; i++) {
			for (let j = i + 1; j < simNodes.length; j++) {
				const a = simNodes[i];
				const b = simNodes[j];
				const dx = b.x - a.x;
				const dy = b.y - a.y;
				const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
				const force = 800 / (dist * dist);
				const fx = (dx / dist) * force;
				const fy = (dy / dist) * force;
				a.vx -= fx;
				a.vy -= fy;
				b.vx += fx;
				b.vy += fy;
			}
		}

		for (const e of edges) {
			const s = nodeMap.get(e.source);
			const t = nodeMap.get(e.target);
			if (!s || !t) continue;
			const dx = t.x - s.x;
			const dy = t.y - s.y;
			const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
			const force = dist * 0.005;
			const fx = (dx / dist) * force;
			const fy = (dy / dist) * force;
			s.vx += fx;
			s.vy += fy;
			t.vx -= fx;
			t.vy -= fy;
		}

		for (const n of simNodes) {
			if (dragging === n) continue;
			n.vx -= n.x * 0.008;
			n.vy -= n.y * 0.008;
			n.vx *= 0.85;
			n.vy *= 0.85;
			n.x += n.vx;
			n.y += n.vy;
		}
	}

	function nodeColor(n: SimNode): string {
		if (!n.is_local) return 'var(--text-secondary)';
		if (n.device_type === 'router' || n.device_type === 'gateway') return 'var(--success)';
		if (n.connection_count > 10) return 'var(--accent)';
		return 'var(--accent)';
	}

	function edgeOpacity(e: TopologyEdge): number {
		if (!e.total_bytes) return 0.15;
		return Math.min(0.7, 0.1 + Math.log10(e.total_bytes + 1) * 0.06);
	}

	function formatBytes(b: number): string {
		if (b >= 1_000_000_000) return (b / 1_000_000_000).toFixed(1) + ' GB';
		if (b >= 1_000_000) return (b / 1_000_000).toFixed(1) + ' MB';
		if (b >= 1_000) return (b / 1_000).toFixed(1) + ' KB';
		return b + ' B';
	}

	function findNode(id: string): SimNode | undefined {
		return simNodes.find((n) => n.id === id);
	}

	function handleWheel(e: WheelEvent) {
		e.preventDefault();
		const factor = e.deltaY > 0 ? 1.1 : 0.9;
		zoom = Math.max(0.2, Math.min(5, zoom * factor));
	}

	function handleMouseDown(e: MouseEvent) {
		if (e.button !== 0) return;
		panning = true;
		panStart = { x: e.clientX, y: e.clientY };
	}

	function handleMouseMove(e: MouseEvent) {
		if (dragging) {
			const svg = (e.currentTarget as SVGSVGElement);
			const rect = svg.getBoundingClientRect();
			const scaleX = (800 * zoom) / rect.width;
			const scaleY = (600 * zoom) / rect.height;
			dragging.x += e.movementX * scaleX;
			dragging.y += e.movementY * scaleY;
			dragging.vx = 0;
			dragging.vy = 0;
		} else if (panning) {
			const svg = (e.currentTarget as SVGSVGElement);
			const rect = svg.getBoundingClientRect();
			const scaleX = (800 * zoom) / rect.width;
			const scaleY = (600 * zoom) / rect.height;
			panX -= (e.clientX - panStart.x) * scaleX;
			panY -= (e.clientY - panStart.y) * scaleY;
			panStart = { x: e.clientX, y: e.clientY };
		}
	}

	function handleMouseUp() {
		dragging = null;
		panning = false;
	}

	function handleNodeMouseDown(e: MouseEvent, node: SimNode) {
		e.stopPropagation();
		dragging = node;
	}

	onMount(async () => {
		await load();
		const interval = setInterval(load, 30_000);
		return () => {
			clearInterval(interval);
			cancelAnimationFrame(animFrame);
		};
	});
</script>

<div class="map-header">
	<h1>Device Map</h1>
	<div class="controls">
		<label>
			Window:
			<select bind:value={hours} onchange={() => { loading = true; load(); }}>
				<option value={1}>1h</option>
				<option value={6}>6h</option>
				<option value={24}>24h</option>
				<option value={168}>7d</option>
			</select>
		</label>
		<span class="node-count">{simNodes.length} nodes, {edges.length} edges</span>
	</div>
</div>

{#if loading && simNodes.length === 0}
	<p class="loading">Loading topology…</p>
{:else if error}
	<p class="error">{error}</p>
{:else if simNodes.length === 0}
	<p class="empty">No devices discovered yet. Start the device-inventory service to populate the map.</p>
{:else}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<svg
		class="graph"
		{viewBox}
		onwheel={handleWheel}
		onmousedown={handleMouseDown}
		onmousemove={handleMouseMove}
		onmouseup={handleMouseUp}
		onmouseleave={handleMouseUp}
	>
		{#each edges as e}
			{@const src = findNode(e.source)}
			{@const tgt = findNode(e.target)}
			{#if src && tgt}
				<line
					x1={src.x}
					y1={src.y}
					x2={tgt.x}
					y2={tgt.y}
					stroke="var(--accent)"
					stroke-opacity={edgeOpacity(e)}
					stroke-width={Math.max(0.5, Math.min(3, Math.log10(e.total_bytes + 1) * 0.3))}
				/>
			{/if}
		{/each}

		{#each simNodes as node}
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<g
				transform="translate({node.x}, {node.y})"
				class="node"
				onmousedown={(e) => handleNodeMouseDown(e, node)}
				onmouseenter={() => (hoveredNode = node)}
				onmouseleave={() => (hoveredNode = null)}
			>
				<circle
					r={node.radius}
					fill={nodeColor(node)}
					stroke={hoveredNode === node ? 'var(--text-primary)' : 'none'}
					stroke-width="2"
					opacity={node.is_local ? 0.9 : 0.4}
				/>
				<text
					y={node.radius + 10}
					text-anchor="middle"
					class="node-label"
					fill={node.is_local ? 'var(--text-primary)' : 'var(--text-secondary)'}
				>
					{node.label.length > 16 ? node.label.slice(0, 14) + '…' : node.label}
				</text>
			</g>
		{/each}
	</svg>

	{#if hoveredNode}
		<div class="tooltip">
			<div class="tooltip-row"><strong>{hoveredNode.label}</strong></div>
			<div class="tooltip-row mono">{hoveredNode.ip}</div>
			{#if hoveredNode.mac}<div class="tooltip-row mono">{hoveredNode.mac}</div>{/if}
			{#if hoveredNode.vendor}<div class="tooltip-row">{hoveredNode.vendor}</div>{/if}
			{#if hoveredNode.device_type}<div class="tooltip-row">Type: {hoveredNode.device_type}</div>{/if}
			<div class="tooltip-row">Connections: {hoveredNode.connection_count}</div>
			<div class="tooltip-row">Traffic: {formatBytes(hoveredNode.total_bytes)}</div>
		</div>
	{/if}
{/if}

<style>
	.map-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: 1rem;
	}
	.map-header h1 { margin-bottom: 0; }
	.controls {
		display: flex;
		align-items: center;
		gap: 1rem;
		font-size: 0.875rem;
	}
	.controls select {
		background: var(--bg-tertiary);
		color: var(--text-primary);
		border: 1px solid var(--border);
		border-radius: 4px;
		padding: 0.25rem 0.5rem;
		font-size: 0.8125rem;
	}
	.node-count {
		color: var(--text-secondary);
		font-size: 0.8125rem;
	}
	.graph {
		width: 100%;
		height: calc(100vh - 140px);
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		border-radius: 6px;
		cursor: grab;
		user-select: none;
	}
	.graph:active { cursor: grabbing; }
	.node { cursor: pointer; }
	.node-label {
		font-size: 8px;
		font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace;
		pointer-events: none;
	}
	.tooltip {
		position: fixed;
		bottom: 2rem;
		right: 2rem;
		background: var(--bg-tertiary);
		border: 1px solid var(--border);
		border-radius: 6px;
		padding: 0.75rem 1rem;
		font-size: 0.8125rem;
		min-width: 180px;
		pointer-events: none;
		z-index: 10;
	}
	.tooltip-row {
		line-height: 1.6;
	}
</style>
