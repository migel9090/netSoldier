<script lang="ts">
	import { page } from '$app/state';
	import type { Snippet } from 'svelte';
	import '../app.css';

	let { children }: { children: Snippet } = $props();
</script>

<nav>
	<a href="/" class="logo">netSoldier</a>
	<a href="/devices" class:active={page.url.pathname === '/devices'}>Devices</a>
	<a href="/alerts" class:active={page.url.pathname === '/alerts'}>Alerts</a>
	<a href="/killswitch" class:active={page.url.pathname === '/killswitch'}>Killswitch</a>
</nav>
<main>
	{@render children()}
</main>
