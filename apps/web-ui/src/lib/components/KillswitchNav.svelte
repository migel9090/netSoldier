<script lang="ts">
  import { page } from '$app/state'

  const links: [string, string][] = [
    ['/killswitch', 'Approvals'],
    ['/killswitch/history', 'History'],
    ['/killswitch/audit', 'Audit log'],
  ]
</script>

<p class="subnav" data-testid="killswitch-nav">
  {#each links as [href, label], i}
    {#if i > 0}<span class="sep">·</span>{/if}
    <a {href} class:current={page.url.pathname === href}>{label}</a>
  {/each}
</p>

<style>
  .subnav {
    margin: -1rem 0 1.5rem;
    font-size: 0.875rem;
  }
  .subnav a {
    color: var(--accent);
    text-decoration: none;
  }
  .subnav a:hover {
    text-decoration: underline;
  }
  .subnav a.current {
    color: var(--text-primary);
    font-weight: 600;
  }
  .sep {
    color: var(--text-secondary);
    margin: 0 0.5rem;
  }
</style>
