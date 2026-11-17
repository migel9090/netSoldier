<script lang="ts">
  import { page } from '$app/state'

  /** The second row of navigation under a section heading. */
  let { links, testid, label }: { links: [string, string][]; testid: string; label: string } =
    $props()
</script>

<nav class="subnav" data-testid={testid} aria-label={label}>
  {#each links as [href, text], i (href)}
    {#if i > 0}<span class="sep" aria-hidden="true">·</span>{/if}
    <a
      {href}
      class:current={page.url.pathname === href}
      aria-current={page.url.pathname === href ? 'page' : undefined}>{text}</a
    >
  {/each}
</nav>

<style>
  .subnav {
    display: block;
    margin: -1rem 0 1.5rem;
    padding: 0;
    background: none;
    border: none;
    font-size: 0.875rem;
  }
  .subnav a {
    color: var(--accent);
    text-decoration: none;
    border: none;
    padding: 0;
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
