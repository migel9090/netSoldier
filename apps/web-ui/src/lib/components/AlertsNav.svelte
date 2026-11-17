<script lang="ts">
  import SubNav from './SubNav.svelte'

  const links: [string, string][] = [
    ['/alerts', 'Alerts'],
    ['/suppressions', 'Suppressions'],
  ]
</script>

<SubNav {links} testid="alerts-nav" label="Alerts" />
