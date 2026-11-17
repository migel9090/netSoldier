<script lang="ts">
  import SubNav from './SubNav.svelte'

  const links: [string, string][] = [
    ['/killswitch', 'Approvals'],
    ['/killswitch/history', 'History'],
    ['/killswitch/audit', 'Audit log'],
    ['/killswitch/policy', 'Policy'],
  ]
</script>

<SubNav {links} testid="killswitch-nav" label="Killswitch" />
