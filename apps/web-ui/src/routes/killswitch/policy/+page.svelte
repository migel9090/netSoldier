<script lang="ts">
  import { onMount } from 'svelte'
  import { fetchAllowlist, fetchDevices, fetchPolicy } from '#lib/api.ts'
  import KillswitchNav from '#lib/components/KillswitchNav.svelte'
  import ModePanel from '#lib/components/ModePanel.svelte'
  import { actionTypeRows, policyRows, protectedRows } from '#lib/policy.ts'
  import type { Allowlist, Device, KillswitchPolicy } from '#lib/types.ts'

  /**
   * The killswitch policy as the controller runs it (GET /policy and
   * GET /allowlist): when it proposes a block, when it may block on its own
   * and whether it does, with which enforcement, and whom it never touches.
   */

  let policy = $state<KillswitchPolicy | null>(null)
  let policyError = $state('')
  let allowlist = $state<Allowlist | null>(null)
  let allowlistError = $state('')
  let devices: Device[] = $state([])
  let loading = $state(true)

  let rows = $derived(policy ? policyRows(policy) : [])
  let types = $derived(policy ? actionTypeRows(policy) : [])
  let protectedList = $derived(allowlist ? protectedRows(allowlist, devices) : [])
  let rejected = $derived(policy?.rejected_protection_entries ?? 0)

  async function load() {
    const [p, a] = await Promise.allSettled([fetchPolicy(), fetchAllowlist()])
    if (p.status === 'fulfilled') {
      policy = p.value
      policyError = ''
    } else {
      policyError = p.reason instanceof Error ? p.reason.message : 'could not be read'
    }
    if (a.status === 'fulfilled') {
      allowlist = a.value
      allowlistError = ''
    } else {
      allowlistError = a.reason instanceof Error ? a.reason.message : 'could not be read'
    }
  }

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    // Best effort: names for the protected devices the inventory knows.
    fetchDevices()
      .then((d) => (devices = d.devices))
      .catch(() => {})
    const interval = setInterval(() => void load(), 30_000)
    return () => clearInterval(interval)
  })
</script>

<h1>Killswitch Policy</h1>
<KillswitchNav />

<ModePanel {policy} error={policyError} />

{#if loading}
  <p class="loading">Loading…</p>
{:else}
  <section aria-labelledby="when-heading">
    <h2 id="when-heading">When the killswitch acts</h2>
    {#if policyError}
      <p class="error" data-testid="policy-error">Killswitch policy: {policyError}</p>
    {:else if policy}
      <table data-testid="policy-rows">
        <tbody>
          {#each rows as r (r.key)}
            <tr data-key={r.key}>
              <th scope="row">{r.label}</th>
              <td data-testid="policy-value">{r.value}</td>
              <td class="detail">{r.detail}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>

  <section aria-labelledby="types-heading">
    <h2 id="types-heading">Enforcement types</h2>
    {#if policy && !policyError}
      <p class="muted lead">
        What an operator can choose when approving, as the controller reports it now. A type that is
        not available says why; the automatic path only ever uses the DNS sinkhole.
      </p>
      <table data-testid="action-types">
        <thead>
          <tr>
            <th scope="col">Type</th>
            <th scope="col">Available</th>
            <th scope="col">Why not</th>
          </tr>
        </thead>
        <tbody>
          {#each types as t (t.type)}
            <tr data-type={t.type} data-available={String(t.available)}>
              <td
                >{t.name}{#if t.isDefault}<span class="secondary">proposals use this</span>{/if}</td
              >
              <td>{t.available ? 'yes' : 'no'}</td>
              <td class="reason" data-testid="unavailable-reason">{t.reason || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else if policyError}
      <p class="error">Not known: the policy could not be read.</p>
    {/if}
  </section>

  <section aria-labelledby="protected-heading">
    <h2 id="protected-heading">Never enforced against</h2>
    <p class="muted lead">
      Detections about these devices are recorded but never proposed or blocked. The default gateway
      (GATEWAY_IP / GATEWAY_MAC), the killswitch's own addresses and the DNS server it enforces
      through are protected as well, on the controller's own account; they are not listed here.
    </p>
    {#if rejected > 0}
      <p class="warn" data-testid="rejected-entries">
        {rejected} protection entr{rejected === 1 ? 'y was' : 'ies were'} refused when the killswitch
        started (malformed) and protect nothing. Its log names them.
      </p>
    {/if}
    {#if allowlistError}
      <p class="error" data-testid="allowlist-error">{allowlistError}</p>
    {:else if allowlist && protectedList.length === 0}
      <p class="empty" data-testid="protected-empty">
        The list is empty: no device of the household is protected beyond the infrastructure above.
      </p>
    {:else if allowlist}
      <table data-testid="protected-table">
        <thead>
          <tr>
            <th scope="col">Kind</th>
            <th scope="col">Address</th>
            <th scope="col">Device</th>
          </tr>
        </thead>
        <tbody>
          {#each protectedList as p (`${p.kind}|${p.value}`)}
            <tr data-value={p.value}>
              <td>{p.kind}</td>
              <td class="mono">{p.value}</td>
              <td>{p.name || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}

<style>
  section {
    margin-bottom: 2rem;
  }
  th[scope='row'] {
    text-transform: none;
    letter-spacing: normal;
    font-size: 0.8125rem;
    color: var(--text-primary);
    width: 16rem;
    border-top: 1px solid var(--border);
  }
  .detail {
    color: var(--text-secondary);
  }
  .lead {
    max-width: 48rem;
    margin-bottom: 0.75rem;
  }
  .reason {
    max-width: 28rem;
  }
  .warn {
    color: var(--warning);
    max-width: 48rem;
    margin-bottom: 0.75rem;
  }
</style>
