<script lang="ts">
  import type { Snippet } from 'svelte'
  import { formatActionType } from '#lib/api.ts'
  import { autoBlockStatus } from '#lib/killswitch.ts'
  import { autoBlockSettingWords } from '#lib/policy.ts'
  import type { KillswitchPolicy } from '#lib/types.ts'

  /**
   * What mode the system is in, at the top of the health and policy pages.
   *
   * This is where every system-wide switch belongs: automatic blocking
   * today; the observation mode and the emergency stop the killswitch is
   * getting go in this panel too (their indicator in the list, their control
   * in `controls`), so an operator finds them in one place on both pages.
   */
  let {
    policy,
    error = '',
    controls,
  }: { policy: KillswitchPolicy | null; error?: string; controls?: Snippet } = $props()

  let auto = $derived(policy ? autoBlockStatus(policy) : null)
  let setting = $derived(policy ? autoBlockSettingWords(policy) : null)
</script>

<section class="mode" aria-labelledby="mode-heading" data-testid="mode">
  <h2 id="mode-heading">Mode</h2>
  {#if error}
    <p class="error-inline" data-testid="mode-error">
      The killswitch policy could not be read: {error}. The mode is unknown.
    </p>
  {:else if !policy}
    <p class="muted">Reading the killswitch policy…</p>
  {:else}
    <dl>
      <dt>Automatic blocking</dt>
      <dd data-testid="mode-auto-block" data-on={auto?.on === null ? undefined : String(auto?.on)}>
        {#if auto?.on === true}
          <strong class="on">in effect</strong> — a detection that meets every automatic condition is
          blocked by DNS sinkhole without waiting for anyone.
        {:else if auto?.on === false}
          <strong class="off">not in effect</strong> — nothing is blocked unless a person approves
          it.
          {#if auto.explanation}{auto.explanation}{/if}
          {#if auto.reason}
            <span class="secondary"
              >The killswitch says: <span class="mono" data-testid="mode-auto-block-reason"
                >{auto.reason}</span
              ></span
            >
          {/if}
        {:else}
          the killswitch does not say.
        {/if}
        {#if setting}<span class="secondary">Configured: {setting}.</span>{/if}
      </dd>
      <dt>Enforcement available</dt>
      <dd data-testid="mode-available">
        {policy.available_action_types.length > 0
          ? policy.available_action_types.map(formatActionType).join(', ')
          : 'none — nothing can be enforced right now'}
      </dd>
    </dl>
  {/if}
  {#if controls}
    <div class="controls" data-testid="mode-controls">{@render controls()}</div>
  {/if}
</section>

<style>
  .mode {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-bottom: 1.5rem;
    max-width: 56rem;
  }
  .mode h2 {
    margin: 0 0 0.5rem;
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1rem;
    font-size: 0.875rem;
  }
  dt {
    color: var(--text-secondary);
  }
  .on {
    color: var(--warning);
  }
  .off {
    color: var(--success);
  }
  .error-inline {
    color: var(--danger);
    font-size: 0.875rem;
  }
  .controls {
    margin-top: 0.75rem;
  }
</style>
