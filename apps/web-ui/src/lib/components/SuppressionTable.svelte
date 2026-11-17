<script lang="ts">
  import { SUPPRESSION_DAYS, suppressionAnchor, suppressionEnds } from '#lib/alerts.ts'
  import { formatTime, formatTimeLeft } from '#lib/api.ts'
  import type { Suppression } from '#lib/types.ts'

  /**
   * The suppressions in force (GET /feedback), newest first, each with when
   * it ends (`expires_at`) and a Lift button. Shared by the alerts page and
   * the suppressions page; lifting itself is the page's (it confirms first).
   */
  let {
    suppressions,
    target = '',
    onlift,
    lifting = new Set<string>(),
  }: {
    suppressions: Suppression[]
    /** The anchor in the URL's hash, highlighted. */
    target?: string
    onlift: (s: Suppression) => void
    /** Anchors of suppressions being lifted right now. */
    lifting?: Set<string>
  } = $props()
</script>

<table data-testid="suppressions-table">
  <thead>
    <tr>
      <th scope="col">Indicator</th>
      <th scope="col">Signal</th>
      <th scope="col">Device</th>
      <th scope="col">Marked by</th>
      <th scope="col">Marked</th>
      <th scope="col">Ends</th>
      <th scope="col">Reason</th>
      <th scope="col"><span class="visually-hidden">Lift</span></th>
    </tr>
  </thead>
  <tbody>
    {#each suppressions as s (`${s.matched_ioc}|${s.client_ip ?? ''}|${s.signal_class}`)}
      {@const anchor = suppressionAnchor(s)}
      {@const end = suppressionEnds(s)}
      <tr id={anchor} data-ioc={s.matched_ioc} class:targeted={target === anchor}>
        <td class="mono truncate" title={s.matched_ioc}>{s.matched_ioc}</td>
        <td>{s.signal_class}</td>
        <td class="mono">{s.client_ip || 'every device'}</td>
        <td>{s.analyst || '—'}</td>
        <td class="nowrap">{formatTime(s.timestamp)}</td>
        <td class="nowrap" data-testid="suppression-ends">
          {#if end}
            {end.estimated ? `about ${formatTime(end.at)}` : formatTime(end.at)}
            <span class="secondary"
              >{end.estimated
                ? `estimated: the engine did not say; ${SUPPRESSION_DAYS} days is its default`
                : formatTimeLeft(end.at)}</span
            >
          {:else}
            —
          {/if}
        </td>
        <td class="truncate" title={s.reason}>{s.reason || '—'}</td>
        <td>
          <button
            class="fp-btn"
            disabled={lifting.has(anchor)}
            aria-label="Lift the suppression of {s.matched_ioc} ({s.signal_class}) on {s.client_ip ||
              'every device'}"
            onclick={() => onlift(s)}>Lift</button
          >
        </td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  .nowrap {
    white-space: nowrap;
  }
  .fp-btn {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.6875rem;
    padding: 0.2rem 0.5rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .fp-btn:hover {
    color: var(--warning);
    border-color: var(--warning);
  }
  .fp-btn:disabled {
    opacity: 0.5;
    cursor: wait;
  }
  tr.targeted td,
  tr.targeted:hover td {
    background: rgba(88, 166, 255, 0.12);
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
