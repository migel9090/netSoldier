<script lang="ts">
  import type { SignalRow } from '#lib/alerts.ts'

  /** The signals a detection is made of: one row each. */
  let { rows, composite = false }: { rows: SignalRow[]; composite?: boolean } = $props()
</script>

{#if rows.length === 0}
  <p class="muted" data-testid="signals-none">
    The detection engine sent no signals for this detection.
  </p>
{:else}
  {#if composite}
    <p class="muted" data-testid="signals-composite">
      A combined detection: {rows.length} signal{rows.length === 1 ? '' : 's'} about the same device agreed.
      Its confidence is the combination's; each signal keeps its own below.
    </p>
  {/if}
  <table class="signals" data-testid="signals-table">
    <thead>
      <tr>
        <th scope="col">Signal</th>
        <th scope="col">Confidence</th>
        <th scope="col">Indicator</th>
        <th scope="col">Source</th>
      </tr>
    </thead>
    <tbody>
      {#each rows as s, i (`${i}|${s.class}|${s.indicator}`)}
        <tr data-signal-class={s.class}>
          <td>{s.class}</td>
          <td>{s.confidence === null ? '—' : `${s.confidence}%`}</td>
          <td class="mono"
            >{s.indicator || '—'}{#if s.indicatorType}<span class="secondary"
                >{s.indicatorType}</span
              >{/if}</td
          >
          <td>{s.source || '—'}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<style>
  .signals {
    margin: 0.25rem 0;
  }
  .signals th,
  .signals td {
    padding: 0.35rem 0.75rem;
  }
</style>
