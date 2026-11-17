<script lang="ts">
  import { onMount, tick } from 'svelte'
  import { page } from '$app/state'
  import {
    SUPPRESSION_DAYS,
    liftNote,
    liftQuestion,
    liftRequest,
    sortSuppressions,
    suppressionAnchor,
    suppressionDays,
    suppressionPeriod,
    type Note,
  } from '#lib/alerts.ts'
  import { fetchSuppressions, liftSuppression } from '#lib/api.ts'
  import AlertsNav from '#lib/components/AlertsNav.svelte'
  import SuppressionTable from '#lib/components/SuppressionTable.svelte'
  import type { Suppression } from '#lib/types.ts'

  /**
   * The false-positive verdicts in force (GET /feedback): what is silenced,
   * by whom, until when, and a way to end each one (POST /feedback/lift,
   * after a confirmation that says what lifting changes).
   */

  let suppressions: Suppression[] = $state([])
  let loading = $state(true)
  let error = $state('')
  let notes: (Note & { key: number })[] = $state([])
  let seq = 0
  let lifting: Set<string> = $state(new Set())

  let ttlDays = $derived(suppressionDays(suppressions))
  let target = $derived(page.url.hash.slice(1))
  let wide = $derived(suppressions.filter((s) => !s.client_ip).length)

  function note(n: Note) {
    notes = [{ ...n, key: ++seq }, ...notes].slice(0, 5)
  }

  async function load() {
    try {
      suppressions = sortSuppressions(await fetchSuppressions())
      error = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load suppressions'
    }
  }

  async function lift(s: Suppression) {
    if (!confirm(liftQuestion(s, suppressions))) return
    const anchor = suppressionAnchor(s)
    lifting = new Set(lifting).add(anchor)
    try {
      note(liftNote(s, await liftSuppression(liftRequest(s))))
    } catch (e) {
      note({
        tone: 'fail',
        text: e instanceof Error ? e.message : 'Failed to lift the suppression',
      })
    } finally {
      const next = new Set(lifting)
      next.delete(anchor)
      lifting = next
      await load()
    }
  }

  let scrolledTo = ''
  $effect(() => {
    const id = target
    if (!id || id === scrolledTo || loading || suppressions.length === 0) return
    void tick().then(() => {
      const el = document.getElementById(id)
      if (!el) return
      scrolledTo = id
      el.scrollIntoView({ block: 'center' })
    })
  })

  onMount(() => {
    void load().finally(() => {
      loading = false
    })
    const interval = setInterval(() => void load(), 30_000)
    return () => clearInterval(interval)
  })
</script>

<h1>Suppressions</h1>
<AlertsNav />

<p class="muted intro">
  A false-positive verdict (“Mark FP” on an alert) keeps detections of one indicator and signal from
  reaching the killswitch — on one device, or on every device when none is named — until it ends ({ttlDays ===
  null
    ? `by default ${SUPPRESSION_DAYS} days`
    : suppressionPeriod(ttlDays)} after it was made). Those detections are still recorded and listed on
  the alerts page, marked Silenced. Lifting a suppression ends it at once; it does not record the indicator
  as malicious.
</p>

{#if notes.length > 0}
  <ul class="notes" aria-live="polite">
    {#each notes as n (n.key)}
      <li class="note note-{n.tone}" data-testid="feedback-note">{n.text}</li>
    {/each}
  </ul>
{/if}

{#if loading}
  <p class="loading">Loading…</p>
{:else if error}
  <p class="error">{error}</p>
{:else if suppressions.length === 0}
  <p class="empty">Nothing is suppressed.</p>
{:else}
  <p class="muted count" data-testid="suppression-count">
    {suppressions.length} in force{wide > 0 ? `, ${wide} of them on every device` : ''}.
  </p>
  <SuppressionTable {suppressions} {target} onlift={lift} {lifting} />
{/if}

<style>
  .intro {
    max-width: 48rem;
    margin-bottom: 1rem;
  }
  .count {
    margin-bottom: 0.5rem;
  }
  .notes {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-bottom: 1rem;
  }
  .note {
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    border-left: 3px solid var(--success);
    background: var(--bg-secondary);
    font-size: 0.875rem;
  }
  .note-warn {
    border-left-color: var(--warning);
  }
  .note-fail {
    border-left-color: var(--danger);
    color: var(--danger);
  }
</style>
