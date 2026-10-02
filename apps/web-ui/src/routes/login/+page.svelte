<script lang="ts">
  let password = $state('')
  let actor = $state('')
  let error = $state('')
  let busy = $state(false)

  async function submit(e: Event) {
    e.preventDefault()
    busy = true
    error = ''
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, actor }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        error = body.error ?? `Login failed (${res.status})`
        return
      }
      window.location.href = '/'
    } catch {
      error = 'Login request failed'
    } finally {
      busy = false
    }
  }
</script>

<h1>netSoldier</h1>
<p class="hint">
  Approving a killswitch action quarantines a device on this network. Sign in so every approval is
  attributable.
</p>

<form onsubmit={submit}>
  <label>
    Who are you?
    <input bind:value={actor} placeholder="household" autocomplete="username" />
  </label>
  <label>
    Password
    <!-- svelte-ignore a11y_autofocus -->
    <input
      type="password"
      bind:value={password}
      autocomplete="current-password"
      autofocus
      required
    />
  </label>
  <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
</form>

{#if error}
  <p class="error">{error}</p>
{/if}

<style>
  form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    max-width: 20rem;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .hint {
    max-width: 40rem;
    opacity: 0.8;
  }
  .error {
    color: #c0392b;
  }
</style>
