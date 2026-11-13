<script lang="ts">
  import { page } from '$app/state'
  import { signOut } from '$lib/api'
  import type { LayoutProps } from './$types'
  import '../app.css'

  let { children, data }: LayoutProps = $props()
  let signingOut = $state(false)
  let signOutError = $state('')

  async function handleSignOut() {
    signingOut = true
    signOutError = ''
    try {
      await signOut()
      window.location.href = '/login'
    } catch (e) {
      signOutError = e instanceof Error ? e.message : 'Sign-out failed'
      signingOut = false
    }
  }
</script>

<nav>
  <a href="/" class="logo">netSoldier</a>
  <a href="/devices" class:active={page.url.pathname === '/devices'}>Devices</a>
  <a href="/map" class:active={page.url.pathname === '/map'}>Map</a>
  <a href="/alerts" class:active={page.url.pathname === '/alerts'}>Alerts</a>
  <a href="/killswitch" class:active={page.url.pathname === '/killswitch'}>Killswitch</a>
  {#if data.actor}
    <span class="whoami">Signed in as <strong data-testid="actor">{data.actor}</strong></span>
    <button class="signout" onclick={handleSignOut} disabled={signingOut}>
      {signingOut ? 'Signing out…' : 'Sign out'}
    </button>
  {/if}
</nav>
{#if signOutError}
  <p class="error">{signOutError}</p>
{/if}
<main>
  {@render children()}
</main>
