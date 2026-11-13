import { sveltekit } from '@sveltejs/kit/vite'
import { defineConfig } from 'vite'

// No dev-server proxy: /api/* is served by hooks.server.ts in `vite dev` as
// in production, so development exercises the same session, CSRF and route
// allowlist checks. Configure it with the production env vars (see
// src/lib/server/config.ts; a local .env works).
export default defineConfig({
  plugins: [sveltekit()],
})
