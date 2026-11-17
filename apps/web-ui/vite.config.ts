import adapter from '@sveltejs/adapter-node'
import { sveltekit } from '@sveltejs/kit/vite'
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'

// No dev-server proxy: /api/* is served by hooks.server.ts in `vite dev` as
// in production, so development exercises the same session, CSRF and route
// allowlist checks. Configure it with the production env vars (see
// src/lib/server/config.ts; a local .env works).
//
// SvelteKit 3 takes its configuration here; svelte.config.js is no longer
// read. `paths.origin` is deliberately not set: the origin comes from the
// ORIGIN environment variable at run time (adapter-node reads it when
// paths.origin is unset), and the UI's own configuration check requires it.
export default defineConfig({
  plugins: [
    sveltekit({
      preprocess: vitePreprocess(),
      adapter: adapter(),
      // SvelteKit boots the client from an inline script. Letting the
      // framework write the CSP gives that script a per-response nonce; a
      // hand-written `script-src 'self'` header blocked it and left every
      // page blank. Non-page responses get a stricter policy in
      // hooks.server.ts.
      csp: {
        mode: 'auto',
        directives: {
          'default-src': ['self'],
          'script-src': ['self'],
          // Svelte writes inline style attributes (the topology map, transitions).
          'style-src': ['self', 'unsafe-inline'],
          'img-src': ['self', 'data:'],
          'connect-src': ['self'],
          'font-src': ['self'],
          'object-src': ['none'],
          'frame-ancestors': ['none'],
          'base-uri': ['none'],
          'form-action': ['self'],
        },
      },
    }),
  ],
})
