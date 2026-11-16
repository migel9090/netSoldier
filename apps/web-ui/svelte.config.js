import adapter from '@sveltejs/adapter-node'
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte'

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    // SvelteKit boots the client from an inline script. Letting the framework
    // write the CSP gives that script a per-response nonce; a hand-written
    // `script-src 'self'` header blocked it and left every page blank.
    // Non-page responses get a stricter policy in hooks.server.ts.
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
  },
}

export default config
