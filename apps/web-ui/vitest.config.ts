import { defineConfig } from 'vitest/config'
import { resolve } from 'node:path'

// `#lib/*` resolves through package.json "imports", as in the app. Two
// SvelteKit modules have no meaning outside a SvelteKit build and are
// replaced by stand-ins the tests control.
export default defineConfig({
  resolve: {
    alias: [
      // The server's environment (src/lib/server/env.ts wraps SvelteKit's
      // `$app/env/private`), replaced by a mutable object the tests fill in
      // (see src/testing/env.ts).
      { find: /^#lib\/server\/env\.ts$/, replacement: resolve('./src/testing/env.ts') },
      { find: /^\$app\/env$/, replacement: resolve('./src/testing/app-environment.ts') },
    ],
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
