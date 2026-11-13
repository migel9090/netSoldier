import { defineConfig } from 'vitest/config'
import { resolve } from 'node:path'

export default defineConfig({
  resolve: {
    alias: {
      $lib: resolve('./src/lib'),
      // SvelteKit's virtual env module, replaced by a mutable object the
      // tests fill in (see src/testing/env.ts).
      '$env/dynamic/private': resolve('./src/testing/env.ts'),
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
