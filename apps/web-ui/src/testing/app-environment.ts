/**
 * Stand-in for SvelteKit's `$app/env` in unit tests (aliased in
 * vitest.config.ts): a running server, not a build.
 */
export const browser = false
export const building = false
export const dev = false
export const version = 'test'
