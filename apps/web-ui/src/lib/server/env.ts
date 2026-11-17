import * as declared from '$app/env/private'

/**
 * The web UI's environment as SvelteKit read it at start-up: exactly the
 * variables src/env.ts declares, each a string or undefined. Read through
 * this one object so the configuration check (config.ts) sees all of them
 * at once, and so the unit tests can stand in for it (vitest.config.ts
 * aliases this module to src/testing/env.ts).
 */
export const env: Readonly<Record<string, string | undefined>> = declared
