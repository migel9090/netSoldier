/**
 * Stand-in for src/lib/server/env.ts (SvelteKit's `$app/env/private`) in
 * unit tests, aliased in vitest.config.ts. Tests assign to it; config is
 * read per request, so a change takes effect on the next call into the hook.
 */
export const env: Record<string, string | undefined> = {}
