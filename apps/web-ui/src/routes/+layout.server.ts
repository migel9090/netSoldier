import type { LayoutServerLoad } from './$types'

// Who is signed in, for the "Signed in as …" line in the navigation. The
// session itself never leaves the server: it is an HttpOnly cookie.
export const load: LayoutServerLoad = ({ locals }) => ({ actor: locals.actor ?? null })
