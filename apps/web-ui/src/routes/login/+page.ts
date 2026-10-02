// The login page must not be prerendered or data-loaded: it is reached
// unauthenticated and its only job is to post credentials.
export const ssr = true
export const prerender = false
