import type { Cookies, RequestEvent } from '@sveltejs/kit'
import type { Handle } from '@sveltejs/kit/hooks'

/**
 * A minimal stand-in for SvelteKit's request pipeline, for driving the whole
 * `handle` hook in unit tests.
 *
 * The one property that matters most is copied from SvelteKit's
 * runtime/server/respond.js: cookies set through `event.cookies` are written
 * to the response *inside `resolve()`* and nowhere else. A hook that answers
 * a request itself, without calling `resolve()`, sends no Set-Cookie — which
 * is exactly how sign-in was broken while the helper-level tests passed.
 *
 * `resolve()` dispatches /api endpoints to the real `+server.ts` modules and
 * answers every other path with a stand-in page carrying a nonce CSP, as
 * SvelteKit's renderer would.
 */

type Handler = (event: RequestEvent) => Response | Promise<Response>
export type Endpoints = Record<string, Partial<Record<string, Handler>>>

export const PAGE_CSP = "script-src 'self' 'nonce-test'"

interface SetCookie {
  value: string
  options: NonNullable<Parameters<Cookies['set']>[2]>
}

function serialize(name: string, value: string, o: SetCookie['options']): string {
  const parts = [`${name}=${encodeURIComponent(value)}`]
  if (o.maxAge !== undefined) parts.push(`Max-Age=${o.maxAge}`)
  if (o.path) parts.push(`Path=${o.path}`)
  if (o.httpOnly !== false) parts.push('HttpOnly')
  if (o.secure !== false) parts.push('Secure')
  if (o.sameSite) {
    const s = String(o.sameSite)
    parts.push(`SameSite=${s.charAt(0).toUpperCase()}${s.slice(1)}`)
  }
  return parts.join('; ')
}

function parseCookieHeader(header: string | null): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of (header ?? '').split(';')) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim())
  }
  return out
}

export interface InvokeOptions {
  /** The configured ORIGIN; adapter-node builds event.url from it. */
  origin: string
  clientAddress?: string
  isDataRequest?: boolean
}

export async function invokeHandle(
  handle: Handle,
  endpoints: Endpoints,
  request: Request,
  { origin, clientAddress = '192.168.1.50', isDataRequest = false }: InvokeOptions,
): Promise<Response> {
  const incoming = new URL(request.url)
  const url = new URL(incoming.pathname + incoming.search, origin)
  const requestCookies = parseCookieHeader(request.headers.get('cookie'))
  const setCookies = new Map<string, SetCookie>()

  const cookies = {
    get: (name: string) =>
      setCookies.has(name) ? setCookies.get(name)!.value : requestCookies[name],
    getAll: () => Object.entries(requestCookies).map(([name, value]) => ({ name, value })),
    set: (name: string, value: string, options: SetCookie['options']) => {
      if (!options?.path)
        throw new Error(
          'cookies.set without a path: SvelteKit 3 would default it to /, and the device cookie must stay on /api/login',
        )
      setCookies.set(name, { value, options })
    },
    delete: (name: string, options: SetCookie['options']) => {
      if (!options?.path)
        throw new Error('cookies.delete without a path: SvelteKit 3 would default it to /')
      setCookies.set(name, { value: '', options: { ...options, maxAge: 0 } })
    },
    serialize: (name: string, value: string, options: SetCookie['options']) =>
      serialize(name, value, options),
  } as unknown as Cookies

  const event = {
    request,
    url,
    cookies,
    locals: {},
    params: {},
    route: { id: url.pathname },
    platform: undefined,
    isDataRequest,
    isSubRequest: false,
    getClientAddress: () => clientAddress,
    setHeaders: () => {},
    fetch: globalThis.fetch,
  } as unknown as RequestEvent

  const resolve = async (ev: RequestEvent): Promise<Response> => {
    let response: Response
    const endpoint = endpoints[ev.url.pathname]
    if (endpoint) {
      const fn = endpoint[ev.request.method]
      response = fn
        ? await fn(ev)
        : new Response(`${ev.request.method} method not allowed`, {
            status: 405,
            headers: { Allow: Object.keys(endpoint).join(', ') },
          })
    } else {
      response = new Response('<!doctype html><title>page</title>', {
        headers: { 'Content-Type': 'text/html', 'Content-Security-Policy': PAGE_CSP },
      })
    }
    for (const [name, c] of setCookies) {
      response.headers.append('Set-Cookie', serialize(name, c.value, c.options))
    }
    return response
  }

  return handle({ event, resolve })
}

export interface ParsedCookie {
  name: string
  value: string
  attributes: Record<string, string | true>
}

export function parseSetCookie(header: string): ParsedCookie {
  const [pair, ...attrs] = header.split(';').map((s) => s.trim())
  const eq = pair.indexOf('=')
  const attributes: Record<string, string | true> = {}
  for (const a of attrs) {
    const i = a.indexOf('=')
    if (i < 0) attributes[a.toLowerCase()] = true
    else attributes[a.slice(0, i).toLowerCase()] = a.slice(i + 1)
  }
  return {
    name: pair.slice(0, eq),
    value: decodeURIComponent(pair.slice(eq + 1)),
    attributes,
  }
}

export interface BrowserRequest {
  method?: string
  headers?: Record<string, string>
  body?: string
  /** Defaults to the browser's own origin on non-GET requests; null sends none. */
  originHeader?: string | null
  clientAddress?: string
  isDataRequest?: boolean
}

/** Keeps a cookie jar across calls the way a browser on ORIGIN would. */
export class TestBrowser {
  readonly jar = new Map<string, string>()

  constructor(
    readonly handle: Handle,
    readonly endpoints: Endpoints,
    readonly origin: string,
  ) {}

  async fetch(path: string, req: BrowserRequest = {}): Promise<Response> {
    const method = req.method ?? 'GET'
    const headers = new Headers(req.headers)
    if (this.jar.size > 0) {
      headers.set(
        'Cookie',
        [...this.jar].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; '),
      )
    }
    const origin = req.originHeader === undefined ? this.origin : req.originHeader
    if (method !== 'GET' && method !== 'HEAD' && origin !== null) headers.set('Origin', origin)

    const request = new Request(new URL(path, this.origin), { method, headers, body: req.body })
    const res = await invokeHandle(this.handle, this.endpoints, request, {
      origin: this.origin,
      clientAddress: req.clientAddress,
      isDataRequest: req.isDataRequest,
    })
    for (const raw of res.headers.getSetCookie()) {
      const c = parseSetCookie(raw)
      if (c.attributes['max-age'] === '0' || c.value === '') this.jar.delete(c.name)
      else this.jar.set(c.name, c.value)
    }
    return res
  }

  /** Signs in through the real endpoint; returns the response. */
  signIn(password: string, actor = 'michal', clientAddress?: string): Promise<Response> {
    return this.fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, actor }),
      clientAddress,
    })
  }

  csrf(): string {
    return this.jar.get('netsoldier_csrf') ?? ''
  }
}
