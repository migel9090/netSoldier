import { defineEnvVars } from '@sveltejs/kit/env'

/**
 * Every environment variable the web UI reads, for SvelteKit's
 * `$app/env/private` (server-only: nothing here reaches the browser).
 *
 * Each is optional as far as SvelteKit is concerned: the schema hands the
 * value on unchanged, undefined included, so an incomplete configuration
 * still starts the server. The UI validates the configuration as a whole
 * itself (src/lib/server/config.ts) and answers every request — /healthz
 * included — with a 503 that names what is wrong, instead of a process that
 * exits before it can say why.
 *
 * adapter-node reads its own variables (HOST, PORT, ORIGIN for the request
 * URL, ADDRESS_HEADER, XFF_DEPTH, SHUTDOWN_TIMEOUT, BODY_SIZE_LIMIT) from
 * the process environment directly; they are not declared here unless the
 * UI reads them too.
 */

const asIs = (value: string | undefined) => value

export const variables = defineEnvVars({
  SESSION_SECRET: {
    schema: asIs,
    description: 'Signs sessions and CSRF tokens: at least 32 random characters.',
  },
  WEB_UI_PASSWORD: {
    schema: asIs,
    description: 'The shared household password, at least 12 characters.',
  },
  ORIGIN: {
    schema: asIs,
    description: 'The exact origin people open in the browser, e.g. http://192.0.2.10:3000.',
  },
  KILLSWITCH_URL: { schema: asIs, description: 'Base URL of the killswitch-controller API.' },
  KILLSWITCH_API_KEY: { schema: asIs, description: 'The killswitch operator token.' },
  DEVICE_INVENTORY_URL: { schema: asIs, description: 'Base URL of the device-inventory API.' },
  DEVICE_API_KEY: { schema: asIs, description: 'The device-inventory API key.' },
  DETECTION_ENGINE_URL: { schema: asIs, description: 'Base URL of the detection-engine API.' },
  DETECTION_API_KEY: { schema: asIs, description: 'The detection-engine API key.' },
  THREAT_INTEL_URL: {
    schema: asIs,
    description:
      'Optional. Base URL of threat-intel-sync, read for the system status page (feeds, last sync).',
  },
  METRICS_ADDR: {
    schema: asIs,
    description: 'host:port of the separate /metrics listener, or "off" (default 0.0.0.0:9464).',
  },
})
