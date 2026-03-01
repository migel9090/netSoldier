import type { Handle } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';

export const handle: Handle = async ({ event, resolve }) => {
	const { pathname } = event.url;

	if (pathname === '/api/devices' || pathname === '/api/alerts') {
		return proxyAPI(pathname);
	}

	return resolve(event);
};

async function proxyAPI(pathname: string): Promise<Response> {
	const deviceInventoryURL = env.DEVICE_INVENTORY_URL || 'http://device-inventory:8081';
	const detectionEngineURL = env.DETECTION_ENGINE_URL || 'http://detection-engine:8080';

	const target =
		pathname === '/api/devices'
			? `${deviceInventoryURL}/devices`
			: `${detectionEngineURL}/alerts`;

	try {
		const res = await fetch(target);
		return new Response(res.body as ReadableStream, {
			status: res.status,
			headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' }
		});
	} catch {
		return new Response(JSON.stringify({ error: 'backend unavailable' }), {
			status: 502,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}
