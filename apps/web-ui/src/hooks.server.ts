import type { Handle } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';

export const handle: Handle = async ({ event, resolve }) => {
	const { pathname } = event.url;

	if (pathname === '/api/devices' || pathname.startsWith('/api/devices/') || pathname === '/api/topology') {
		return proxyDeviceInventory(pathname);
	}

	if (pathname === '/api/alerts' || pathname === '/api/feedback') {
		return proxyDetectionEngine(pathname, event.request);
	}

	if (pathname.startsWith('/api/killswitch/')) {
		return proxyKillswitch(pathname, event.request);
	}

	return resolve(event);
};

async function proxyDeviceInventory(pathname: string): Promise<Response> {
	const baseURL = env.DEVICE_INVENTORY_URL || 'http://device-inventory:8081';
	const backendPath = pathname.replace('/api/', '/');
	return proxyGET(`${baseURL}${backendPath}`, 'device-inventory');
}

async function proxyDetectionEngine(pathname: string, request?: Request): Promise<Response> {
	const baseURL = env.DETECTION_ENGINE_URL || 'http://detection-engine:8080';
	const backendPath = pathname.replace('/api/', '/');
	const target = `${baseURL}${backendPath}`;
	// POST /api/feedback (step 118) needs to forward the body; everything
	// else is a read.
	if (request && request.method !== 'GET') {
		return proxyForward(target, request, 'detection-engine');
	}
	return proxyGET(target, 'detection-engine');
}

async function proxyGET(target: string, service: string): Promise<Response> {
	try {
		const res = await fetch(target);
		return new Response(res.body as ReadableStream, {
			status: res.status,
			headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' }
		});
	} catch {
		return new Response(JSON.stringify({ error: `${service} unavailable` }), {
			status: 502,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}

async function proxyForward(target: string, request: Request, service: string): Promise<Response> {
	try {
		const body = await request.text();
		const res = await fetch(target, {
			method: request.method,
			headers: { 'Content-Type': 'application/json' },
			body
		});
		return new Response(res.body as ReadableStream, {
			status: res.status,
			headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' }
		});
	} catch {
		return new Response(JSON.stringify({ error: `${service} unavailable` }), {
			status: 502,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}

async function proxyKillswitch(pathname: string, request: Request): Promise<Response> {
	const ksURL = env.KILLSWITCH_URL || 'http://killswitch-controller:8084';
	const ksKey = env.KILLSWITCH_API_KEY || '';

	const subpath = pathname.replace('/api/killswitch', '/actions');
	const target = `${ksURL}${subpath}`;

	const headers: Record<string, string> = {
		'Content-Type': 'application/json'
	};
	if (ksKey) {
		headers['Authorization'] = `Bearer ${ksKey}`;
	}

	try {
		const body = request.method !== 'GET' ? await request.text() : undefined;
		const res = await fetch(target, {
			method: request.method,
			headers,
			body
		});
		return new Response(res.body as ReadableStream, {
			status: res.status,
			headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' }
		});
	} catch {
		return new Response(JSON.stringify({ error: 'killswitch-controller unavailable' }), {
			status: 502,
			headers: { 'Content-Type': 'application/json' }
		});
	}
}
