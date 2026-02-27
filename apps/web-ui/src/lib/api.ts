import type { Device, Alert } from './types';

export async function fetchDevices(): Promise<Device[]> {
	const res = await fetch('/api/devices');
	if (!res.ok) throw new Error(`Devices API: ${res.status}`);
	return res.json();
}

export async function fetchAlerts(): Promise<Alert[]> {
	const res = await fetch('/api/alerts');
	if (!res.ok) throw new Error(`Alerts API: ${res.status}`);
	return res.json();
}

export function formatTime(iso: string): string {
	if (!iso) return '—';
	try {
		return new Date(iso).toLocaleString();
	} catch {
		return iso;
	}
}
