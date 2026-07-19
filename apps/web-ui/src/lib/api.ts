import type { Device, Alert, EnforcementAction, TopologyData, DeviceConnection, DeviceDNS, DeviceAlert } from './types';

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

export async function fetchDevice(mac: string): Promise<Device> {
	const res = await fetch(`/api/devices/${encodeURIComponent(mac)}`);
	if (!res.ok) throw new Error(`Device API: ${res.status}`);
	return res.json();
}

export async function fetchDeviceConnections(mac: string): Promise<DeviceConnection[]> {
	const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/connections`);
	if (!res.ok) throw new Error(`Connections API: ${res.status}`);
	return (await res.json()) ?? [];
}

export async function fetchDeviceDNS(mac: string): Promise<DeviceDNS[]> {
	const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/dns`);
	if (!res.ok) throw new Error(`DNS API: ${res.status}`);
	return (await res.json()) ?? [];
}

export async function fetchDeviceAlerts(mac: string): Promise<DeviceAlert[]> {
	const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/alerts`);
	if (!res.ok) throw new Error(`Alerts API: ${res.status}`);
	return (await res.json()) ?? [];
}

export async function fetchTopology(hours = 1): Promise<TopologyData> {
	const res = await fetch(`/api/topology?hours=${hours}`);
	if (!res.ok) throw new Error(`Topology API: ${res.status}`);
	return res.json();
}

export async function fetchPendingActions(): Promise<EnforcementAction[]> {
	const res = await fetch('/api/killswitch/pending');
	if (!res.ok) throw new Error(`Killswitch API: ${res.status}`);
	return (await res.json()) ?? [];
}

export async function fetchActiveActions(): Promise<EnforcementAction[]> {
	const res = await fetch('/api/killswitch/active');
	if (!res.ok) throw new Error(`Killswitch API: ${res.status}`);
	return (await res.json()) ?? [];
}

export async function approveAction(id: string): Promise<EnforcementAction> {
	const res = await fetch(`/api/killswitch/${id}/approve`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ approved_by: 'web-ui' })
	});
	if (!res.ok) throw new Error(`Approve failed: ${res.status}`);
	return res.json();
}

export async function rejectAction(id: string, reason: string): Promise<EnforcementAction> {
	const res = await fetch(`/api/killswitch/${id}/reject`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) throw new Error(`Reject failed: ${res.status}`);
	return res.json();
}

export async function revertAction(id: string, reason: string): Promise<EnforcementAction> {
	const res = await fetch(`/api/killswitch/${id}/revert`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) throw new Error(`Revert failed: ${res.status}`);
	return res.json();
}

export interface FeedbackVerdict {
	alert_id?: string;
	matched_ioc: string;
	client_ip?: string;
	verdict: 'false_positive' | 'confirmed';
	reason?: string;
	analyst?: string;
}

export async function submitFeedback(v: FeedbackVerdict): Promise<void> {
	const res = await fetch('/api/feedback', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ analyst: 'web-ui', ...v })
	});
	if (!res.ok) throw new Error(`Feedback failed: ${res.status}`);
}

export function formatTime(iso: string): string {
	if (!iso) return '—';
	try {
		return new Date(iso).toLocaleString();
	} catch {
		return iso;
	}
}

export function formatActionType(t: string): string {
	switch (t) {
		case 'dns_sinkhole': return 'DNS Sinkhole';
		case 'arp_isolate': return 'ARP Isolation';
		case 'switch_acl': return 'Switch ACL';
		default: return t;
	}
}
