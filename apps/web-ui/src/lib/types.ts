export interface Device {
	mac: string;
	ip: string;
	hostname: string;
	dhcp_fingerprint: string;
	vendor_class: string;
	first_seen: string;
	last_seen: string;
}

export interface Alert {
	id: string;
	timestamp: string;
	domain: string;
	client_ip: string;
	query_type: string;
	matched_ioc: string;
	severity: string;
	source: string;
}

export interface TopologyNode {
	id: string;
	label: string;
	mac: string;
	ip: string;
	device_type: string;
	vendor: string;
	is_local: boolean;
	total_bytes: number;
	connection_count: number;
}

export interface TopologyEdge {
	source: string;
	target: string;
	total_bytes: number;
	total_packets: number;
	flow_count: number;
}

export interface TopologyData {
	nodes: TopologyNode[];
	edges: TopologyEdge[];
}

export interface EnforcementAction {
	id: string;
	timestamp: string;
	detection_id: string;
	action_type: string;
	state: string;
	target_mac: string;
	target_ip: string;
	blocked_domain: string;
	policy_rule: string;
	auto_approved: boolean;
	ttl_seconds: number;
	expires_at: string | null;
	reverted_at: string | null;
	approved_by: string;
	reason: string;
}
