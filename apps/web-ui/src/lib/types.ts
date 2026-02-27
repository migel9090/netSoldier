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
