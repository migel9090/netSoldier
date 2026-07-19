##! netSoldier Intel framework wiring for the first-party TLS client
##! fingerprint (tls_client_fp).
##!
##! Registers the Intel::TLSFP indicator type (the string threat-intel-sync
##! emits in its Zeek export for JA4-format fingerprints) and feeds every
##! client fingerprint into the Intel framework. The standard observation
##! points for the remaining indicator types — DNS, SNI, ADDR, x509
##! CERT_HASH, ... — come from the stock frameworks/intel/seen policy loaded
##! here.
##!
##! The intel source file itself is deployment config, not image content:
##! the site policy redefs Intel::read_files (fed by the intel-sync
##! sidecar from threat-intel-sync's /export/zeek/intel.dat).

@load base/frameworks/intel
@load frameworks/intel/seen
@load ./netsoldier-tlsfp

module NetSoldier_Intel;

export {
	redef enum Intel::Type += { Intel::TLSFP };
	redef enum Intel::Where += { SSL::IN_TLSFP };
}

redef record connection += {
	## Guards against duplicate Intel hits on renegotiation.
	netsoldier_tlsfp_seen: bool &default=F;
};

# Runs after netsoldier-tlsfp computed c$ssl$tls_client_fp (&priority=-5).
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=-10
	{
	if ( c$netsoldier_tlsfp_seen )
		return;
	if ( ! c?$ssl || ! c$ssl?$tls_client_fp )
		return;

	c$netsoldier_tlsfp_seen = T;
	Intel::seen(Intel::Seen($indicator=c$ssl$tls_client_fp,
	                        $indicator_type=Intel::TLSFP,
	                        $conn=c,
	                        $where=SSL::IN_TLSFP));
	}
