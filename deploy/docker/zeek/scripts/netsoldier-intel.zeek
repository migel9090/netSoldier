##! netSoldier Intel framework wiring for the first-party JA4 fingerprint.
##!
##! Registers the Intel::JA4 indicator type (the string threat-intel-sync
##! emits in its Zeek export) and feeds every client JA4 into the Intel
##! framework. The standard observation points for the remaining indicator
##! types — DNS, SNI, ADDR, x509 CERT_HASH, ... — come from the stock
##! frameworks/intel/seen policy loaded here.
##!
##! The intel source file itself is deployment config, not image content:
##! the site policy redefs Intel::read_files (fed by the intel-sync
##! sidecar from threat-intel-sync's /export/zeek/intel.dat).

@load base/frameworks/intel
@load frameworks/intel/seen
@load ./netsoldier-ja4

module NetSoldier_Intel;

export {
	redef enum Intel::Type += { Intel::JA4 };
	redef enum Intel::Where += { SSL::IN_JA4 };
}

redef record connection += {
	## Guards against duplicate Intel hits on renegotiation.
	netsoldier_ja4_seen: bool &default=F;
};

# Runs after netsoldier-ja4 computed c$ssl$ja4 (&priority=-5).
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=-10
	{
	if ( c$netsoldier_ja4_seen )
		return;
	if ( ! c?$ssl || ! c$ssl?$ja4 )
		return;

	c$netsoldier_ja4_seen = T;
	Intel::seen(Intel::Seen($indicator=c$ssl$ja4,
	                        $indicator_type=Intel::JA4,
	                        $conn=c,
	                        $where=SSL::IN_JA4));
	}
