##! netSoldier first-party TLS client fingerprint (tls_client_fp).
##!
##! Clean-room implementation written from the published JA4 TLS-client
##! fingerprint specification. The JA4 spec and its output format are
##! BSD-3-Clause; "JA4" is a trademark of FoxIO, LLC and is referenced here
##! only nominatively, to state that this field's values are JA4-format
##! compatible (so they interoperate with JA4-labeled threat-intel feeds).
##! This file contains NO FoxIO code. The FoxIO-licensed JA4+ methods (JA4S,
##! JA4H, JA4X, ...) are intentionally NOT implemented — FoxIO License 1.1
##! forbids monetization. See NOTICE and ADR-0003.
##!
##! Adds a `tls_client_fp` column to ssl.log for TLS over TCP ("t"), QUIC
##! ("q") and DTLS ("d") client hellos.

@load base/protocols/ssl

module NetSoldier_TLSFP;

export {
	redef record SSL::Info += {
		## TLS client fingerprint (JA4-format), e.g.
		## t13d1516h2_8daaf6152771_02713d6af862
		tls_client_fp: string &log &optional;
	};
}

# Per-ClientHello state accumulated from the ssl_extension* events, which
# Zeek raises while parsing the hello, before ssl_client_hello fires.
type ClientHelloState: record {
	ext_codes: vector of count &default=vector();
	sni_present: bool &default=F;
	alpn_first: string &default="";
	alpn_present: bool &default=F;
	sig_algs: vector of count &default=vector();
	supported_versions: vector of count &default=vector();
	done: bool &default=F;
};

redef record connection += {
	netsoldier_tlsfp: ClientHelloState &optional;
};

# TLS extension codes with a dedicated slot in the "a" segment; excluded from
# the extension hash but still included in the extension count.
const EXT_SNI = 0x0000;
const EXT_ALPN = 0x0010;

function get_state(c: connection): ClientHelloState
	{
	if ( ! c?$netsoldier_tlsfp )
		c$netsoldier_tlsfp = ClientHelloState();

	return c$netsoldier_tlsfp;
	}

# GREASE values (RFC 8701): both bytes equal, low nibble 0xa
# (0x0a0a, 0x1a1a, ..., 0xfafa). Ignored everywhere per the spec.
function is_grease(v: count): bool
	{
	return ( v >> 8 ) == ( v & 0xff ) && ( v & 0x0f ) == 0x0a;
	}

function version_string(v: count): string
	{
	switch ( v )
		{
		case 0x0304:
			return "13";
		case 0x0303:
			return "12";
		case 0x0302:
			return "11";
		case 0x0301:
			return "10";
		case 0x0300:
			return "s3";
		case 0x0002:
			return "s2";
		case 0xfefc:
			return "d3";
		case 0xfefd:
			return "d2";
		case 0xfeff:
			return "d1";
		default:
			return "00";
		}
	}

# Highest protocol version: from supported_versions when offered, otherwise
# the legacy ClientHello version. DTLS version codes descend as the protocol
# version ascends (1.0=0xfeff, 1.2=0xfefd, 1.3=0xfefc), so "highest" is the
# numeric minimum there.
function effective_version(legacy: count, supported: vector of count): count
	{
	local best_tls = 0;
	local best_dtls = 0xffff;
	local have_tls = F;
	local have_dtls = F;

	for ( i in supported )
		{
		local v = supported[i];
		if ( is_grease(v) )
			next;

		if ( v >= 0xfe00 && v != 0xffff )
			{
			have_dtls = T;
			if ( v < best_dtls )
				best_dtls = v;
			}
		else
			{
			have_tls = T;
			if ( v > best_tls )
				best_tls = v;
			}
		}

	if ( have_tls )
		return best_tls;
	if ( have_dtls )
		return best_dtls;

	return legacy;
	}

# First and last characters of the first ALPN value; "00" when absent.
# Non-alphanumeric first/last byte switches to the hex representation.
function alpn_chars(alpn: string): string
	{
	if ( |alpn| == 0 )
		return "00";

	local first = alpn[0];
	local last = alpn[|alpn| - 1];

	if ( /[a-zA-Z0-9]/ != first || /[a-zA-Z0-9]/ != last )
		{
		local hex = bytestring_to_hexstr(alpn);
		first = hex[0];
		last = hex[|hex| - 1];
		}

	return fmt("%s%s", first, last);
	}

function count2(n: count): string
	{
	return n > 99 ? "99" : fmt("%02d", n);
	}

function sort_counts(v: vector of count): vector of count
	{
	return sort(v, function(a: count, b: count): int
		{
		if ( a < b )
			return -1;
		if ( a > b )
			return 1;
		return 0;
		});
	}

function hex4_join(v: vector of count): string
	{
	local parts: vector of string = vector();
	for ( i in v )
		parts += fmt("%04x", v[i]);

	return join_string_vec(parts, ",");
	}

# Truncated (12 hex chars) SHA-256; an empty input maps to twelve zeros.
function hash12(payload: string): string
	{
	if ( |payload| == 0 )
		return "000000000000";

	return sub_bytes(sha256_hash(payload), 1, 12);
	}

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	if ( ! is_client )
		return;

	local s = get_state(c);
	if ( s$done )
		return;

	s$ext_codes += code;
	if ( code == EXT_SNI )
		s$sni_present = T;
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec)
	{
	if ( ! is_client )
		return;

	local s = get_state(c);
	if ( s$done || s$alpn_present )
		return;

	if ( |protocols| > 0 )
		{
		s$alpn_first = protocols[0];
		s$alpn_present = T;
		}
	}

event ssl_extension_signature_algorithm(c: connection, is_client: bool, signature_and_hashalgorithms: signature_and_hashalgorithm_vec)
	{
	if ( ! is_client )
		return;

	local s = get_state(c);
	if ( s$done )
		return;

	for ( i in signature_and_hashalgorithms )
		{
		local sa = signature_and_hashalgorithms[i];
		local v = sa$HashAlgorithm * 256 + sa$SignatureAlgorithm;
		if ( ! is_grease(v) )
			s$sig_algs += v;
		}
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec)
	{
	if ( ! is_client )
		return;

	local s = get_state(c);
	if ( s$done )
		return;

	for ( i in versions )
		s$supported_versions += versions[i];
	}

# Finalize on the (first) ClientHello: all extension events for it have
# already fired. &priority=-5 runs after the base scripts set up c$ssl.
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=-5
	{
	local s = get_state(c);
	if ( s$done )
		return;
	s$done = T;

	if ( ! c?$ssl )
		return;

	# segment "a": protocol, version, SNI marker, counts, ALPN
	local proto_c = "t";
	if ( get_port_transport_proto(c$id$resp_p) == udp )
		proto_c = version >= 0xfe00 ? "d" : "q";

	local clean_ciphers: vector of count = vector();
	for ( i in ciphers )
		{
		if ( ! is_grease(ciphers[i]) )
			clean_ciphers += ciphers[i];
		}

	local clean_exts: vector of count = vector();
	local hash_exts: vector of count = vector();
	for ( j in s$ext_codes )
		{
		local code = s$ext_codes[j];
		if ( is_grease(code) )
			next;
		clean_exts += code;
		# SNI and ALPN are counted in segment "a" but excluded from the hash
		if ( code != EXT_SNI && code != EXT_ALPN )
			hash_exts += code;
		}

	local seg_a = fmt("%s%s%s%s%s%s", proto_c,
	                  version_string(effective_version(version, s$supported_versions)),
	                  s$sni_present ? "d" : "i",
	                  count2(|clean_ciphers|),
	                  count2(|clean_exts|),
	                  alpn_chars(s$alpn_first));

	# segment "b": truncated hash of the sorted cipher list
	local seg_b = hash12(hex4_join(sort_counts(clean_ciphers)));

	# segment "c": truncated hash of sorted extensions + signature algorithms
	# (original order); empty extension list short-circuits to zeros.
	local seg_c = "000000000000";
	if ( |hash_exts| > 0 )
		{
		local ext_str = hex4_join(sort_counts(hash_exts));
		if ( |s$sig_algs| > 0 )
			seg_c = hash12(fmt("%s_%s", ext_str, hex4_join(s$sig_algs)));
		else
			seg_c = hash12(ext_str);
		}

	c$ssl$tls_client_fp = fmt("%s_%s_%s", seg_a, seg_b, seg_c);
	}
