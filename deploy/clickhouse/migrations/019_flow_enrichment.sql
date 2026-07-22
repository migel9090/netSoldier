-- Vector aggregator enrichment (step 120): geo/ASN from DB-IP Lite mmdb,
-- threat-intel tags from the threat-intel-sync /export/csv snapshot, and
-- reverse-DNS (PTR) on alerts. Empty defaults keep pre-enrichment rows
-- valid; the aggregator fills the fields from this point on.

ALTER TABLE netsoldier.network_flows ADD COLUMN IF NOT EXISTS dst_country LowCardinality(String) DEFAULT '';
ALTER TABLE netsoldier.network_flows ADD COLUMN IF NOT EXISTS dst_asn UInt32 DEFAULT 0;
ALTER TABLE netsoldier.network_flows ADD COLUMN IF NOT EXISTS dst_as_org String DEFAULT '';
ALTER TABLE netsoldier.network_flows ADD COLUMN IF NOT EXISTS threat_source LowCardinality(String) DEFAULT '';
ALTER TABLE netsoldier.network_flows ADD COLUMN IF NOT EXISTS threat_name String DEFAULT '';

ALTER TABLE netsoldier.dns_queries ADD COLUMN IF NOT EXISTS threat_source LowCardinality(String) DEFAULT '';
ALTER TABLE netsoldier.dns_queries ADD COLUMN IF NOT EXISTS threat_name String DEFAULT '';

ALTER TABLE netsoldier.alerts ADD COLUMN IF NOT EXISTS rdns String DEFAULT '';
