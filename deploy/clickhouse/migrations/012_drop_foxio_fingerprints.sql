-- ADR-0003: the FoxIO-licensed JA4+ package was replaced by a
-- first-party JA4 (BSD spec) implementation; JA4S/JA4H are gone.
ALTER TABLE netsoldier.zeek_ssl DROP COLUMN IF EXISTS ja4s;
ALTER TABLE netsoldier.zeek_http DROP COLUMN IF EXISTS ja4h;
