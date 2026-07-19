-- ADR-0003: our produced TLS client fingerprint is renamed off the FoxIO
-- trademark "JA4" to the neutral, descriptive tls_client_fp. The values
-- stay JA4-format-compatible. Rename the column for existing databases
-- (the fresh CREATE above already uses the new name; guard so re-runs and
-- fresh installs are both no-ops).
ALTER TABLE netsoldier.zeek_ssl
    RENAME COLUMN IF EXISTS ja4 TO tls_client_fp;
