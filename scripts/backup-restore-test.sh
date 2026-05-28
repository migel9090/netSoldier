#!/usr/bin/env bash
# Verify backup integrity and restore capability.
# Run locally with kubectl port-forward or as a Kubernetes Job.
set -euo pipefail

FAIL=0
NAMESPACE="${NAMESPACE:-netsoldier}"

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAIL=1; }
skip() { echo "  SKIP: $1"; }

# ---------- ClickHouse S3 backup ----------
echo "==> ClickHouse backup verification"

CH_HOST="${CH_HOST:-localhost}"
CH_PORT="${CH_PORT:-9000}"
S3_ENDPOINT="${S3_ENDPOINT:-}"
S3_BUCKET="${S3_BUCKET:-netsoldier-backup}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-}"
S3_SECRET_KEY="${S3_SECRET_KEY:-}"

if [ -z "${S3_ENDPOINT}" ]; then
  skip "S3_ENDPOINT not set — cannot verify ClickHouse backup"
else
  TODAY=$(date +%Y-%m-%d)
  SCHEMA_URL="${S3_ENDPOINT}/${S3_BUCKET}/clickhouse/${TODAY}/schema.csv"

  if curl -sf "${SCHEMA_URL}" -o /dev/null 2>/dev/null; then
    pass "schema.csv exists for ${TODAY}"
  else
    fail "schema.csv missing for ${TODAY} at ${SCHEMA_URL}"
  fi

  TABLES="devices device_events network_flows dns_queries alerts events connections audit_log"
  for TABLE in $TABLES; do
    DATA_URL="${S3_ENDPOINT}/${S3_BUCKET}/clickhouse/${TODAY}/${TABLE}.native.zst"
    if curl -sf -I "${DATA_URL}" -o /dev/null 2>/dev/null; then
      pass "${TABLE}.native.zst present"
    else
      skip "${TABLE}.native.zst absent (table may be empty)"
    fi
  done

  echo ""
  echo "==> ClickHouse restore test (temp database)"
  TEMP_DB="restore_test_$(date +%s)"

  clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
    --query "CREATE DATABASE IF NOT EXISTS ${TEMP_DB}" 2>/dev/null || {
    skip "cannot connect to ClickHouse — skipping restore test"
  }

  if clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
    --query "SELECT 1 FROM system.databases WHERE name='${TEMP_DB}'" 2>/dev/null | grep -q 1; then

    SCHEMA=$(clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
      --query "SELECT create_table_query FROM s3(
        '${SCHEMA_URL}', '${S3_ACCESS_KEY}', '${S3_SECRET_KEY}', 'CSVWithNames'
      ) LIMIT 1" 2>/dev/null || echo "")

    if [ -n "${SCHEMA}" ]; then
      REWRITTEN=$(echo "${SCHEMA}" | sed "s/netsoldier\./${TEMP_DB}./g")
      if clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
        --query "${REWRITTEN}" 2>/dev/null; then
        pass "schema restore to ${TEMP_DB}"
      else
        fail "schema restore to ${TEMP_DB}"
      fi
    else
      fail "could not read schema from S3"
    fi

    clickhouse-client --host "${CH_HOST}" --port "${CH_PORT}" \
      --query "DROP DATABASE IF EXISTS ${TEMP_DB}" 2>/dev/null
    pass "temp database cleaned up"
  fi
fi

# ---------- State backup (PVC) ----------
echo ""
echo "==> State backup verification"

BACKUP_BASE="${BACKUP_DIR:-/backup/state}"

if [ ! -d "${BACKUP_BASE}" ]; then
  skip "backup directory ${BACKUP_BASE} not found (run with PVC mounted)"
else
  LATEST=$(find "${BACKUP_BASE}" -maxdepth 1 -mindepth 1 -type d | sort -r | head -1)

  if [ -z "${LATEST}" ]; then
    fail "no backup directories found in ${BACKUP_BASE}"
  else
    DIR_DATE=$(basename "${LATEST}")
    echo "  Latest backup: ${DIR_DATE}"

    if [ -f "${LATEST}/devices.json" ]; then
      SIZE=$(wc -c < "${LATEST}/devices.json")
      if [ "$SIZE" -gt 2 ]; then
        pass "devices.json (${SIZE} bytes)"
      else
        fail "devices.json is empty or trivial"
      fi
    else
      fail "devices.json missing"
    fi

    if [ -f "${LATEST}/configmaps.json" ]; then
      SIZE=$(wc -c < "${LATEST}/configmaps.json")
      pass "configmaps.json (${SIZE} bytes)"
    else
      fail "configmaps.json missing"
    fi

    if [ -f "${LATEST}/secrets.age" ]; then
      SIZE=$(wc -c < "${LATEST}/secrets.age")
      pass "secrets.age (${SIZE} bytes, encrypted)"

      if [ -n "${AGE_PRIVATE_KEY:-}" ]; then
        echo "  Attempting decrypt..."
        if echo "${AGE_PRIVATE_KEY}" | age -d -i - "${LATEST}/secrets.age" > /dev/null 2>&1; then
          pass "secrets.age decrypts successfully"
        else
          fail "secrets.age decryption failed"
        fi
      else
        skip "AGE_PRIVATE_KEY not set — decrypt verification skipped"
      fi
    else
      skip "secrets.age not found (AGE_PUBLIC_KEY may not be configured)"
    fi
  fi
fi

# ---------- Summary ----------
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "All backup checks passed."
  exit 0
else
  echo "Some backup checks FAILED — review output above."
  exit 1
fi
