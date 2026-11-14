#!/bin/sh
# netSoldier ClickHouse migration runner: the one way the schema changes.
#
# Applies migrations/NNN_name.sql in order, each exactly once, and records
# every applied file (version, file name, SHA-256 of its bytes) in
# $MIGRATIONS_DATABASE.schema_migrations. The same script runs everywhere:
#
#   Kubernetes  the clickhouse-migrate Job
#               (deploy/kustomize/base/clickhouse/migrate-job.yaml) mounts it
#               and the migrations from ConfigMaps generated straight from
#               this directory by deploy/clickhouse/kustomization.yaml;
#   elsewhere   (Podman, CI, tests) run it in place against the repo files,
#               on a host with clickhouse-client or inside any
#               clickhouse-server container, e.g.
#                 docker run --rm --network <net> \
#                   -v "$PWD/deploy/clickhouse:/opt/migrate:ro" \
#                   -e CLICKHOUSE_HOST=clickhouse -e CLICKHOUSE_USER=migrate \
#                   -e CLICKHOUSE_PASSWORD \
#                   --entrypoint /bin/sh clickhouse/clickhouse-server:24.3-alpine \
#                   /opt/migrate/migrate.sh
#
# Needs a POSIX shell, sha256sum (or shasum) and clickhouse-client (or
# CLICKHOUSE_CLIENT="clickhouse client") reaching the native port.
#
# Environment:
#   CLICKHOUSE_HOST       server host                        (default clickhouse)
#   CLICKHOUSE_PORT       native protocol port               (default 9000)
#   CLICKHOUSE_USER       the migration account              (required)
#   CLICKHOUSE_PASSWORD   its password                       (required, non-empty;
#                         clickhouse-client reads it from the environment, so
#                         it never appears on a command line or in `ps`)
#   MIGRATIONS_DIR        directory of NNN_name.sql files    (default: migrations/
#                         next to this script)
#   MIGRATIONS_DATABASE   database holding schema_migrations (default netsoldier,
#                         so the record travels with the schema it describes)
#   MIGRATE_WAIT_SECONDS  how long to wait for the server    (default 180)
#   CLICKHOUSE_CLIENT     client command                     (default clickhouse-client)
#
# Usage: migrate.sh [apply|status]
#   apply   (default) verify, then apply every pending migration in order
#   status  verify and list applied/pending; exit 0 if none pending, 3 if any
#
# Guarantees:
#   - Nothing is applied unless every recorded migration is still present
#     with the recorded checksum, every file is named NNN_name.sql with a
#     unique NNN, and no pending file sorts before one already applied.
#     Applied migrations are immutable: fix forward with a new file.
#   - Re-running is a no-op once everything is applied.
#   - The first failing statement stops the run with a non-zero exit. A file
#     is recorded only after all of its statements succeeded, so the next
#     run starts that file again from the top. Every migration must
#     therefore survive being re-run after failing part-way (IF [NOT]
#     EXISTS guards, or the drop-stale-copy-then-swap pattern of 020, 021
#     and 023).
#   - One instance at a time: the Job runs with parallelism 1 and ArgoCD
#     runs one hook per sync; do not start a second runner by hand while
#     the Job is running.
set -eu

log() { printf '%s migrate: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

mode=${1:-apply}
case "$mode" in
  apply | status) ;;
  *) die "usage: $0 [apply|status]" ;;
esac

: "${CLICKHOUSE_HOST:=clickhouse}"
: "${CLICKHOUSE_PORT:=9000}"
: "${MIGRATIONS_DATABASE:=netsoldier}"
: "${MIGRATE_WAIT_SECONDS:=180}"
: "${CLICKHOUSE_CLIENT:=clickhouse-client}"
if [ -z "${MIGRATIONS_DIR:-}" ]; then
  MIGRATIONS_DIR="$(cd "$(dirname "$0")" && pwd)/migrations"
fi

[ -n "${CLICKHOUSE_USER:-}" ] || die "CLICKHOUSE_USER is not set (the migration account)"
[ -n "${CLICKHOUSE_PASSWORD:-}" ] ||
  die "CLICKHOUSE_PASSWORD is empty; refusing to connect without a credential"
export CLICKHOUSE_PASSWORD
[ -d "$MIGRATIONS_DIR" ] || die "MIGRATIONS_DIR '$MIGRATIONS_DIR' is not a directory"
case "$MIGRATIONS_DATABASE" in
  "" | *[!A-Za-z0-9_]*) die "MIGRATIONS_DATABASE must be a plain identifier" ;;
esac
DB=$MIGRATIONS_DATABASE

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "need sha256sum or shasum"
fi

# CLICKHOUSE_CLIENT is deliberately unquoted so "clickhouse client" works.
ch() {
  # shellcheck disable=SC2086
  $CLICKHOUSE_CLIENT --host "$CLICKHOUSE_HOST" --port "$CLICKHOUSE_PORT" \
    --user "$CLICKHOUSE_USER" "$@"
}

wait_for_server() {
  deadline=$(($(date +%s) + MIGRATE_WAIT_SECONDS))
  while :; do
    rc=0
    out=$(ch --query "SELECT version()" 2>&1) || rc=$?
    if [ "$rc" -eq 0 ]; then
      log "connected to ClickHouse $out at $CLICKHOUSE_HOST:$CLICKHOUSE_PORT as $CLICKHOUSE_USER"
      return 0
    fi
    # The client exits with the ClickHouse error code modulo 256. Only
    # "not there yet" is worth waiting for: DNS_ERROR (198), NETWORK_ERROR
    # (210), SOCKET_TIMEOUT (209), TIMEOUT_EXCEEDED (159) and
    # ATTEMPT_TO_READ_AFTER_EOF (32). Anything else, notably a refused
    # login (AUTHENTICATION_FAILED, exit 4), fails at once.
    case "$rc" in
      198 | 210 | 209 | 159 | 32) ;;
      *) die "cannot use ClickHouse at $CLICKHOUSE_HOST:$CLICKHOUSE_PORT as $CLICKHOUSE_USER (exit $rc): $out" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] ||
      die "ClickHouse at $CLICKHOUSE_HOST:$CLICKHOUSE_PORT not reachable after ${MIGRATE_WAIT_SECONDS}s: $out"
    log "waiting for ClickHouse: $out"
    sleep 2
  done
}

# Migration file names, one per line, in byte order. NNN is exactly three
# digits so byte order and numeric order agree.
list_files() {
  for f in "$MIGRATIONS_DIR"/*.sql; do
    [ -e "$f" ] && basename "$f"
  done | LC_ALL=C sort
}

validate_names() {
  files=$(list_files)
  [ -n "$files" ] || die "no *.sql files in $MIGRATIONS_DIR"
  prev=""
  for name in $files; do
    case "$name" in
      [0-9][0-9][0-9]_?*.sql) ;;
      *) die "'$name' is not named NNN_name.sql (NNN = three digits)" ;;
    esac
    case "${name%.sql}" in
      *[!A-Za-z0-9_]*) die "'$name': use only letters, digits and _ in migration names" ;;
    esac
    version=${name%%_*}
    [ "$version" != "$prev" ] || die "two migrations share version $version"
    prev=$version
  done
}

table_exists() {
  [ "$(ch --query "EXISTS TABLE ${DB}.schema_migrations")" = "1" ]
}

bootstrap() {
  ch --multiquery --query "
    CREATE DATABASE IF NOT EXISTS ${DB};
    CREATE TABLE IF NOT EXISTS ${DB}.schema_migrations
    (
        version    UInt32,
        name       String,
        checksum   String,
        applied_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),
        applied_by String DEFAULT currentUser()
    )
    ENGINE = MergeTree
    ORDER BY version" ||
    die "cannot create ${DB}.schema_migrations"
}

tab=$(printf '\t')

# Sets $applied (names, one per line) and $last_applied; dies on drift.
verify_applied() {
  applied=""
  last_applied=""
  if table_exists; then
    records=$(ch --query "SELECT name, checksum FROM ${DB}.schema_migrations ORDER BY name FORMAT TSV")
  else
    records=""
  fi
  while IFS="$tab" read -r name sum; do
    [ -n "$name" ] || continue
    f="$MIGRATIONS_DIR/$name"
    [ -f "$f" ] ||
      die "$name is recorded as applied but $f does not exist; applied migrations must never be removed or renamed"
    actual=$(sha256 "$f")
    [ "$actual" = "$sum" ] ||
      die "$name changed after it was applied (recorded sha256 $sum, file now $actual). Applied migrations are immutable: restore the file and put the change in a new migration"
    applied="$applied$name
"
    last_applied=$name
  done <<EOF
$records
EOF
}

is_applied() {
  printf '%s' "$applied" | grep -Fqx -- "$1"
}

pending_files() {
  for name in $files; do
    is_applied "$name" || echo "$name"
  done
}

apply_file() {
  name=$1
  f="$MIGRATIONS_DIR/$name"
  sum=$(sha256 "$f")
  [ -n "$sum" ] || die "cannot read $f"
  log "applying $name (sha256 $sum)"
  start=$(date +%s)
  rc=0
  ch --multiquery --queries-file "$f" || rc=$?
  [ "$rc" -eq 0 ] ||
    die "$name failed (client exit $rc); it was not recorded, so the next run re-applies it from its first statement once the cause is fixed"
  # "001" -> "1": a UInt32 query parameter must not have leading zeros.
  version=$(printf '%s' "${name%%_*}" | sed 's/^0*\(.\)/\1/')
  # INSERT ... SELECT rather than VALUES: the server evaluates it, whereas
  # VALUES is parsed by the client, which then wants a writable working
  # directory (it fails on a read-only root filesystem).
  ch --param_version="$version" --param_name="$name" --param_checksum="$sum" --query "
    INSERT INTO ${DB}.schema_migrations (version, name, checksum)
    SELECT {version:UInt32}, {name:String}, {checksum:String}" ||
    die "$name was applied but could not be recorded; the next run re-applies it"
  log "applied $name in $(($(date +%s) - start))s"
}

validate_names
wait_for_server
[ "$mode" = "status" ] || bootstrap
verify_applied

pending=$(pending_files)
if [ -n "$pending" ] && [ -n "$last_applied" ]; then
  for name in $pending; do
    # Byte order is version order (validate_names).
    if [ "$(printf '%s\n%s\n' "$name" "$last_applied" | LC_ALL=C sort | head -n 1)" = "$name" ]; then
      die "$name is new but sorts before $last_applied, which is already applied; give it a version after the last applied one"
    fi
  done
fi

count_lines() { printf '%s' "$1" | grep -c . || true; }

if [ "$mode" = "status" ]; then
  for name in $files; do
    if is_applied "$name"; then echo "applied  $name"; else echo "pending  $name"; fi
  done
  if [ -n "$pending" ]; then
    log "$(count_lines "$pending") pending, $(count_lines "$applied") applied"
    exit 3
  fi
  log "up to date at ${last_applied} ($(count_lines "$applied") applied)"
  exit 0
fi

if [ -z "$pending" ]; then
  log "nothing to apply; schema is at $last_applied ($(count_lines "$applied") migrations, checksums verified)"
  exit 0
fi

n=0
for name in $pending; do
  apply_file "$name"
  n=$((n + 1))
done
log "done: applied $n migration(s); schema is at $name"
