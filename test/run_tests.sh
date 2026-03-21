#!/usr/bin/env bash
# run_tests.sh — spin up test containers and run audit against each
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
AUDIT="python3 ${REPO_ROOT}/audit.py"
OUTPUT_DIR="${SCRIPT_DIR}/output"

mkdir -p "$OUTPUT_DIR"

cleanup() {
  docker rm -f pg-hardened pg-vulnerable pg-baseline >/dev/null 2>&1 || true
  docker volume rm pg_hardened_data pg_vulnerable_data pg_baseline_data >/dev/null 2>&1 || true
}

wait_ready() {
  local container="$1"
  for _ in $(seq 1 40); do
    if docker exec "$container" pg_isready -U postgres >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: timed out waiting for $container" >&2
  docker logs "$container" || true
  exit 1
}

echo "════════════════════════════════════════════════════════"
echo "  pg-stig-audit — Integration Test Suite"
echo "════════════════════════════════════════════════════════"
echo

echo "▶ Preparing fixture containers..."
cleanup

echo "  Building hardened image..."
docker build -t pg-stig-audit-hardened:local -f "$SCRIPT_DIR/Dockerfile.hardened" "$SCRIPT_DIR" >/dev/null

echo "  Starting pg-hardened..."
docker run -d \
  --name pg-hardened \
  -e POSTGRES_PASSWORD='SecurePassw0rd!' \
  -e POSTGRES_DB='postgres' \
  -e POSTGRES_INITDB_ARGS='--auth-local=scram-sha-256 --auth-host=scram-sha-256' \
  -p 5433:5432 \
  -v pg_hardened_data:/var/lib/postgresql/data \
  pg-stig-audit-hardened:local \
  postgres \
    -c ssl=on \
    -c ssl_cert_file=/etc/postgresql/certs/server.crt \
    -c ssl_key_file=/etc/postgresql/certs/server.key \
    -c ssl_min_protocol_version=TLSv1.2 \
    -c ssl_ciphers=HIGH:!aNULL:!MD5:!RC4:!3DES \
    -c password_encryption=scram-sha-256 \
    -c logging_collector=on \
    -c log_connections=on \
    -c log_disconnections=on \
    -c log_statement=ddl \
    -c log_min_duration_statement=1000 \
    -c log_min_messages=warning \
    -c log_min_error_statement=error \
    -c "log_line_prefix=%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h " \
    -c log_error_verbosity=default \
    -c log_checkpoints=on \
    -c log_lock_waits=on \
    -c fsync=on \
    -c full_page_writes=on \
    -c idle_session_timeout=900000 \
    -c listen_addresses=localhost >/dev/null

echo "  Starting pg-vulnerable..."
docker run -d \
  --name pg-vulnerable \
  -e POSTGRES_PASSWORD='password' \
  -e POSTGRES_DB='postgres' \
  -e POSTGRES_HOST_AUTH_METHOD='trust' \
  -p 5434:5432 \
  -v pg_vulnerable_data:/var/lib/postgresql/data \
  postgres:16-alpine \
  postgres \
    -c ssl=off \
    -c password_encryption=md5 \
    -c logging_collector=off \
    -c log_connections=off \
    -c log_disconnections=off \
    -c log_statement=none \
    -c log_min_messages=fatal \
    -c listen_addresses='*' \
    -c fsync=on >/dev/null

echo "  Starting pg-baseline..."
docker run -d \
  --name pg-baseline \
  -e POSTGRES_PASSWORD='baseline_password' \
  -e POSTGRES_DB='postgres' \
  -p 5435:5432 \
  -v pg_baseline_data:/var/lib/postgresql/data \
  postgres:16-alpine >/dev/null

echo "  Waiting for containers to be ready..."
wait_ready pg-hardened
wait_ready pg-vulnerable
wait_ready pg-baseline

echo
echo "════════════════════════════════════════════════════════"
echo "  Test 1: HARDENED instance (expect most checks to PASS)"
echo "════════════════════════════════════════════════════════"
$AUDIT \
  --mode docker \
  --container pg-hardened \
  --password 'SecurePassw0rd!' \
  --sarif "$OUTPUT_DIR/hardened.sarif.json" \
  --json "$OUTPUT_DIR/hardened.json" \
  --fail-on critical || true

echo
echo "════════════════════════════════════════════════════════"
echo "  Test 2: VULNERABLE instance (expect many checks to FAIL)"
echo "════════════════════════════════════════════════════════"
$AUDIT \
  --mode docker \
  --container pg-vulnerable \
  --sarif "$OUTPUT_DIR/vulnerable.sarif.json" \
  --json "$OUTPUT_DIR/vulnerable.json" \
  --fail-on none || true

echo
echo "════════════════════════════════════════════════════════"
echo "  Test 3: BASELINE instance (stock PostgreSQL defaults)"
echo "════════════════════════════════════════════════════════"
$AUDIT \
  --mode docker \
  --container pg-baseline \
  --sarif "$OUTPUT_DIR/baseline.sarif.json" \
  --json "$OUTPUT_DIR/baseline.json" \
  --fail-on none || true

echo
echo "▶ Test outputs written to: ${OUTPUT_DIR}/"
echo "  hardened.sarif.json"
echo "  vulnerable.sarif.json"
echo "  baseline.sarif.json"
echo

echo "▶ Stopping test containers..."
cleanup

echo "✅ Tests complete."
