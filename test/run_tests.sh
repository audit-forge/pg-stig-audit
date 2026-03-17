#!/bin/bash
# run_tests.sh — spin up test containers and run audit against each
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT="python3 ${SCRIPT_DIR}/../audit.py"
OUTPUT_DIR="${SCRIPT_DIR}/output"

mkdir -p "$OUTPUT_DIR"

echo "════════════════════════════════════════════════════════"
echo "  pg-stig-audit — Integration Test Suite"
echo "════════════════════════════════════════════════════════"
echo

# Start test containers
echo "▶ Starting test containers..."
docker compose -f "${SCRIPT_DIR}/docker-compose.test.yml" up -d
echo "  Waiting for containers to be healthy..."
sleep 8

echo
echo "════════════════════════════════════════════════════════"
echo "  Test 1: HARDENED instance (expect most checks to PASS)"
echo "════════════════════════════════════════════════════════"
$AUDIT \
    --mode docker \
    --container pg-hardened \
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
docker compose -f "${SCRIPT_DIR}/docker-compose.test.yml" down -v

echo "✅ Tests complete."
