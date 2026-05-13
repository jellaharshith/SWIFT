#!/usr/bin/env bash
# Benchmark SWIFT time-to-first-finding on Juice Shop (clean-room run)
set -euo pipefail

TARGET="${1:-http://localhost:3000}"
VENV_ACTIVATE="${2:-.venv/bin/activate}"

echo "=== SWIFT TTHW Benchmark ==="
echo "Target: $TARGET"

# Fresh venv check
if [ ! -f "$VENV_ACTIVATE" ]; then
    echo "ERROR: venv not found at $VENV_ACTIVATE" >&2
    exit 1
fi

source "$VENV_ACTIVATE"

# Time the scan to first finding
START=$(date +%s%N)
timeout 300 swiftsec web-scan "$TARGET" --json 2>/dev/null | python3 -c "
import sys, json, time
data = json.load(sys.stdin)
findings = data.get('findings', 0)
print(f'Findings: {findings}')
" || true
END=$(date +%s%N)

ELAPSED=$(( (END - START) / 1000000 ))
echo "TTHW: ${ELAPSED}ms"
