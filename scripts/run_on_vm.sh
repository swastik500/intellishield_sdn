#!/usr/bin/env bash
# Remote start: dashboard (+ optional twin demo seed) on Ubuntu lab VM.
# Usage: ./scripts/run_on_vm.sh [VM_USER@VM_HOST]
set -euo pipefail

TARGET="${1:-akshay@192.168.64.5}"
REMOTE_DIR="${REMOTE_DIR:-intellishield-sdn}"

ssh "$TARGET" bash -s <<EOF
set -euo pipefail
cd ~/${REMOTE_DIR}
export PYTHONPATH="\$HOME/${REMOTE_DIR}\${PYTHONPATH:+:\$PYTHONPATH}"

echo "=== update.sh (deps / dirs) ==="
bash ./update.sh || true

echo "=== twin Level A seed (fixture) ==="
python3 scripts/r3_level_a_demo.py \\
  --logs-dir tests/fixtures/twin_s2_slim \\
  --scenario S2 --whatif attack_sec=25 || echo "WARN: twin demo failed (check sklearn)"

if lsof -iTCP:8080 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Stopping existing dashboard on :8080..."
  kill \$(lsof -t -iTCP:8080 -sTCP:LISTEN) 2>/dev/null || true
  sleep 1
fi

echo "=== starting dashboard/api.py on 0.0.0.0:8080 ==="
nohup python3 dashboard/api.py > logs/dashboard_api.log 2>&1 &
sleep 2
curl -sS -o /dev/null -w "HTTP %{http_code}\\n" http://127.0.0.1:8080/ || true
curl -sS http://127.0.0.1:8080/api/digital-twin/stats | head -c 400 || true
echo
echo "Open from Mac: http://192.168.64.5:8080/"
echo "Log: ~/${REMOTE_DIR}/logs/dashboard_api.log"
EOF
