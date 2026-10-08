#!/usr/bin/env bash
# Run ON the Ubuntu lab VM (~/intellishield-sdn). Starts dashboard + seeds twin fixture.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo "=== IntelliShield VM lab start ==="
echo "Root: $ROOT"

if [[ -f ./update.sh ]]; then
  bash ./update.sh || true
fi

echo "=== R3 Level A twin seed (fixture) ==="
python3 scripts/r3_level_a_demo.py \
  --logs-dir tests/fixtures/twin_s2_slim \
  --scenario S2 --whatif attack_sec=25

if command -v lsof >/dev/null 2>&1 && lsof -iTCP:8080 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Stopping existing process on :8080..."
  kill "$(lsof -t -iTCP:8080 -sTCP:LISTEN)" 2>/dev/null || true
  sleep 1
fi

mkdir -p logs
nohup python3 dashboard/api.py > logs/dashboard_api.log 2>&1 &
sleep 2

curl -sS -o /dev/null -w "Dashboard HTTP %{http_code}\n" http://127.0.0.1:8080/
curl -sS http://127.0.0.1:8080/api/digital-twin/stats || true
echo
echo "From Mac browser: http://192.168.64.5:8080/"
echo "  DDoS Dashboard: /"
echo "  Digital Twin:   /#twin"
echo "  Lab Control:    /#lab-control"
echo "Log: $ROOT/logs/dashboard_api.log"
