#!/usr/bin/env bash
# IntelliShield SDN — Release 1.0 quick start (lab)
# Validates environment, starts controller + dashboard in background, prints next steps.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

# Load .env if present (without overriding already-exported vars carefully)
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export INTELLISHIELD_OPS_PROFILE="${INTELLISHIELD_OPS_PROFILE:-lab}"
export INTELLISHIELD_R6_FUSION="${INTELLISHIELD_R6_FUSION:-1}"

echo "============================================================"
echo " IntelliShield SDN — quick_start.sh"
echo " OPS_PROFILE=$INTELLISHIELD_OPS_PROFILE  R6_FUSION=$INTELLISHIELD_R6_FUSION"
echo "============================================================"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

PY=python3
command -v python >/dev/null 2>&1 && PY=python

echo ""
echo "[1/4] Health check"
set +e
$PY health_check.py
HC=$?
set -e
if [[ $HC -ne 0 ]]; then
  echo "FAIL: fix health check issues (run ./update.sh or ./update_mac.sh first)"
  exit 1
fi

mkdir -p logs
CTRL_LOG="$ROOT/logs/quick_start_controller.log"
DASH_LOG="$ROOT/logs/quick_start_dashboard.log"

if ! command -v osken-manager >/dev/null 2>&1; then
  echo ""
  echo "WARN: osken-manager not found — starting dashboard only."
  echo "      For full SDN, run this on the Ubuntu lab VM."
  START_CTRL=0
else
  START_CTRL=1
fi

echo ""
echo "[2/4] Start controller (OpenFlow :6653)"
if [[ $START_CTRL -eq 1 ]]; then
  if pgrep -f 'osken-manager.*flow_monitor' >/dev/null 2>&1; then
    echo "Controller already running — leaving it."
  else
    nohup osken-manager "$ROOT/controller/flow_monitor.py" >"$CTRL_LOG" 2>&1 &
    echo $! > "$ROOT/logs/quick_start_controller.pid"
    echo "Controller PID $(cat "$ROOT/logs/quick_start_controller.pid")  log=$CTRL_LOG"
    sleep 2
  fi
fi

echo ""
echo "[3/4] Start dashboard (HTTP :8080)"
if curl -sf "http://127.0.0.1:8080/api/status" >/dev/null 2>&1; then
  echo "Dashboard already responding on :8080"
else
  nohup $PY "$ROOT/dashboard/api.py" >"$DASH_LOG" 2>&1 &
  echo $! > "$ROOT/logs/quick_start_dashboard.pid"
  echo "Dashboard PID $(cat "$ROOT/logs/quick_start_dashboard.pid")  log=$DASH_LOG"
  sleep 2
fi

echo ""
echo "[4/4] URLs & next commands"
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-127.0.0.1}
echo "  Dashboard UI : http://127.0.0.1:8080/"
echo "  Dashboard UI : http://${IP}:8080/   (LAN/VM)"
echo "  API status   : http://127.0.0.1:8080/api/status"
echo "  OpenAPI      : http://127.0.0.1:8080/docs"
echo "  Controller   : OpenFlow TCP :6653"
echo ""
echo " Next (Ubuntu lab, sudo):"
echo "  sudo python3 -m traffic_generator.traffic_scheduler --scenario 2"
echo "  sudo python3 -m traffic_generator.traffic_scheduler --all"
echo ""
echo " Stop:"
echo "  kill \$(cat logs/quick_start_dashboard.pid) 2>/dev/null || true"
echo "  kill \$(cat logs/quick_start_controller.pid) 2>/dev/null || pkill -f 'osken-manager.*flow_monitor' || true"
echo "============================================================"
