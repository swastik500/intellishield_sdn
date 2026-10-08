#!/usr/bin/env bash
# IntelliShield SDN — Release 1.0 upgrade script (macOS developer host)
# Full Mininet/OsKen live SDN is expected on the Ubuntu lab VM, not macOS.
# This script upgrades Python deps, folders, env, health checks, and scoped tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "============================================================"
echo " IntelliShield SDN — update_mac.sh (macOS)"
echo " Root: $ROOT"
echo "============================================================"

echo ""
echo "[1/10] Git reminder (optional)"
echo "  git fetch origin && git status && git pull --ff-only"
echo "  Note: Release 1.0 R4–R8 trees must exist locally or on origin."

echo ""
echo "[2/10] Python version"
command -v python3 >/dev/null || { echo "FAIL: python3 missing (brew install python@3.12)"; exit 1; }
PY_VER=$(python3 -c 'import sys; print("%d.%d"%sys.version_info[:2])')
python3 -c 'import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)' \
  || { echo "FAIL: need Python >= 3.10 (found $PY_VER)"; exit 1; }
echo "OK: Python $PY_VER"

echo ""
echo "[3/10] Create/activate .venv"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
echo "OK: .venv activated"
PY=python
PIP=pip

echo ""
echo "[4/10] Upgrade pip + dependencies"
$PY -m pip install --upgrade pip
$PY -m pip install -r requirements-dev.txt
$PY -m pip install -r dashboard/requirements.txt 2>/dev/null || true

echo ""
echo "[5/10] SDN binaries (expected WARN on Mac)"
for b in osken-manager mn ovs-vsctl; do
  if command -v "$b" >/dev/null 2>&1; then
    echo "OK: $b"
  else
    echo "WARN: $b not on macOS PATH (use Ubuntu lab VM for live Mininet)"
  fi
done

echo ""
echo "[6/10] Folders / log dirs"
mkdir -p logs/twin logs/archive logs/experiments logs/models
mkdir -p logs/twin/candidates logs/twin/datasets
for f in alerts.jsonl correlation_results.jsonl fused_decisions.jsonl \
         root_cause_reports.jsonl verification_trace.jsonl; do
  [[ -f "logs/$f" ]] || { : > "logs/$f"; echo "created logs/$f"; }
done

echo ""
echo "[7/10] .env (never overwrite)"
if [[ -f .env.example && ! -f .env ]]; then
  cp .env.example .env
  echo "created .env"
else
  echo "keep existing .env (or example missing)"
fi

echo ""
echo "[8/10] PYTHONPATH"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
if [[ -f .env ]] && ! grep -q '^PYTHONPATH=' .env 2>/dev/null; then
  echo "PYTHONPATH=$ROOT" >> .env
fi
echo "PYTHONPATH=$PYTHONPATH"

echo ""
echo "[9/10] Health check"
set +e
$PY health_check.py
HC=$?
set -e

echo ""
echo "[10/10] Scoped pytest"
set +e
$PY -m pytest -q \
  tests/test_shared_contracts_foundation.py \
  tests/test_ops_confidence_calibration.py \
  tests/test_fusion_engine_r62.py \
  tests/test_verification_engine_r71.py \
  tests/test_alerting_core_r81.py \
  --tb=line
PT=$?
set -e

echo ""
echo "============================================================"
echo " UPDATE SUMMARY (macOS)"
[[ $HC -eq 0 ]] && echo "  health_check : PASS" || echo "  health_check : FAIL"
[[ $PT -eq 0 ]] && echo "  scoped tests : PASS" || echo "  scoped tests : FAIL"
echo " Live SDN: sync this tree to the Ubuntu VM (rsync/git) then run update.sh there."
echo "============================================================"
if [[ $HC -ne 0 || $PT -ne 0 ]]; then exit 1; fi
exit 0
