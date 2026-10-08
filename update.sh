#!/usr/bin/env bash
# IntelliShield SDN — Release 1.0 upgrade script (Linux / Ubuntu lab VM)
# Does NOT overwrite an existing .env
# Does NOT modify application source code
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "============================================================"
echo " IntelliShield SDN — update.sh (Linux)"
echo " Root: $ROOT"
echo "============================================================"

echo ""
echo "[1/10] Git reminder (optional — not run automatically)"
echo "  If this tree is a git clone with Release 1.0 pushed to origin:"
echo "    git fetch origin && git status"
echo "    git pull --ff-only"
echo "  IMPORTANT: As of the Release 1.0 audit, many R4–R8 packages may"
echo "  still be local-only until the maintainer commits & pushes them."
echo "  A plain 'git pull' against an old remote may NOT be enough."

echo ""
echo "[2/10] Python version"
if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 not found"; exit 1
fi
PY_VER=$(python3 -c 'import sys; print("%d.%d"%sys.version_info[:2])')
python3 -c 'import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)' \
  || { echo "FAIL: need Python >= 3.10 (found $PY_VER)"; exit 1; }
echo "OK: Python $PY_VER"

echo ""
echo "[3/10] Virtual environment (optional on lab VM; created if missing)"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv || echo "WARN: venv create failed — continuing with system python3"
fi
if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  echo "OK: activated .venv"
  PY=python
  PIP=pip
else
  PY=python3
  PIP=pip3
  echo "WARN: using system $PY / $PIP"
fi

echo ""
echo "[4/10] Upgrade pip + install dependencies"
$PY -m pip install --upgrade pip
if [[ -f requirements-dev.txt ]]; then
  $PY -m pip install -r requirements-dev.txt
elif [[ -f requirements.txt ]]; then
  $PY -m pip install -r requirements.txt
  $PY -m pip install pytest httpx || true
else
  echo "WARN: no requirements.txt — installing known stack"
  $PY -m pip install numpy scikit-learn pandas scipy joblib fastapi uvicorn pydantic psutil pytest httpx
fi
if [[ -f dashboard/requirements.txt ]]; then
  $PY -m pip install -r dashboard/requirements.txt
fi

echo ""
echo "[5/10] Verify system binaries (Ubuntu lab)"
for b in osken-manager mn ovs-vsctl; do
  if command -v "$b" >/dev/null 2>&1; then
    echo "OK: $b → $(command -v "$b")"
  else
    echo "WARN: $b not found — install via apt (see INSTALLATION.md)"
  fi
done

echo ""
echo "[6/10] Create missing folders / log dirs (idempotent)"
mkdir -p logs/twin logs/archive logs/experiments logs/models
mkdir -p logs/twin/candidates logs/twin/datasets
# Touch empty JSONL placeholders only if missing (do not truncate)
for f in alerts.jsonl correlation_results.jsonl fused_decisions.jsonl \
         root_cause_reports.jsonl verification_trace.jsonl; do
  if [[ ! -f "logs/$f" ]]; then
    : > "logs/$f"
    echo "created logs/$f"
  else
    echo "keep existing logs/$f"
  fi
done

echo ""
echo "[7/10] Default config / .env (never overwrite)"
if [[ -f .env.example ]]; then
  if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "created .env from .env.example"
  else
    echo "keep existing .env (not overwritten)"
  fi
else
  echo "WARN: .env.example missing"
fi

echo ""
echo "[8/10] PYTHONPATH for this session"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
echo "PYTHONPATH=$PYTHONPATH"
# Persist hint
if [[ -f .env ]] && ! grep -q '^PYTHONPATH=' .env 2>/dev/null; then
  echo "PYTHONPATH=$ROOT" >> .env
  echo "appended PYTHONPATH to .env"
fi

echo ""
echo "[9/10] Repository health check"
set +e
$PY health_check.py
HC=$?
set -e

echo ""
echo "[10/10] Scoped validation tests"
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
echo " UPDATE SUMMARY"
[[ $HC -eq 0 ]] && echo "  health_check.py : PASS" || echo "  health_check.py : FAIL"
[[ $PT -eq 0 ]] && echo "  scoped pytest   : PASS" || echo "  scoped pytest   : FAIL (or tests missing — sync Release 1.0 tree)"
echo ""
echo " Next:"
echo "  export INTELLISHIELD_OPS_PROFILE=lab"
echo "  export PYTHONPATH=$ROOT"
echo "  osken-manager controller/flow_monitor.py"
echo "  python3 dashboard/api.py"
echo "============================================================"
if [[ $HC -ne 0 || $PT -ne 0 ]]; then
  exit 1
fi
exit 0
