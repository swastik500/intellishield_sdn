#!/usr/bin/env bash
# ============================================================================
# IntelliShield SDN — setup_novelties.sh
# ============================================================================
# Run this AFTER pulling new code that includes Release 1.0 novelty packages:
#   shared_contracts/, correlation/, fusion/, verification/, rca/, xai/,
#   alerting/, twin/, evaluation/
#
# This script:
#   1. Checks Python version (>= 3.10)
#   2. Installs / upgrades pip dependencies (requirements.txt + dev)
#   3. Installs system-level packages if on Ubuntu (apt)
#   4. Creates required folders and JSONL log placeholders
#   5. Sets up .env from .env.example (never overwrites existing)
#   6. Validates that all novelty packages can be imported
#   7. Runs the full novelty + foundation test suite
#   8. Prints a summary and next steps
#
# Usage:
#   chmod +x setup_novelties.sh
#   ./setup_novelties.sh              # standard
#   ./setup_novelties.sh --skip-apt   # skip apt (e.g. on Mac or no sudo)
#   ./setup_novelties.sh --skip-tests # skip pytest at end
#
# Works on: Ubuntu 22.04 (lab VM), macOS (dev host), WSL
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

SKIP_APT=0
SKIP_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --skip-apt)   SKIP_APT=1 ;;
    --skip-tests) SKIP_TESTS=1 ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

SEP="============================================================"
echo "$SEP"
echo " IntelliShield SDN — setup_novelties.sh"
echo " Root: $ROOT"
echo " Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "$SEP"

FAIL=0

# ── 1. Python version ────────────────────────────────────────────
echo ""
echo "[1/8] Python version check"
if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: python3 not found. Install Python >= 3.10."
  exit 1
fi
PY_VER=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
  || { echo "FAIL: Python >= 3.10 required (found $PY_VER)"; exit 1; }
echo "  OK: Python $PY_VER"

# ── 2. Virtual environment ───────────────────────────────────────
echo ""
echo "[2/8] Virtual environment"
if [[ ! -d .venv ]]; then
  echo "  Creating .venv ..."
  python3 -m venv .venv || echo "  WARN: venv creation failed — using system python3"
fi
if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  echo "  OK: .venv activated"
  PY=python
  PIP=pip
else
  PY=python3
  PIP=pip3
  echo "  WARN: using system $PY (no .venv)"
fi

# ── 3. System packages (Ubuntu only) ─────────────────────────────
echo ""
echo "[3/8] System-level dependencies"
if [[ $SKIP_APT -eq 1 ]]; then
  echo "  Skipped (--skip-apt)"
elif [[ "$(uname)" == "Linux" ]] && command -v apt >/dev/null 2>&1; then
  echo "  Updating apt and installing SDN packages (may ask for sudo password) ..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    mininet openvswitch-switch python3-os-ken \
    hping3 iperf \
    2>&1 | tail -5
  sudo systemctl enable --now openvswitch-switch 2>/dev/null || true
  echo "  OK: apt packages installed"
else
  echo "  Not Ubuntu / no apt — skipping system packages."
  echo "  On macOS: SDN binaries (osken-manager, mn, ovs-vsctl) are not expected."
  echo "  Use the Ubuntu lab VM for live Mininet experiments."
fi

# ── 4. Python dependencies ───────────────────────────────────────
echo ""
echo "[4/8] Python dependencies (pip)"
$PY -m pip install --upgrade pip -q
if [[ -f requirements-dev.txt ]]; then
  $PY -m pip install -r requirements-dev.txt -q
  echo "  OK: requirements-dev.txt installed"
elif [[ -f requirements.txt ]]; then
  $PY -m pip install -r requirements.txt -q
  $PY -m pip install pytest httpx -q 2>/dev/null || true
  echo "  OK: requirements.txt installed"
else
  echo "  WARN: no requirements.txt found — installing known stack"
  $PY -m pip install \
    numpy scikit-learn pandas scipy joblib \
    fastapi uvicorn pydantic psutil \
    pytest httpx -q
fi
if [[ -f dashboard/requirements.txt ]]; then
  $PY -m pip install -r dashboard/requirements.txt -q 2>/dev/null || true
fi

# ── 5. Required folders and JSONL placeholders ───────────────────
echo ""
echo "[5/8] Folders and log placeholders"
DIRS=(
  logs
  logs/twin
  logs/twin/snapshots
  logs/twin/replays
  logs/twin/simulations
  logs/twin/candidates
  logs/twin/datasets
  logs/archive
  logs/experiments
  logs/models
)
for d in "${DIRS[@]}"; do
  mkdir -p "$d"
done
echo "  OK: ${#DIRS[@]} directories ensured"

JSONL_FILES=(
  alerts.jsonl
  correlation_results.jsonl
  fused_decisions.jsonl
  root_cause_reports.jsonl
  verification_trace.jsonl
)
created=0
for f in "${JSONL_FILES[@]}"; do
  if [[ ! -f "logs/$f" ]]; then
    : > "logs/$f"
    ((created++)) || true
  fi
done
echo "  OK: JSONL placeholders checked ($created created, $((${#JSONL_FILES[@]} - created)) already existed)"

# ── 6. Environment (.env) ────────────────────────────────────────
echo ""
echo "[6/8] Environment configuration"
if [[ -f .env.example && ! -f .env ]]; then
  cp .env.example .env
  echo "  Created .env from .env.example"
elif [[ -f .env ]]; then
  echo "  .env exists (not overwritten)"
else
  echo "  WARN: .env.example missing — create .env manually"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
if [[ -f .env ]] && ! grep -q '^PYTHONPATH=' .env 2>/dev/null; then
  echo "PYTHONPATH=$ROOT" >> .env
  echo "  Appended PYTHONPATH to .env"
fi
echo "  PYTHONPATH=$PYTHONPATH"

# ── 7. Validate novelty package imports ──────────────────────────
echo ""
echo "[7/8] Novelty package import validation"
NOVELTY_IMPORTS=(
  shared_contracts
  shared_contracts.enums
  shared_contracts.models
  shared_contracts.ops_profile
  shared_contracts.timeutil
  correlation
  correlation.engine
  fusion
  fusion.engine
  verification
  verification.engine
  rca
  rca.engine
  xai
  alerting
  alerting.manager
  twin.snapshot
  twin.replay
  twin.whatif
  evaluation.experiment_windows
)
import_pass=0
import_fail=0
for mod in "${NOVELTY_IMPORTS[@]}"; do
  if $PY -c "import $mod" 2>/dev/null; then
    ((import_pass++)) || true
  else
    echo "  FAIL: import $mod"
    ((import_fail++)) || true
    FAIL=1
  fi
done
echo "  Imports: $import_pass passed, $import_fail failed (out of ${#NOVELTY_IMPORTS[@]})"

# ── 8. Run novelty test suite ────────────────────────────────────
echo ""
echo "[8/8] Novelty test suite"
if [[ $SKIP_TESTS -eq 1 ]]; then
  echo "  Skipped (--skip-tests)"
  PT=0
else
  set +e
  NOVELTY_TESTS=(
    tests/test_shared_contracts_foundation.py
    tests/test_ops_confidence_calibration.py
    tests/test_correlation_engine_r41.py
    tests/test_fusion_engine_r62.py
    tests/test_verification_engine_r71.py
    tests/test_alerting_core_r81.py
    tests/test_rca_core_r52.py
    tests/test_twin_model_r31.py
    tests/test_twin_scenario_r32.py
    tests/test_twin_validation_r33.py
    tests/test_twin_training_r34.py
    tests/test_twin_fidelity_r35.py
    tests/test_twin_snapshot_replay_r36.py
  )
  # Filter to only tests that exist (some may not have been pulled yet)
  EXISTING_TESTS=()
  for t in "${NOVELTY_TESTS[@]}"; do
    [[ -f "$t" ]] && EXISTING_TESTS+=("$t")
  done
  if [[ ${#EXISTING_TESTS[@]} -gt 0 ]]; then
    echo "  Running ${#EXISTING_TESTS[@]} test files ..."
    $PY -m pytest -q "${EXISTING_TESTS[@]}" --tb=short 2>&1 | tail -20
    PT=$?
  else
    echo "  WARN: No novelty test files found (tests/ may be incomplete)"
    PT=0
  fi
  set -e
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "$SEP"
echo " SETUP NOVELTIES — SUMMARY"
echo "$SEP"
echo "  Python         : $PY_VER"
echo "  Pip deps       : installed"
echo "  Folders/JSONL  : OK"
echo "  .env           : $([ -f .env ] && echo 'present' || echo 'MISSING')"
echo "  Novelty imports: $import_pass/${#NOVELTY_IMPORTS[@]} passed"
if [[ $SKIP_TESTS -eq 0 ]]; then
  [[ ${PT:-0} -eq 0 ]] && echo "  Novelty tests  : PASS" || echo "  Novelty tests  : FAIL"
else
  echo "  Novelty tests  : skipped"
fi
echo ""
echo " If everything passed, you're ready:"
echo "  export PYTHONPATH=$ROOT"
echo "  export INTELLISHIELD_OPS_PROFILE=lab"
echo "  osken-manager controller/flow_monitor.py    # Terminal A"
echo "  python3 dashboard/api.py                    # Terminal B"
echo "  http://<VM-IP>:8080                         # Browser"
echo ""
echo " For live Mininet experiments (Ubuntu VM only):"
echo "  sudo python3 -m traffic_generator.traffic_scheduler --scenario 2"
echo "$SEP"

if [[ $FAIL -ne 0 || ${PT:-0} -ne 0 ]]; then
  echo ""
  echo "WARNING: Some checks failed. Review output above."
  exit 1
fi
exit 0
