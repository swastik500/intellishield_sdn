# IntelliShield SDN — Release 1.0 upgrade script (Windows PowerShell)
# NOTE: Live Mininet / OsKen / Open vSwitch are NOT supported on native Windows.
# Use this script for dependency sync, folder init, health check, and unit tests.
# For live SDN, use an Ubuntu 22.04 VM (UTM/VirtualBox/WSL2 with limitations).

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "============================================================"
Write-Host " IntelliShield SDN — update.ps1 (Windows)"
Write-Host " Root: $Root"
Write-Host "============================================================"

Write-Host ""
Write-Host "[1/10] Git reminder (optional)"
Write-Host "  git fetch origin; git status; git pull --ff-only"
Write-Host "  Ensure Release 1.0 packages exist on the remote before relying on pull."

Write-Host ""
Write-Host "[2/10] Python version"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) { throw "FAIL: python not found" }
& $py.Source -c "import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)"
if ($LASTEXITCODE -ne 0) { throw "FAIL: need Python >= 3.10" }
Write-Host "OK: $($py.Source)"

Write-Host ""
Write-Host "[3/10] Create/activate venv"
if (-not (Test-Path ".venv")) {
  & $py.Source -m venv .venv
}
$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) { throw "FAIL: .venv python missing" }
Write-Host "OK: $VenvPy"

Write-Host ""
Write-Host "[4/10] Upgrade pip + dependencies"
& $VenvPy -m pip install --upgrade pip
if (Test-Path "requirements-dev.txt") {
  & $VenvPy -m pip install -r requirements-dev.txt
} else {
  & $VenvPy -m pip install -r requirements.txt
  & $VenvPy -m pip install pytest httpx
}
if (Test-Path "dashboard\requirements.txt") {
  & $VenvPy -m pip install -r dashboard\requirements.txt
}

Write-Host ""
Write-Host "[5/10] SDN binaries"
Write-Host "WARN: osken-manager / mn / ovs-vsctl expected only on Ubuntu lab VM"

Write-Host ""
Write-Host "[6/10] Folders / log dirs"
$dirs = @(
  "logs", "logs\twin", "logs\archive", "logs\experiments", "logs\models",
  "logs\twin\candidates", "logs\twin\datasets"
)
foreach ($d in $dirs) {
  New-Item -ItemType Directory -Force -Path $d | Out-Null
}
$jsonl = @(
  "alerts.jsonl", "correlation_results.jsonl", "fused_decisions.jsonl",
  "root_cause_reports.jsonl", "verification_trace.jsonl"
)
foreach ($f in $jsonl) {
  $path = Join-Path "logs" $f
  if (-not (Test-Path $path)) {
    New-Item -ItemType File -Path $path | Out-Null
    Write-Host "created $path"
  }
}

Write-Host ""
Write-Host "[7/10] .env (never overwrite)"
if ((Test-Path ".env.example") -and -not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "created .env"
} else {
  Write-Host "keep existing .env"
}

Write-Host ""
Write-Host "[8/10] PYTHONPATH"
$env:PYTHONPATH = $Root
Write-Host "PYTHONPATH=$env:PYTHONPATH"

Write-Host ""
Write-Host "[9/10] Health check"
& $VenvPy health_check.py
$hc = $LASTEXITCODE

Write-Host ""
Write-Host "[10/10] Scoped pytest"
& $VenvPy -m pytest -q `
  tests/test_shared_contracts_foundation.py `
  tests/test_ops_confidence_calibration.py `
  tests/test_fusion_engine_r62.py `
  tests/test_verification_engine_r71.py `
  tests/test_alerting_core_r81.py `
  --tb=line
$pt = $LASTEXITCODE

Write-Host ""
Write-Host "============================================================"
Write-Host " UPDATE SUMMARY (Windows)"
if ($hc -eq 0) { Write-Host "  health_check : PASS" } else { Write-Host "  health_check : FAIL" }
if ($pt -eq 0) { Write-Host "  scoped tests : PASS" } else { Write-Host "  scoped tests : FAIL" }
Write-Host " Live Mininet: use Ubuntu VM + update.sh"
Write-Host "============================================================"
if ($hc -ne 0 -or $pt -ne 0) { exit 1 }
exit 0
