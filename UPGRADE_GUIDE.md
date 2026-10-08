# Upgrade Guide — IntelliShield SDN Release 1.0

Related: [UPDATE_AUDIT.md](UPDATE_AUDIT.md) · [INSTALLATION.md](INSTALLATION.md) · [DOCS/release-1.0/CONFIGURATION.md](DOCS/release-1.0/CONFIGURATION.md)

---

## Who should use this guide

Developers who:

- cloned IntelliShield **weeks ago** (pre–Release 1.0 / pre–R4–R8),
- already installed older Python deps,
- want to move to the **Release 1.0** laboratory stack.

If you are installing on a **blank** machine, use [INSTALLATION.md](INSTALLATION.md) instead.

---

## Prerequisites

| Item | Notes |
|------|-------|
| Git access to the updated tree | See critical warning below |
| Python ≥ 3.10 | 3.10 recommended on Ubuntu 22.04 lab VM |
| Disk space for `logs/` + models | Modest |
| Ubuntu VM for live Mininet | Mac/Windows: deps + unit tests only |

### Critical warning — `git pull` may not be enough

At the time of the Release 1.0 update audit, large parts of Release 1.0 (`shared_contracts/`, `correlation/`, `fusion/`, `verification/`, `alerting/`, `rca/`, `xai/`, `twin/`, many tests, release docs) were present in the working tree as **untracked / not yet pushed** relative to `origin/main`.

**Implication:** an older clone that only runs `git pull` against GitHub may still receive an **incomplete** tree until the maintainer **commits and pushes** Release 1.0.

After the maintainer publishes Release 1.0 to the remote:

```bash
git fetch origin
git status
git pull --ff-only
```

If packages like `fusion/` are still missing after pull, obtain the tree via maintainer sync (e.g. rsync) or wait for the push.

---

## Recommended upgrade path (automated)

### Ubuntu lab VM

```bash
cd ~/intellishield-sdn   # or your clone path
chmod +x update.sh quick_start.sh health_check.py
./update.sh
```

### macOS developer host

```bash
cd /path/to/ddos_network
chmod +x update_mac.sh health_check.py
./update_mac.sh
# Then rsync/sync to Ubuntu for live Mininet
```

### Windows

```powershell
cd C:\path\to\ddos_network
powershell -ExecutionPolicy Bypass -File .\update.ps1
```

Live SDN is **not** supported on native Windows — use an Ubuntu VM.

---

## Manual steps (if not using scripts)

### 1. Sync code

```bash
git fetch origin && git pull --ff-only
# OR rsync from maintainer Mac → VM
```

### 2. Dependencies

```bash
python3 -m venv .venv          # optional on lab VM
source .venv/bin/activate      # if using venv
pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -r dashboard/requirements.txt
```

### 3. Environment

```bash
cp -n .env.example .env        # never overwrite existing .env
export PYTHONPATH="$PWD"
export INTELLISHIELD_OPS_PROFILE=lab   # for demos
```

New variables (Release 1.0):

| Variable | Default | Purpose |
|----------|---------|---------|
| `INTELLISHIELD_OPS_PROFILE` | `production` | `lab` freezes conf gate at 60% |
| `INTELLISHIELD_R6_FUSION` | `1` | Set `0` for legacy dual-path |
| `INTELLISHIELD_AUTO_TRAIN_SYNTHETIC` | `0` | Demo ML auto-train |
| `INTELLISHIELD_SUDO_PASS` | unset | Optional dashboard sudo (lab) |

Removed / renamed: **none** of the historical `INTELLISHIELD_*` names were removed in R1.0.

### 4. Log directories

```bash
mkdir -p logs/twin logs/archive logs/experiments logs/models
# JSONL files are created on first write; update scripts may touch empty files
```

### 5. Validate

```bash
python3 health_check.py
python3 -m pytest -q \
  tests/test_shared_contracts_foundation.py \
  tests/test_ops_confidence_calibration.py \
  tests/test_fusion_engine_r62.py \
  tests/test_verification_engine_r71.py \
  tests/test_alerting_core_r81.py
```

### 6. Start

```bash
./quick_start.sh
# or manually:
osken-manager controller/flow_monitor.py
python3 dashboard/api.py
```

---

## Configuration updates

| Change | Action |
|--------|--------|
| Ops profile | Set `INTELLISHIELD_OPS_PROFILE=lab` for reproducible demos |
| Fusion flag | Leave default `1` unless debugging legacy path |
| No central YAML | Thresholds remain in Python config modules |
| Do not overwrite | Scripts never replace existing `.env` |

Migration of old CSV logs: **not required**. New JSONL files are additive.

---

## Storage / database migration

| Store | Migration |
|-------|-----------|
| CSV under `logs/` | Keep; no schema migration tool |
| New JSONL (`alerts.jsonl`, `fused_decisions.jsonl`, …) | Created empty / on first write — **no migration** |
| SQL / Redis | **Not used** — no migration |

Old alerts CSV (`detection_alerts.csv`) remains for legacy `/api/alerts`. R8 uses `logs/alerts.jsonl`.

---

## Validation checklist

- [ ] `health_check.py` → PASS  
- [ ] Scoped pytest → PASS  
- [ ] Controller logs show R4–R8 ACTIVE (on VM with full tree)  
- [ ] `http://127.0.0.1:8080/api/status` responds  
- [ ] (Optional) S2 scenario under sudo with lab profile  

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Missing `fusion/` after `git pull` | Remote not updated — sync full Release 1.0 tree |
| `ModuleNotFoundError: shared_contracts` | `export PYTHONPATH=$PWD` |
| Always `INELIGIBLE` | `export INTELLISHIELD_OPS_PROFILE=lab` |
| Dashboard TestClient errors | `pip install httpx` |
| Scenario button hangs | sudoers or `INTELLISHIELD_SUDO_PASS` |
| Mac has no `osken-manager` | Expected — use Ubuntu VM |

More: [DOCS/release-1.0/TROUBLESHOOTING.md](DOCS/release-1.0/TROUBLESHOOTING.md)

---

## Rollback steps

1. Stop controller/dashboard (`pkill -f osken-manager`, kill dashboard PID).  
2. Restore previous git revision: `git checkout <old-sha>` (only if R1.0 was committed).  
3. Reinstall old pip set if needed from your prior notes.  
4. Keep `.env` backups — scripts do not delete them.  
5. Archive new JSONL if desired: `mkdir -p logs/archive && mv logs/*.jsonl logs/archive/`  

There is no automated database down-migration (file-backed).

---

## FAQ

**Q: Can I only run `git pull`?**  
**A: No** — see [UPDATE_AUDIT.md](UPDATE_AUDIT.md). At minimum: confirm R1.0 packages exist, reinstall deps, set env, run health check.

**Q: Do I need Redis or Postgres?**  
**A: No.**

**Q: Do I need to wipe `logs/`?**  
**A: No.** Additive JSONL is fine.

**Q: Mac vs VM?**  
**A:** Develop/test on Mac; run Mininet live on Ubuntu.
