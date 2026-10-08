# IntelliShield SDN

**Self-Evolving Hybrid Framework for DDoS Detection and Mitigation in Software Defined Networks**

Release **1.0** · MCA Final Year / IEEE research laboratory prototype  
OpenFlow **1.3** · OsKen · Mininet · OVS · Python · FastAPI

> Canonical Release 1.0 docs: [`docs/release-1.0/`](docs/release-1.0/)

---

## Project overview

IntelliShield is an SDN security research stack that detects volumetric and flood-style DDoS attacks in a Mininet lab, verifies decisions through a multi-stage gate, optionally installs OpenFlow DROP rules, and emits explainable alerts with root-cause evidence.

It is designed for **controlled laboratory evaluation**, not as a hardened internet-facing product.

---

## Objectives

1. Collect OpenFlow flow/port statistics from a virtual SDN fabric.
2. Detect anomalies via Shannon entropy and an Isolation Forest + Decision Tree ensemble.
3. Correlate cross-layer signals (R4) and fuse detector decisions (R6).
4. Verify before mitigation (R7), then actuate DROP rules safely.
5. Produce RCA/XAI evidence (R5) and persisted alerts (R8) for the live dashboard.

---

## Architecture (high level)

```
Traffic (Mininet S1–S5)
        │
        ▼
┌───────────────────┐
│  flow_monitor.py  │  OsKen OF1.3 controller (:6653)
│  (orchestrator)   │
└─────────┬─────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
 Entropy       ML
    └─────┬─────┘
          ▼
     R4 Correlation (advisory)
          ▼
     R6 Collaborative Fusion
          ▼
     R7 Verification gate
          ▼
     Mitigation (OpenFlow DROP)
          ▼
     R5 RCA  +  R8 Alerts
          ▼
     Dashboard FastAPI (:8080)
```

Details: [ARCHITECTURE.md](docs/release-1.0/ARCHITECTURE.md) · [RUNTIME_FLOW.md](docs/release-1.0/RUNTIME_FLOW.md)

---

## Features

| Area | Capability |
|------|------------|
| Monitoring | Flow/port stats CSV logging |
| Detection | 5-D entropy + 15-D ML features |
| Correlation | R4 advisory co-occurrence scoring |
| Fusion | R6 reliability-aware collaborative decisions |
| Verification | R7 warm-up / confirm / confidence gate |
| Mitigation | Surgical FLOW_PAIR / SRC_MAC DROP |
| Explainability | R5 XAI + RCA JSONL |
| Alerting | R8 severity, dedup, JSONL persistence |
| Ops profiles | `lab` (frozen gate) / `production` (bounded RL) |
| Dashboard | Real-time HTTP API + static UI |
| Digital Twin (R3) | COMPLETE Level A — snapshot / replay / what-if / fidelity (read-only) |

---

## Implemented requirements (Release 1.0 scope)

| ID | Name | Status |
|----|------|--------|
| Foundation | Shared contracts | **COMPLETE** |
| P0.1–P0.6 | Production hardening fixes | **COMPLETE** |
| R4 | Cross-layer correlation | **COMPLETE** (lab live) |
| R5 | XAI + RCA | **COMPLETE** (lab live) |
| R6 | Collaborative fusion | **COMPLETE** (lab live) |
| R7 | Multi-stage verification | **COMPLETE** (lab live) |
| R8 | Automated alerting | **COMPLETE** (lab live) |
| R3 | Digital twin | **COMPLETE (Level A)** — observational snapshot twin; live OpenFlow twin **not** claimed |

**Out of current project scope / deferred**

| ID | Name | Status |
|----|------|--------|
| R2 | SSL zero-day | **Not implemented** |
| R1 / R9 | Roadmap items | **Out of current project scope** |

---

## Folder structure

```
ddos_network/
├── controller/          # OsKen flow monitor (main runtime)
├── entropy_engine/      # Shannon entropy detection
├── ml_models/           # Feature builder + IF/DT ensemble
├── correlation/         # R4
├── fusion/              # R6
├── verification/        # R7
├── mitigation/          # OpenFlow actuation
├── rca/ + xai/          # R5
├── alerting/            # R8
├── dashboard/           # FastAPI + UI
├── traffic_generator/   # Mininet scenarios S1–S5
├── rl_engine/           # PPO threshold adapter
├── shared_contracts/    # Typed DTOs / enums
├── tests/               # pytest suite
├── evaluation/          # Metrics / bundles
├── scripts/             # CLI helpers
├── logs/                # Runtime artifacts
├── docs/release-1.0/    # This Release 1.0 doc suite
├── DOCS/                # Design / roadmap notes
└── IMPLEMENTED/         # Per-requirement implementation notes
```

Full map: [PROJECT_STRUCTURE.md](docs/release-1.0/PROJECT_STRUCTURE.md)

---

## Technology stack

| Layer | Technology |
|-------|------------|
| SDN | OpenFlow 1.3, Open vSwitch, Mininet |
| Controller | OsKen (`osken-manager`) |
| Language | Python 3.10+ (lab VM typically 3.10) |
| ML | scikit-learn (Isolation Forest, Decision Tree) |
| Dashboard | FastAPI, Uvicorn, static HTML |
| Tests | pytest |
| Lab OS | Ubuntu 22.04 VM (often aarch64 under UTM) |

---

## Installation

### Development host (macOS)

```bash
git clone <your-remote> ddos_network
cd ddos_network
python3 -m venv .venv
source .venv/bin/activate
pip install -r dashboard/requirements.txt
pip install pytest httpx scikit-learn   # plus OsKen/Mininet on the lab VM
```

Full VM install: see [`NEW_SYSTEM_INSTALLATION.md`](NEW_SYSTEM_INSTALLATION.md).

### Lab VM (runtime)

Sync this repo to `~/intellishield-sdn` on Ubuntu, install Mininet, OVS, OsKen, and Python deps per the installation guide.

---

## Environment setup

```bash
# Recommended for demos / thesis live runs
export INTELLISHIELD_OPS_PROFILE=lab

# Optional dashboard Mininet control (sudo)
export INTELLISHIELD_SUDO_PASS='your-sudo-password'   # lab only; prefer sudoers NOPASSWD

# Optional: disable R6 fusion (legacy dual-path)
# export INTELLISHIELD_R6_FUSION=0
```

Details: [CONFIGURATION.md](docs/release-1.0/CONFIGURATION.md)

---

## Running the controller

```bash
cd ~/intellishield-sdn   # or this repo path on the VM
export INTELLISHIELD_OPS_PROFILE=lab
osken-manager controller/flow_monitor.py
```

Listens on **TCP 6653**. Expect log lines for ENTROPY / ML / R4–R8 ACTIVE when packages are present.

---

## Running the dashboard

```bash
python3 dashboard/api.py
# open http://<VM-IP>:8080
```

API reference: [API_REFERENCE.md](docs/release-1.0/API_REFERENCE.md)

---

## Running Mininet scenarios

```bash
sudo python3 -m traffic_generator.traffic_scheduler --scenario 1   # S1 … S5
# or
sudo python3 -m traffic_generator.traffic_scheduler --all
```

Requires controller already running and `mn` / OVS available.

---

## Running tests

```bash
# On Mac (with venv)
.venv/bin/python -m pytest -q tests/

# Phase 7 RL smoke
.venv/bin/python verify_phase7.py
```

Guide: [TESTING_GUIDE.md](docs/release-1.0/TESTING_GUIDE.md)

---

## R3 Level A Digital Twin demo

Observational snapshot twin (does **not** launch Mininet / OpenFlow):

```bash
export PYTHONPATH="$PWD"
python3 scripts/r3_level_a_demo.py \
  --logs-dir logs/live_vm_20260728T170330Z/logs/live_runs/slim_20260728T170330Z \
  --scenario S2 \
  --whatif attack_sec=25
```

Fixture path for CI: `tests/fixtures/twin_s2_slim/`.  
Roadmap: [R3_LEVEL_A_COMPLETION_ROADMAP.md](docs/R3_LEVEL_A_COMPLETION_ROADMAP.md).

---

## Runtime flow

See [RUNTIME_FLOW.md](docs/release-1.0/RUNTIME_FLOW.md).

---

## Current status (Release 1.0)

| Gate | Result |
|------|--------|
| Scoped unit/integration tests | Green in acceptance audit (491 passed for scoped set) |
| Live Mininet S1–S5 (lab profile) | Measured E2E: detect → R4/R6/R7 → mitigate → R5/R8 |
| Production readiness (lab) | ~92/100 |
| Research readiness (scoped) | ~94/100 |

Evidence: `logs/live_vm_20260728T181121Z/`, `logs/FINAL_PRODUCTION_ACCEPTANCE_REPORT.md`

---

## Known limitations

- Research / lab prototype — not internet-edge hardened.
- R7 may mark many cycles `INELIGIBLE` when confidence gate fails (by design).
- `verify_phase7.py` may still assert legacy conf `0.80` while runtime default is `0.60` (script drift).
- R3 snapshot twin is **COMPLETE (Level A)**; live OpenFlow twin / twin-launched Mininet remain **not claimed**. R2 SSL zero-day is **not** implemented.
- Dashboard control uses subprocess + optional sudo password env var.

---

## Future roadmap

| Priority | Item |
|----------|------|
| Optional | Align `verify_phase7` with ops profile |
| Deferred | R3 **live OpenFlow** twin DoD (beyond Level A snapshot twin) |
| Deferred | R2 self-supervised zero-day / UNKNOWN |
| Out of scope | R1 / R9 until authorized |

---

## Screenshots

> Placeholder — add captures from `http://<VM-IP>:8080` during a live S2 run:
>
> 1. Dashboard overview / summary  
> 2. Security alerts panel  
> 3. Correlation / fusion panels  
> 4. Blocklist after mitigation  

---

## License

Not explicitly declared in-repo at Release 1.0. Treat as **academic / research use** unless a `LICENSE` file is added by the project owner.

---

## Acknowledgements

Built as an MCA final-year / IEEE-oriented SDN security laboratory project using Mininet, Open vSwitch, and OsKen.

---

## Upgrading from an older clone

**Do not rely on `git pull` alone.** See [UPDATE_AUDIT.md](UPDATE_AUDIT.md) (verdict: **NO**) and [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md).

```bash
./update_mac.sh    # macOS
./update.sh        # Ubuntu lab VM
# Windows: .\update.ps1
python3 health_check.py
./quick_start.sh   # lab / when osken-manager available
```

Fresh installs: [INSTALLATION.md](INSTALLATION.md) · [NEW_SYSTEM_INSTALLATION.md](NEW_SYSTEM_INSTALLATION.md)

---

## Documentation index

| Document | Path |
|----------|------|
| Update audit | [UPDATE_AUDIT.md](UPDATE_AUDIT.md) |
| Upgrade guide | [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md) |
| Installation | [INSTALLATION.md](INSTALLATION.md) |
| Architecture | [docs/release-1.0/ARCHITECTURE.md](docs/release-1.0/ARCHITECTURE.md) |
| Developer guide | [docs/release-1.0/DEVELOPER_GUIDE.md](docs/release-1.0/DEVELOPER_GUIDE.md) |
| Runtime flow | [docs/release-1.0/RUNTIME_FLOW.md](docs/release-1.0/RUNTIME_FLOW.md) |
| Testing | [docs/release-1.0/TESTING_GUIDE.md](docs/release-1.0/TESTING_GUIDE.md) |
| Release notes | [docs/release-1.0/RELEASE_1.0.md](docs/release-1.0/RELEASE_1.0.md) |
| Full suite TOC | [docs/release-1.0/README.md](docs/release-1.0/README.md) |
