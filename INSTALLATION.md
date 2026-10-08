# Installation Guide — IntelliShield SDN Release 1.0

Related: [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md) · [NEW_SYSTEM_INSTALLATION.md](NEW_SYSTEM_INSTALLATION.md) · [UPDATE_AUDIT.md](UPDATE_AUDIT.md)

This guide covers **fresh** installs and points upgraders to the upgrade path.

---

## Choose your path

| Situation | Document / script |
|-----------|-------------------|
| Brand-new Ubuntu 22.04 lab VM | This guide § Ubuntu + `./update.sh` |
| Existing older clone | [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md) |
| macOS coding host | § Mac + `./update_mac.sh` |
| Windows | § Windows + `update.ps1` (no live Mininet) |
| Detailed VM cookbook | [NEW_SYSTEM_INSTALLATION.md](NEW_SYSTEM_INSTALLATION.md) |

---

## System requirements

| Component | Required? | Notes |
|-----------|-----------|-------|
| Python 3.10+ | **Yes** | 3.10 on Ubuntu 22.04 lab |
| pip / venv | **Yes** | venv recommended on Mac; optional on lab VM |
| OsKen (`osken-manager`) | **Yes** (live SDN) | `apt install python3-os-ken` |
| Mininet (`mn`) | **Yes** (live SDN) | `apt install mininet` |
| Open vSwitch | **Yes** (live SDN) | `openvswitch-switch` |
| OpenFlow 1.3 | **Yes** | Via OVS + OsKen |
| FastAPI / Uvicorn | **Yes** (dashboard) | pip |
| NumPy / scikit-learn / pandas / scipy / joblib | **Yes** | pip — see `requirements.txt` |
| pytest / httpx | **Yes** (tests) | `requirements-dev.txt` |
| Redis | **No** | Not implemented |
| PostgreSQL | **No** | Not implemented |
| Docker | **No** | Out of scope for R1.0 core |
| Graphviz | **No** | Not required at runtime |

---

## Fresh installation — Ubuntu 22.04 (lab VM)

### 1. OS packages

```bash
sudo apt update
sudo apt install -y \
  git build-essential \
  python3 python3-pip python3-venv \
  mininet openvswitch-switch python3-os-ken \
  hping3 iperf
sudo systemctl enable --now openvswitch-switch
```

### 2. Clone / sync project

```bash
cd ~
git clone <REPO_URL> intellishield-sdn
cd intellishield-sdn
# If Release 1.0 is not yet on the remote, sync the full tree from the maintainer.
```

### 3. Python dependencies

```bash
chmod +x update.sh quick_start.sh health_check.py
./update.sh
```

Or manually:

```bash
pip3 install --upgrade pip
pip3 install -r requirements-dev.txt
```

### 4. Environment

```bash
cp -n .env.example .env
export PYTHONPATH="$HOME/intellishield-sdn"
export INTELLISHIELD_OPS_PROFILE=lab
# optional: INTELLISHIELD_SUDO_PASS or sudoers for traffic_scheduler
```

### 5. ML models (if missing)

```bash
PYTHONPATH=$PWD python3 -m ml_models.model_trainer --synthetic
# or INTELLISHIELD_AUTO_TRAIN_SYNTHETIC=1 for demo-only auto-train
```

### 6. Run

```bash
./quick_start.sh
# Terminal A: osken-manager controller/flow_monitor.py
# Terminal B: python3 dashboard/api.py
# Terminal C: sudo python3 -m traffic_generator.traffic_scheduler --scenario 2
```

Dashboard: `http://<VM-IP>:8080`

---

## Fresh installation — macOS

```bash
brew install python@3.12 git   # or use system python3 ≥ 3.10
git clone <REPO_URL> ddos_network
cd ddos_network
chmod +x update_mac.sh health_check.py
./update_mac.sh
source .venv/bin/activate
export PYTHONPATH="$PWD"
export INTELLISHIELD_OPS_PROFILE=lab
python3 health_check.py
python3 dashboard/api.py   # UI/API only
```

**Mininet / OsKen / OVS:** not expected on macOS. Sync the same commit/tree to an Ubuntu VM for live experiments.

---

## Fresh installation — Windows

```powershell
# Install Python 3.10+ from python.org
git clone <REPO_URL> ddos_network
cd ddos_network
powershell -ExecutionPolicy Bypass -File .\update.ps1
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = (Get-Location).Path
python health_check.py
python dashboard\api.py
```

Live SDN: use Ubuntu VM (UTM / VirtualBox / Hyper-V).

---

## Upgrade installation

See [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md). Short form:

```bash
# After code sync:
./update.sh          # Linux
./update_mac.sh      # Mac
.\update.ps1         # Windows
```

---

## Virtual environment

| Host | Recommendation |
|------|----------------|
| Mac | Always use `.venv` |
| Ubuntu lab | Optional; `NEW_SYSTEM_INSTALLATION.md` historically used system pip3 |
| Windows | Use `.venv` |

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
```

---

## Mininet / OsKen / Dashboard / Testing

| Layer | Command |
|-------|---------|
| OVS | `systemctl status openvswitch-switch` |
| Controller | `osken-manager controller/flow_monitor.py` |
| Dashboard | `python3 dashboard/api.py` → `:8080` |
| Traffic | `sudo python3 -m traffic_generator.traffic_scheduler --all` |
| Health | `python3 health_check.py` |
| Tests | `pytest -q tests/` or scoped set in `update.sh` |

---

## Dependency rationale (`requirements.txt`)

| Package | Why |
|---------|-----|
| `numpy` | Features, RL, detectors |
| `scikit-learn` | Isolation Forest, Decision Tree, HDBSCAN |
| `pandas` | Evaluation / metrics |
| `scipy` | ML utilities |
| `joblib` | Model persistence |
| `fastapi` / `uvicorn` / `pydantic` | Dashboard HTTP API |
| `psutil` | Optional controller host metrics |
| `pytest` / `httpx` (dev) | Test suite + FastAPI TestClient |

Not required: Redis, Postgres clients, torch, river, standalone `hdbscan` PyPI package.
