# Chapter 5 — Implementation

## 5.1 Introduction

This chapter describes how IntelliShield SDN was built: technology choices, phase-wise implementation, key algorithms, configuration, and deployment. Exhaustive module documentation resides in `PROJECT_DOCS/04_Implementation/11_Module_Reference.md`; here we focus on implementation rationale and critical code paths.

## 5.2 Technology Stack

| Layer | Technology | Version / Notes |
|-------|------------|-----------------|
| Language | Python 3.10+ | All controller and analytics code |
| SDN Controller | OsKen | OpenFlow 1.3 application host |
| Emulation | Mininet 2.3 | Five-host star topology |
| Data plane | Open vSwitch | Kernel datapath |
| ML | scikit-learn | Isolation Forest, Decision Tree |
| RL | NumPy (custom PPO) | No PyTorch/TensorFlow dependency |
| Clustering | hdbscan | Batch profiling |
| Web | FastAPI + Uvicorn | Dashboard on port 8080 |
| Attack tool | hping3 | SYN/UDP flood generation |

**Not implemented:** Kubernetes, Docker, SQL database, TLS authentication.

## 5.3 Development Environment

| Environment | Role |
|-------------|------|
| macOS (dev host) | Code editing, static analysis |
| Ubuntu 22.04 VM (`~/intellishield-sdn/`) | Runtime: controller, Mininet, dashboard |

Synchronisation between hosts uses `rsync` or manual copy. All runtime validation occurs on the VM.

## 5.4 Phase-Wise Implementation

### Phase 1 — Flow Statistics (`controller/`)

`IntelliShieldFlowMonitor` extends OsKen's `app_manager.RyuApp` (OsKen-compatible API). On each `MONITOR_INTERVAL`:

- Sends `OFPFlowStatsRequest` to datapath.
- Parses replies in `flow_stats.py`; updates `_flows` dictionary.
- Filters ARP/LLDP from monitored traffic.
- Rejects flows with external (non-lab) IP subnets via safety guard.

### Phase 2 — Entropy Engine (`entropy_engine/`)

`EntropyDetector` maintains `WINDOW_SIZE` (10) samples per dimension. Shannon entropy computed with `math.log2`; composite score is weighted sum. States:

- **NORMAL** — entropy above warning threshold.
- **WARNING** — marginal collapse.
- **ALERT** — significant collapse on one or more dimensions.

Alerts written to `logs/entropy_alerts.csv`.

### Phase 3 — Traffic Generator (`traffic_generator/`)

Five scenarios defined in `attack_scenarios.py`:

| ID | Name | Attack type |
|----|------|-------------|
| S1 | Normal baseline | ICMP only (light) |
| S2 | SYN flood | TCP SYN to victim |
| S3 | UDP flood | UDP packets to victim |
| S4 | Burst flood | 8 s SYN burst |
| S5 | Mixed attack | Sequential SYN then UDP |

`scenario_runner.py` logs `ATTACK_START` / `ATTACK_END` timestamps to `scenario_logs.csv` for metrics alignment.

### Phase 4 — Machine Learning (`ml_models/`)

**Feature vector (15 dimensions):**

1–5: Flow rates (packet, byte, duration, src count, dst count)  
6–10: Entropy values per dimension  
11–15: Derived ratios and deltas

**Ensemble:** `0.4 × IsolationForest_score + 0.6 × DecisionTree_prob` → NORMAL/ATTACK label.

**Explainer:** Rule-based hints mapping feature patterns to SYN_FLOOD, UDP_FLOOD, or GENERIC_ATTACK.

Models persisted as `models/isolation_forest.pkl`, `models/decision_tree.pkl`.

### Phase 5 — Mitigation (`mitigation/`)

`MitigationEngine.handle_alert()` evaluates gates, then `rule_builder` constructs:

```
match: eth_src=<attacker_mac>, eth_dst=<victim_mac>
action: DROP
hard_timeout: 30–120 s (confidence tier)
```

`block_manager` tracks active blocks; expired rules removed automatically.

### Phase 6 — Advanced Analytics (`advanced_analytics/`)

- **ADWIN:** Pure-Python implementation; four parallel detectors (packet_rate, flow_count, entropy_score, byte_rate).
- **HDBSCAN:** Runs every 10 monitor cycles on buffered feature vectors; labels clusters NORMAL/ATTACK heuristically.

### Phase 7 — Reinforcement Learning (`rl_engine/`)

Custom NumPy PPO with:

- **State:** normalised traffic metrics + current thresholds.
- **Action:** adjust packet_rate_thresh, byte_rate_thresh, ml_conf_gate.
- **Reward:** +1 TP, −2 FP, −1 FN per cycle.

`rl_adapter.py` clamps thresholds to safe ranges before applying to mitigation gates.

### Phase 8 — Dashboard (`dashboard/`)

FastAPI application exposing:

- `GET /api/status` — live system state.
- `GET /api/alerts`, `/api/blocks`, `/api/ml` — telemetry.
- `POST /api/control/run_scenario` — Master Control scenario execution.
- `POST /api/control/restart_controller` — PID-based controller restart.
- `POST /api/control/compute_metrics` — invoke `scripts/compute_metrics.py`.
- `POST /api/control/retrain` — retrain ML models.

Static UI in `dashboard/static/index.html` polls every 5 s.

### Release 1.0 novelty packages

These sit on the controller cycle after entropy/ML and **before** OpenFlow DROP (except R5/R8, which run after verification). Full manuals: `PROJECT_DOCS/02_Novelties/`.

| Package | Role |
|---------|------|
| `shared_contracts/` | Typed DTOs shared by later planes |
| `correlation/` | Advisory S·T·D·A·P score (does not DROP) |
| `fusion/` | Reliability×health fusion |
| `verification/` | Fail-closed eligibility gate; only VERIFIED may mitigate |
| `xai/` + `rca/` | Explainability and root-cause chain |
| `alerting/` | Policy alerts (default: VERIFIED) |
| `twin/` | Read-only snapshot twin; no OpenFlow |

Evidence is written as JSONL under `logs/` (`correlation_results.jsonl`, `fused_decisions.jsonl`, `verification_trace.jsonl`, `root_cause_reports.jsonl`, `alerts.jsonl`). Twin artefacts live under `logs/twin/`.

## 5.5 Key Implementation Parameters

| Parameter | Default | Location |
|-----------|---------|----------|
| `MONITOR_INTERVAL` | 5 s | `flow_monitor.py` |
| `WINDOW_SIZE` | 10 | `entropy_detector.py` |
| Warm-up cycles | 3 | `flow_monitor.py` |
| Attack streak | 2 | `flow_monitor.py` |
| HDBSCAN interval | 10 cycles | `hdbscan_clusterer.py` |
| Ensemble weights | 0.4 / 0.6 | `ensemble.py` |
| Block timeout | 30–120 s | `mitigation_engine.py` |

## 5.6 Configuration and Scripts

| File | Purpose |
|------|---------|
| `config/settings.py` | Centralised thresholds and paths |
| `scripts/start_all.sh` | Launch controller + Mininet + dashboard |
| `scripts/compute_metrics.py` | Detection/mitigation latency from logs |
| `verify_phase7.py` | Automated Phase 7 validation (40+ checks) |

## 5.7 Security Considerations (Lab Scope)

- Dashboard binds to VM IP without authentication — acceptable for isolated lab.
- External IP safety guard prevents blocking non-lab addresses.
- No secrets in repository; no `.env` credentials.

*Full security notes: `PROJECT_DOCS/04_Implementation/08_Security.md`*

## 5.8 Deployment Procedure

1. Clone repository to `~/intellishield-sdn/` on Ubuntu VM.
2. Install dependencies (`requirements.txt`).
3. Run `scripts/start_all.sh` or use dashboard Master Control.
4. Access dashboard at `http://<vm-ip>:8080`.
5. Archive `logs/` before each experiment run.

*Full deployment guide: `PROJECT_DOCS/04_Implementation/10_Deployment.md`*

## 5.9 Implementation Challenges and Resolutions

| Challenge | Resolution |
|-----------|------------|
| Metrics cross-run contamination | Archive-first workflow; in-window timestamp matching in `compute_metrics.py` |
| False positives on startup | Warm-up cycles before ML/mitigation |
| Duplicate entropy hook | Single registration in `flow_monitor.py` |
| Controller restart self-kill | PID file excludes own process in `control.py` |
| S4 burst near poll boundary | Documented as stress-test limitation |

## 5.10 Code Statistics

- **~40 Python modules** across eight phases, plus Release 1.0 packages (`correlation/`, `fusion/`, `verification/`, `rca/`, `xai/`, `alerting/`, `twin/`, `shared_contracts/`).
- **Hub file:** `controller/flow_monitor.py` — orchestrates the eight-phase loop and novelty-plane hooks.
- **Verification:** `verify_phase7.py` (Phase 7) plus `tests/test_twin_*.py` and Foundation/R4–R8 unit tests.

## 5.11 Summary

IntelliShield was implemented as a monolithic OsKen controller application with modular packages per phase, file-based persistence, and a FastAPI dashboard for experiment control. Release 1.0 adds a **correlate → fuse → verify → mitigate → explain → alert** path on shared contracts, and a **read-only snapshot twin**. The implementation prioritises integrability and reproducibility over distributed microservice complexity — appropriate for the MCA project scope.
