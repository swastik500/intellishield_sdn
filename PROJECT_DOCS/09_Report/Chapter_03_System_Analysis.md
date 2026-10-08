# Chapter 3 — System Analysis

## 3.1 Introduction

System analysis defines *what* IntelliShield must do before design and implementation. This chapter covers stakeholder needs, functional and non-functional requirements, feasibility, and constraints derived from the laboratory deployment model.

## 3.2 Stakeholders

| Stakeholder | Interest |
|-------------|----------|
| Network operator (lab) | Detect attacks, block attackers, monitor health |
| Researcher / student | Reproducible experiments, metrics for report |
| Examiner / viva panel | Explainable decisions, verifiable architecture |
| Developer | Modular code, clear phase boundaries |

## 3.3 Functional Requirements

### FR-1 — Traffic Monitoring

- Poll OpenFlow flow statistics at configurable intervals (default 5 s).
- Compute per-flow packet rate, byte rate, and duration.
- Separate control-plane traffic (ARP, LLDP) from monitored flows.

### FR-2 — Entropy Detection

- Maintain sliding windows over five traffic dimensions.
- Classify entropy state as NORMAL, WARNING, or ALERT.
- Emit structured alerts with dimension-level detail.

### FR-3 — Traffic Simulation

- Generate benign baseline traffic (ICMP ping, light HTTP).
- Execute attack scenarios: SYN flood, UDP flood, burst, mixed sequential.
- Log ground-truth attack windows to `scenario_logs.csv`.

### FR-4 — Machine Learning Classification

- Build 15-dimensional feature vectors from flow and entropy data.
- Classify traffic as NORMAL or ATTACK with confidence score.
- Provide attack type hints (e.g., SYN_FLOOD) via explainability module.

### FR-5 — Automated Mitigation

- Install OpenFlow DROP rules on confirmed attacks.
- Use FLOW_PAIR matching (source + destination MAC).
- Apply confidence-based `hard_timeout` (30–120 s) for auto-recovery.
- Enforce warm-up, streak confirmation, and confidence gates.

### FR-6 — Advanced Analytics

- ADWIN drift detection on four traffic metrics.
- HDBSCAN batch clustering for traffic profiling.
- PPO reinforcement learning for threshold adaptation.

### FR-7 — Dashboard and Control

- Display live alerts, blocks, entropy state, and ML decisions.
- Master Control: run scenarios, restart controller, compute metrics, retrain models.
- REST API for programmatic access.

### FR-8 — Metrics and Logging

- Persist detection events, blocks, and scenario ground truth.
- Compute detection latency, mitigation latency, false positive rate.

## 3.4 Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1 | Detection latency (steady state) | 5–20 s |
| NFR-2 | False positive blocks on normal traffic | Zero (S1) |
| NFR-3 | Modularity | Eight independent phases |
| NFR-4 | Reproducibility | Scripted scenarios + archived logs |
| NFR-5 | Explainability | Entropy dimensions + ML hints |
| NFR-6 | Resource footprint | Single VM (Ubuntu 22.04) |

## 3.5 Use Case Analysis

### UC-1: Normal Operation

1. Controller polls switch statistics.
2. Entropy remains NORMAL; ML classifies NORMAL.
3. No mitigation rules installed.
4. Dashboard shows green status.

### UC-2: SYN Flood Attack

1. Attacker host floods victim via `hping3`.
2. Entropy collapses on source/flow dimensions → ALERT.
3. ML confirms ATTACK with SYN_FLOOD hint.
4. After streak confirmation, FLOW_PAIR DROP rule installed.
5. Metrics record detection and mitigation latency.

### UC-3: Experiment Execution

1. Operator selects scenario from Master Control.
2. System archives prior logs, restarts controller, runs scenario.
3. `compute_metrics.py` produces latency and accuracy summary.

## 3.6 Feasibility Study

### Technical Feasibility

| Component | Assessment |
|-----------|------------|
| OsKen + OpenFlow 1.3 | Mature open-source stack |
| Mininet emulation | Standard SDN research tool |
| sklearn ML | Well-documented, CPU-efficient |
| NumPy PPO | Lightweight, no GPU required |
| FastAPI dashboard | Proven Python web framework |

**Verdict:** Technically feasible on a single Linux VM.

### Operational Feasibility

- Deployment path documented (`USAGE_GUIDE.md`, `PROJECT_DOCS/04_Implementation/10_Deployment.md`).
- Browser access to dashboard on port 8080.
- No external cloud dependencies.

### Economic Feasibility

- Zero licensing cost (open-source stack).
- Runs on commodity hardware / VM (UTM, VirtualBox).

## 3.7 Constraints and Assumptions

### Constraints

1. **Single-switch topology** — one Open vSwitch, five hosts.
2. **5-second poll interval** — detection latency floor.
3. **File-based persistence** — no SQL database.
4. **Lab network only** — not hardened for internet exposure.
5. **No Kubernetes/Docker** — direct VM process deployment.

### Assumptions

1. Attack traffic is emulated with `hping3` inside Mininet.
2. Controller has uninterrupted connectivity to the switch.
3. Operators archive logs between experiment runs to prevent cross-run contamination.
4. ML models are pre-trained or retrained via dashboard; warm-up allows three cycles before mitigation.

## 3.8 Risk Analysis

| Risk | Impact | Mitigation |
|------|--------|------------|
| False positive block | Service disruption | Confidence gates, warm-up, streak confirmation |
| Missed short burst (S4) | Undetected attack | Documented limitation; reduce poll interval in future |
| Log cross-run bleed | Incorrect metrics | Archive-first workflow |
| Controller crash | Detection gap | Dashboard restart + PID management |

## 3.9 Summary

System analysis confirms IntelliShield is feasible as a laboratory SDN security prototype. Requirements map directly to the eight implementation phases. Constraints are explicit and honest — single-switch Mininet scope, file-based storage, no production hardening — setting appropriate expectations for evaluation in Chapter 6.

*Detailed scope: `PROJECT_DOCS/01_Project_Overview/04_Scope.md`*
