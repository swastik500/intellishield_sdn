# Limitations

## 1. Overview

This document states the **honest boundaries** of IntelliShield SDN as a research prototype. Acknowledging limitations strengthens academic credibility and guides future work.

---

## 2. Environmental Limitations

### 2.1 Laboratory emulation only

| Limitation | Impact |
|------------|--------|
| Mininet virtual network | Does not reflect physical switch ASIC performance, buffering, or line-rate constraints |
| Single VM deployment | No high-availability or distributed controller validation |
| Ubuntu 22.04 target | Results may differ on other OS or cloud instances |

**Implication:** Throughput, latency, and scalability numbers apply to **emulated SDN**, not production ISP or data-centre networks.

### 2.2 Single-switch topology

The validated topology is **one Open vSwitch bridge (DPID 1) with five hosts**.

| Not tested | Risk |
|------------|------|
| Multi-switch fabrics | Controller scalability unknown |
| Cross-switch attack paths | Mitigation may not generalise |
| WAN latency | Remote controller effects not measured |

---

## 3. Detection Limitations

### 3.1 Poll-bound latency floor

The 5-second `MONITOR_INTERVAL` sets a **hard floor** on detection responsiveness:

- Best-case steady-state latency: ~5 s
- With warm-up and streak confirmation: up to ~25–30 s after controller restart

**Implication:** Sub-second detection is **not achievable** with current settings without architectural changes.

### 3.2 Short burst attacks (S4)

An 8-second SYN burst may occur between poll cycles or before the entropy window stabilises.

**Implication:** Minimum detectable attack duration is **bounded by poll interval + window size** — very short pulses may evade detection.

### 3.3 ADWIN false positives

With `delta=0.002`, ADWIN is sensitive to normal traffic variance and may fire drift alerts during benign fluctuations.

**Implication:** ADWIN is better positioned as an **early warning** than a standalone detector; requires tuning for continuous operation.

### 3.4 ML training data

| Limitation | Detail |
|------------|--------|
| Synthetic bootstrap | Default models trained on generated data, not production traffic |
| Limited attack diversity | Only SYN, UDP, ICMP, burst patterns implemented |
| Decision Tree overfit risk | 100% synthetic test accuracy may not generalise |
| No online retraining | ML models are static during a session; only RL thresholds adapt |

**Implication:** ML performance on **unseen attack types** (DNS amplification, HTTP flood, slowloris) is **unvalidated**.

### 3.5 HDBSCAN latency

Clustering runs every ~50 seconds as a **batch profiler**, not a real-time detector.

**Implication:** HDBSCAN results are useful for analysis and labelling, not for sub-minute response.

---

## 4. Mitigation Limitations

### 4.1 MAC-layer blocking only

Mitigation operates on **Ethernet source/destination MAC** matches via OpenFlow.

| Not addressed | Example |
|---------------|---------|
| IP spoofing at scale | Randomised source IPs with common gateway MAC |
| Distributed attacks | Thousands of unique sources |
| Application-layer attacks | Low-rate HTTP abuse |
| Encrypted traffic analysis | Payload inspection not performed |

### 4.2 Collateral risk on shared MAC

If multiple hosts share infrastructure (NAT, virtualisation) behind one MAC, `SRC_MAC` blocking could affect legitimate co-tenants.

**Mitigation:** `FLOW_PAIR` reduces but does not eliminate this risk.

### 4.3 Confidence gating trade-off

Raising the RL confidence threshold (default 80%) reduces false positives but may **delay or skip** blocks on ambiguous attacks.

### 4.4 No automatic model rollback

If RL adjusts thresholds poorly over a long session, there is no automatic rollback to known-good defaults without controller restart.

---

## 5. Integration and Engineering Limitations

### 5.1 No formal CI/CD test suite

Testing relies on:

- Manual VM runs
- `verify_phase7.py` (RL only)
- Module `__main__` self-tests
- Scenario acceptance tests

**Gap:** Phases 1–6 lack automated pytest/regression in CI.

### 5.2 Log-based persistence

| Limitation | Consequence |
|------------|-------------|
| CSV append-only | No concurrent write safety beyond single controller |
| No database | Complex queries require offline Python scripts |
| Header corruption risk | Mitigated by fallback headers, but archiving during writes can still cause gaps |
| Disk growth | Long runs require manual archival |

### 5.3 Dashboard security

| Gap | Detail |
|-----|--------|
| No authentication | HTTP on :8080 open to anyone on network |
| No TLS | Credentials in `INTELLISHIELD_SUDO_PASS` if used |
| Sudo delegation | Scenario runs require elevated privileges |

**Implication:** Dashboard is for **lab use only**, not internet-facing deployment.

### 5.4 macOS dev host gap

Full runtime validation requires the Ubuntu VM. macOS lacks OsKen, Mininet, and (often) numpy — limiting local pre-commit testing.

---

## 6. Evaluation Limitations

### 6.1 Limited attack taxonomy

Implemented scenarios cover volumetric L3/L4 floods only:

- SYN flood
- UDP flood
- ICMP flood
- Burst SYN
- Mixed SYN + UDP

**Not evaluated:** amplification, reflection, protocol exploitation, IoT botnet simulation, low-and-slow attacks.

### 6.2 Ground truth granularity

`scenario_logs.csv` records attack start/stop at **second resolution** aligned with scenario scripts — not per-packet ground truth.

**Implication:** Detection latency has ±5 s uncertainty tied to poll alignment.

### 6.3 No comparison baseline

The repository does not include side-by-side benchmarks against:

- Static threshold-only IDS
- Commercial SDN controllers with security apps
- Published IEEE systems

**Implication:** Results demonstrate **feasibility**, not **superiority** over existing solutions.

### 6.4 Single-operator experiments

Results reflect one VM configuration (192.168.64.5) and one operator's experiment discipline (archive-first workflow). Multi-reviewer reproduction is documented but not independently verified in this repository.

---

## 7. Reinforcement Learning Limitations

| Limitation | Detail |
|------------|--------|
| Custom NumPy PPO | Not industry-standard implementation; limited hyperparameter tuning |
| Online learning only | No offline training on historical attack corpora |
| Reward shaping sensitivity | Reward function manually designed; may not converge optimally |
| No safety constraints | Thresholds bounded but RL can still oscillate |
| Limited state space | 10-dim state may omit important context (port, protocol, cluster label) |

---

## 8. Scope Boundaries (Explicitly Out of Scope)

Per project scope documentation:

- Production enterprise deployment
- Multi-switch WAN orchestration
- Hardware traffic generators
- Zero-trust policy management
- Encrypted telemetry pipelines
- Comprehensive DDoS family coverage
- 24-hour soak / chaos testing
- Twin-launched Mininet or live OpenFlow from `twin/` (R3 is observational)
- Email / Slack / Redis alerting backends
- R1 AutoML, R2 SSL zero-day, R9 adaptive learning (not in this release)

---

## 9. Summary Table

| Category | Key limitation |
|----------|----------------|
| Environment | Mininet lab, single switch, single VM |
| Detection speed | 5 s poll floor; warm-up + streak delays |
| ML generalisation | Synthetic training; limited attack types |
| Mitigation scope | MAC-layer OpenFlow only |
| Security | No dashboard auth/TLS |
| Evaluation | No external baseline comparison |
| Testing | Manual VM validation; pytest for Foundation/R4–R8/twin cores |
| Snapshot twin (R3) | COMPLETE Level A — log ingest/replay/what-if/fidelity; no live OF replica |

---

## 10. How to Present Limitations in Academic Writing

> IntelliShield SDN is validated as a laboratory-scale SDN research prototype. Detection latency is bounded by the 5-second OpenFlow polling interval and confirmation gates. Machine learning models are bootstrapped on synthetic data and evaluated against five emulated flood scenarios in Mininet. Mitigation is limited to Ethernet-flow OpenFlow rules on a single switch. These constraints are appropriate for demonstrating architectural feasibility but do not constitute production security certification.

Acknowledging these boundaries demonstrates research maturity and aligns with the prototype scope defined in the project documentation.
