# Speaking Notes

Slide-by-slide narration for a **15–18 minute** presentation. Adjust pace for your panel; bold phrases are emphasis points.

---

## Slide 1 — Title

> Good morning/afternoon. I am [Name], and today I present **IntelliShield SDN** — a self-evolving hybrid framework for DDoS detection and mitigation in Software Defined Networks. This is my MCA final-year / IEEE research prototype.

---

## Slide 2 — Problem

> Distributed Denial-of-Service attacks remain one of the most critical threats to network availability. Traditional intrusion detection systems often sit **outside** the data path and cannot **programmatically block** malicious flows at line rate.
>
> Software Defined Networks change that — the controller sees **global flow statistics** and can install **OpenFlow rules** in real time. But most academic prototypes still rely on **single-method detectors** or **static thresholds** that break when traffic patterns shift.
>
> **Our problem:** How do we build an SDN-native system that **detects**, **explains**, **mitigates**, and **adapts** — in one reproducible pipeline?

---

## Slide 3 — Objectives

> We defined six objectives:
>
> 1. **Continuous telemetry** from OpenFlow flow and port statistics.
> 2. **Multi-dimensional entropy detection** for fast anomaly signalling.
> 3. **Hybrid machine learning** — unsupervised plus supervised — for attack classification.
> 4. **Automated surgical mitigation** via OpenFlow DROP rules.
> 5. **Adaptive threshold tuning** using reinforcement learning.
> 6. **Reproducible evaluation** with predefined scenarios and automated metrics.
>
> Every objective is **implemented and validated** in our repository across eight phases.

---

## Slide 4 — Scope

> **In scope:** A Mininet laboratory with five hosts and one Open vSwitch, OpenFlow 1.3, OsKen controller, and five attack scenarios — normal baseline, SYN flood, UDP flood, burst, and mixed attacks.
>
> **Out of scope:** Production ISP deployment, multi-datacenter orchestration, and hardware switch benchmarking. We position this honestly as a **research prototype** — not a commercial product.

---

## Slide 5 — Literature Gap

> Existing SDN security work often covers **one layer well** — entropy-only IDS, ML-only classifiers, or detection without mitigation.
>
> Few integrate **entropy plus ML plus drift detection plus RL adaptation** in a **single controller loop**. Fewer still provide **operator dashboards** and **reproducible experiment scripts** suitable for IEEE-style evaluation.
>
> That integration gap is what IntelliShield addresses.

---

## Slide 6 — Novelty (preview)

> Our novelty is **system-level**, not a single algorithm:
>
> - **Hybrid detection** — entropy, ML, ADWIN, HDBSCAN working together.
> - **Closed loop** — detect → confirm → block → measure → adapt.
> - **Surgical FLOW_PAIR mitigation** — block attacker-to-victim only.
> - **PPO threshold adaptation** — the system **self-evolves**.
> - **Dashboard plus Master Control** — full lifecycle from the browser.
>
> I will return to novelty in detail before Q&A.

---

## Slide 7 — Architecture Overview

> [Point to diagram]
>
> At the bottom is the **data plane** — Mininet hosts generating normal and attack traffic through Open vSwitch.
>
> Above that is the **control plane** — our OsKen controller running `flow_monitor.py`, which polls statistics every **five seconds**.
>
> Detection and mitigation logic runs as **Python hooks** inside that controller — entropy, ML, ADWIN, HDBSCAN, PPO.
>
> At the top is the **presentation layer** — a FastAPI dashboard reading CSV logs and offering a Master Control panel to run experiments.

---

## Slide 8 — Eight Phases

> We organised the implementation into eight phases:
>
> | Phase | Role |
> |-------|------|
> | 1 | Flow statistics monitoring |
> | 2 | Shannon entropy detection |
> | 3 | Traffic and attack simulation |
> | 4 | Hybrid ML ensemble |
> | 5 | Automated mitigation |
> | 6 | ADWIN drift + HDBSCAN clustering |
> | 7 | PPO reinforcement learning |
> | 8 | Live dashboard |
>
> Phases one through seven execute **inside the controller**. Phase eight is a **separate process** that reads the logs they produce.

---

## Slide 9 — Closed Loop

> [Point to loop diagram]
>
> Every five seconds: **monitor** flow stats → **detect** via entropy and ML → **decide** with confidence and streak gates → **mitigate** with OpenFlow DROP → **log** everything to CSV → **evaluate** with our metrics script → **adapt** thresholds via PPO reward.
>
> This is not a batch offline system — RL runs **online** during live traffic.

---

## Slide 10 — Technology Stack

> The stack is deliberately **lean**:
>
> - **Python 3.10** on **Ubuntu 22.04**
> - **OsKen** for OpenFlow 1.3 control
> - **Mininet** and **Open vSwitch** for emulation
> - **scikit-learn** for Isolation Forest, Decision Tree, and HDBSCAN
> - **NumPy-only PPO** — no PyTorch dependency
> - **FastAPI** for the dashboard API
>
> We use **CSV and JSON files** for persistence — no separate database server. That keeps the prototype portable and easy to audit.

---

## Slide 11 — Detection Layers

> Detection is **defence in depth**:
>
> 1. **Entropy** — five dimensions collapse during floods; fast and interpretable.
> 2. **ADWIN** — detects **distribution shift** one cycle before ML may react.
> 3. **ML ensemble** — Isolation Forest catches novel patterns; Decision Tree classifies known attacks.
> 4. **HDBSCAN** — batch clusters traffic into NORMAL, ATTACK, SUSPICIOUS every ~50 seconds.
>
> Entropy asks *"is diversity collapsing?"* ML asks *"does this match attack patterns?"* ADWIN asks *"did the distribution just change?"*

---

## Slide 12 — Reinforcement Learning

> Static thresholds fail when baseline traffic changes. Our **PPO agent** adjusts three thresholds every cycle:
>
> - Packet-rate warning threshold
> - Byte-rate warning threshold
> - ML confidence gate for mitigation
>
> **Reward** rewards true positives and penalises false positives and missed attacks. Weights persist to `ppo_weights.pkl`. Mitigation uses the **RL confidence gate** — default eighty percent — not a fixed sixty.

---

## Slide 13 — Controller Hub

> All intelligence converges in **one file**: `controller/flow_monitor.py`.
>
> Optional phases import with graceful fallback — if sklearn is missing, ML disables but monitoring continues.
>
> A **warm-up period** of three cycles lets the entropy window fill before ML and mitigation activate. An **attack streak** of two consecutive ATTACK cycles prevents single-spike false blocks.

---

## Slide 14 — Mitigation Policy

> When ATTACK is confirmed:
>
> 1. Identify top packet-rate source MAC from flow stats.
> 2. Check whitelist — never block broadcast or LLDP.
> 3. Choose **FLOW_PAIR** for SYN/UDP floods — surgical src-plus-dst block.
> 4. Install OpenFlow DROP at priority 200 with **hard_timeout** 30 to 120 seconds.
>
> Legitimate traffic between other host pairs **continues uninterrupted**.

---

## Slide 15 — Experiment Setup

> We validate on an Ubuntu VM with IntelliShield at `~/intellishield-sdn/`.
>
> Five scenarios, each logging ground-truth timestamps to `scenario_logs.csv`. Our metrics script joins those windows with detection and block events.
>
> **Critical practice:** archive logs before each run to prevent cross-contamination.

---

## Slide 16 — Results

> **Scenario 1 — Normal:** Entropy near 1.0, ML NORMAL, **zero blocks**. This proves no false positives on baseline after we fixed the light ICMP profile.
>
> **Scenario 2 — SYN flood:** Source entropy collapses to ~0.04, entropy ALERT, ML ATTACK at ~85% with SYN_FLOOD hint, FLOW_PAIR block installed.
>
> **Detection latency:** typically five to twenty seconds — bounded by our five-second poll interval plus confirmation gates.
>
> **Mitigation** is effectively immediate once the block decision is made — OpenFlow installs in milliseconds.

---

## Slide 17 — Metrics

> `compute_metrics.py` produces IEEE-ready numbers:
>
> - Entropy detection latency
> - ML detection latency
> - Mitigation latency
> - False-positive block count
>
> Results export to `metrics_report.json` and appear on the dashboard at `/api/metrics`.

---

## Slide 18 — Live Demo

> I will now demonstrate the **Master Control dashboard**:
>
> 1. Archive logs and restart the controller.
> 2. Run Scenario 1 — show NORMAL baseline.
> 3. Run Scenario 2 — show entropy collapse, ML ATTACK, and surgical block.
> 4. Compute and display metrics.
>
> [Transition to demo — follow `02_Demo_Script.md`]

---

## Slide 19 — Limitations

> We are transparent about limitations:
>
> - **Five-second poll floor** on detection speed.
> - **Single-switch Mininet** — not multi-fabric production.
> - **ML bootstrapped on synthetic data** — real-log retraining available via `--from-csv`.
> - **Dashboard has no authentication** — lab use only.
>
> These are appropriate for a research prototype and are documented in our project reports.

---

## Slide 20 — Future Work

> Near-term: more attack scenarios, pytest CI, multi-switch topology.
>
> Medium-term: faster event-driven detection, ML retraining pipeline, dashboard auth.
>
> Long-term: comparative benchmarks against static-threshold and ML-only baselines for IEEE rigour.

---

## Slide 21 — Conclusion

> IntelliShield SDN implements a **complete eight-phase pipeline** — from OpenFlow telemetry to entropy and hybrid ML detection, through surgical OpenFlow mitigation, online PPO adaptation, and browser-based experiment control.
>
> We validated detection and mitigation across five scenarios with reproducible metrics and a live dashboard.
>
> **Thank you.** I welcome your questions and will now proceed to the live demonstration.

---

## Q&A — Quick Answers

| Question | Answer |
|----------|--------|
| Why entropy? | DDoS collapses source/destination diversity — measurable via Shannon entropy. |
| Why two ML models? | IF finds anomalies without labels; DT classifies known patterns; ensemble is more robust. |
| Why PPO? | Adapts thresholds online when FP/FN balance shifts; no manual retuning. |
| Why not deep learning? | Lab scale; sklearn + NumPy PPO is sufficient and dependency-light. |
| Detection latency? | ~5–20 s steady state; poll interval + warm-up + streak confirmation. |
| Kubernetes? | Not implemented — single VM process deployment. |
| Database? | CSV/JSON files under `logs/` — no SQL. |
| How prevent false blocks? | Confidence gate, streak confirmation, whitelist, S1 validation. |

---

## Delivery Tips

- **Pause** on entropy gauge during demo when ALERT fires — let examiners see the transition.
- **Do not apologise** for Mininet — frame it as controlled reproducible evaluation.
- If demo fails, show **archived logs** and **metrics_report.json** as backup evidence.
- Keep **controller terminal visible** on second monitor for console banners during S2.
