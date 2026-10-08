# Expected Answers — Quick Reference

One-page revision cheat sheet for viva. Expand using category files for depth.

---

## Project Identity

| Q | A |
|---|---|
| Project name? | IntelliShield SDN — Self-Evolving Hybrid Framework for DDoS Detection and Mitigation in SDN |
| Problem? | DDoS threatens availability; SDN enables programmable defence but most prototypes detect only or use static thresholds |
| Solution? | Closed-loop: monitor → entropy + ML → mitigate → metrics → PPO adapt |
| Phases? | 8 — all implemented |
| Platform? | Ubuntu VM, Mininet, OsKen, OVS, Python |

---

## Numbers to Remember

| Parameter | Value |
|-----------|-------|
| Monitor interval | 5 s |
| ML features | 15 |
| RL state dims | 10 |
| RL action dims | 3 |
| Entropy window | 100 flows |
| Warm-up cycles | ~3 |
| Attack streak | 2 consecutive |
| Block priority | 200 |
| Block timeout | 30–120 s |
| Detection latency | ~5–20 s (steady state) |
| Hosts / switches | 5 hosts, 1 switch |
| Scenarios | S1–S5 |

---

## Technology Stack (30 sec)

Python 3.10, OsKen, OpenFlow 1.3, Mininet, OVS, sklearn (IF+DT+HDBSCAN), NumPy PPO, FastAPI dashboard. **No** Kubernetes, Docker, SQL DB, PyTorch.

---

## Architecture (30 sec)

Single controller hub (`flow_monitor.py`) polls every 5 s → entropy → ML → **R4 correlate → R6 fuse → R7 verify** → mitigation hooks → **R5 RCA / R8 alerts**. CSV/JSONL logs as system of record. Dashboard reads logs; Master Control runs experiments. Phase 3 generates traffic + ground truth. R3 twin is **read-only replay**, not a second controller.

---

## AI (30 sec)

Shannon entropy (5D) for fast collapse detection. IF+DT ensemble on 15 features. ADWIN early drift warning. HDBSCAN batch profiling. PPO tunes pkt/byte/conf thresholds online — does not replace classifiers.

---

## Mitigation (20 sec)

Confidence gate (RL ~80%) + 2-cycle streak → identify top MAC → FLOW_PAIR OpenFlow DROP → hard_timeout auto-expiry → whitelist broadcast/LLDP.

---

## Results (20 sec)

S1: NORMAL, zero blocks. S2: entropy ALERT, ML ATTACK SYN_FLOOD, FLOW_PAIR block. Metrics via `compute_metrics.py`. Validated on Ubuntu VM.

---

## Novelty (30 sec)

Integration + closed loop + surgical mitigation + online RL + explainability + reproducible scenarios/dashboard. We do not claim to invent Shannon entropy or PPO — we claim novel **unified SDN security architecture**.

---

## Kubernetes (10 sec)

**Not used.** Ubuntu VM native processes. `control.py` orchestrates demos. Future scope only.

---

## Database (10 sec)

**No SQL.** CSV/JSON/pickle under `logs/`. Dashboard tail-reads CSV. Archive before experiments.

---

## DevOps (10 sec)

Manual VM deploy. Master Control for ops. `verify_phase7.py` + scenarios for test. No CI/CD in repo.

---

## Release 1.0 novelties (30 sec)

Foundation = one typed vocabulary. R4 is **advisory** (S·T·D·A·P). R6 fuses with reliability×health, not majority vote. R7 is the **only** DROP gate (fail-closed). R5/R8 run after VERIFIED. Ops profile freezes lab RL at 60%. R3 snapshot twin replays logs — **no live OpenFlow**. Detail: `07_Viva/08_Novelty_Questions.md` and full banks in `07_Viva/Novelty_QNA/`.

---

## Limitations (honest)

5 s poll floor; single-switch Mininet; synthetic ML bootstrap; MAC-layer only; not production ISP scale. R3 is COMPLETE as a **Level A snapshot twin** (no twin-launched Mininet / no live OpenFlow replica). Email/Slack alerting not implemented.

---

## Top 20 Rapid-Fire Q&A

**1. What is SDN?** Control plane separated from data plane; global view; programmable via OpenFlow.

**2. Why entropy for DDoS?** Floods collapse traffic diversity; entropy drops measurably.

**3. Why two ML models?** IF = unsupervised anomalies; DT = supervised patterns; ensemble robustness.

**4. Why PPO?** Adapts thresholds when FP/FN balance shifts; static thresholds brittle.

**5. Why FLOW_PAIR?** Surgical block; less collateral than blocking entire host.

**6. Detection latency?** ~5–20 s; poll + warm-up + streak.

**7. False positives?** Streak, confidence gate, whitelist; S1 shows zero blocks.

**8. Central file?** `controller/flow_monitor.py`

**9. Dashboard port?** 8080

**10. OpenFlow version?** 1.3

**11. Attack simulation?** hping3 via traffic_scheduler scenarios

**12. Ground truth?** scenario_logs.csv ATTACK_START/STOP

**13. Metrics script?** scripts/compute_metrics.py

**14. ADWIN purpose?** Early distribution shift alarm

**15. HDBSCAN purpose?** Traffic profiling every ~50 s; not blocking

**16. Explainability?** Explainer attack hints + entropy dimensions

**17. K8s?** No

**18. Database?** No — CSV logs

**19. CI/CD?** No — manual VM test

**20. Future work?** More scenarios, multi-switch, pytest CI, comparison baselines

---

## If You Don't Know

| Situation | Response |
|-----------|----------|
| Unknown attack type | "Out of scope — we validated SYN, UDP, burst, mixed" |
| Production deployment | "Research prototype; documented limitations" |
| K8s/Docker detail | "Not implemented; single VM deployment" |
| Exact latency number | "Typically 5–20 s depending on poll alignment; see metrics_report.json" |
| Why not deep learning | "Interpretability, lab scale, sklearn sufficient" |

---

## Closing Statement (memorise)

> IntelliShield implements a complete eight-phase SDN pipeline — from OpenFlow telemetry through entropy and hybrid ML detection, surgical OpenFlow mitigation, online PPO adaptation, to a live dashboard with reproducible experiments. Release 1.0 adds correlate–fuse–verify before DROP, then RCA and policy alerts on shared contracts. A snapshot twin replays experiment logs; it does not control the switch. The contribution is the integrated, self-evolving, explainable architecture — not an isolated algorithm.

---

## File Pointers (if asked "show me in code")

| Topic | File |
|-------|------|
| Controller hub | `controller/flow_monitor.py` |
| Entropy | `entropy_engine/entropy_detector.py` |
| ML ensemble | `ml_models/anomaly_detector.py` |
| Mitigation | `mitigation/mitigation_engine.py` |
| PPO | `rl_engine/ppo_agent.py` |
| Dashboard API | `dashboard/api.py` |
| Master Control | `dashboard/control.py` |
| Scenarios | `traffic_generator/attack_scenarios.py` |
| Metrics | `scripts/compute_metrics.py` |
| Shared contracts | `shared_contracts/` |
| Correlation | `correlation/engine.py` |
| Fusion | `fusion/engine.py` |
| Verification | `verification/` |
| RCA / XAI | `rca/` , `xai/` |
| Alerting | `alerting/manager.py` |
| Snapshot twin | `twin/` |
