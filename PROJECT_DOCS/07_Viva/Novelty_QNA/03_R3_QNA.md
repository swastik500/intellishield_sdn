# R3 — Digital Twin: Knowledge Base Q&A

**Related:** [../../02_Novelties/08_R3_Digital_Twin.md](../../02_Novelties/08_R3_Digital_Twin.md) · `R3_DIGITAL_TWIN.md` · `GLOSSARY.md`

Answers reflect the current `twin/` package. Twin-owned Mininet launch and live OpenFlow sync are **Not implemented** (fail-closed / out of snapshot-twin scope). R1 and R9 are **out of current project scope**.

> **PROJECT_DOCS copy** — adapted from `R3_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

R3 is a **snapshot-driven, read-only digital twin**: it models the lab (profile, topology, S1–S5 plans), ingests completed experiment logs, replays expected vs observed events, and gates isolated model candidates. It does **not** control the live SDN.

---

## Architecture

```
Completed logs/  →  capture_snapshot  →  TwinObservation
                         ↓
              replay_scenario | simulate_whatif
                         ↓
              validate_candidate / ingest_experiment_logs
                         ↓
              GET /api/digital-twin/*  (READ_ONLY)
```

---

## Q&A — What R3 is

**Q. Is Mininet “the digital twin”?**  
**A.** No. Mininet + `TrafficScheduler` are the **execution backend**. The twin is `twin/` (profile, plans, snapshot, replay, validation). Calling raw Mininet “the twin” is explicitly rejected in `twin/inventory.py`.

**Q. What fidelity level is claimed?**  
**A.** LEVEL 3: runtime-connected **read-only** twin via completed logs and dashboard GET APIs. Not LEVEL 4 live OpenFlow sync. Not LEVEL 5 closed-loop control.

**Q. Does the controller import twin?**  
**A.** No. `controller/flow_monitor.py` has no twin import. Isolation is intentional.

**Q. Can the twin launch S1–S5 attacks?**  
**A.** No. `TwinExperimentRunner(mode="live_mininet")` fails closed (`LIVE_MININET_NOT_RUN`). Lab traffic still uses `sudo python3 -m traffic_generator.traffic_scheduler`.

**Q. What is a snapshot?**  
**A.** `capture_snapshot(logs_dir)` reads bounded CSV/JSONL from a completed experiment directory, writes `logs/twin/snapshots/<id>/`, and populates `TwinObservation`.

**Q. What does replay mean?**  
**A.** Event replay of `scenario_logs` against expected S1–S5 timeline events (START / ATTACK_* / END). It is **not** packet-level replay.

**Q. What is what-if?**  
**A.** Plan-space comparison (`simulate_whatif`) of planner overrides (e.g. `attack_sec`) vs observed attack-window duration. Detectors are **not** re-executed.

**Q. How is training data labeled?**  
**A.** `TwinDatasetGenerator` uses scenario/attack windows only — never ML, R6, or mitigation outcomes as ground truth.

**Q. How are candidates validated?**  
**A.** `validate_candidate(candidate) → ValidationResult` (offline synthetic metrics) or `ingest_experiment_logs(logs_dir, candidate=...)` (IEEE `metrics_report.json` or `ml_predictions.csv`). Missing required metrics → SKIPPED, not PASS.

**Q. Does the twin overwrite production models?**  
**A.** No. Candidates must stay off `logs/models/*.pkl`. Tests assert mtimes.

**Q. Can the dashboard run shell via twin APIs?**  
**A.** No. GET-only. POST `/api/digital-twin/exec` is 404/405.

**Q. Which GET APIs exist?**  
**A.** `/api/digital-twin/profiles|runs|runs/{id}|validation|datasets|stats|snapshots|snapshots/{id}|replays|simulations`. UI refresh shows runs + SNAP rows.

**Q. Is TRAFFIC_FIDELITY always PASS after a live run?**  
**A.** No. That gate needs observed SYN/UDP rates. Snapshot mean packet rate is not wired as SYN rate (would be a false compare). Status is often **NOT_AVAILABLE**.

**Q. Is R3 part of Release 1.0 live DoD (S1–S5 VERIFIED blocks)?**  
**A.** The R1.0 acceptance pipeline is Foundation + P0 + R4–R8 + mitigation. R3 is an additional plane: code and tests exist; twin-orchestrated Mininet is **not** required for that DoD.

**Q. Does R3 implement R1 AutoML or R9 adaptive learning?**  
**A.** No. It only exposes validation/dataset extension points. Do not start R1/R9 from twin code.

**Q. Where are implementation notes?**  
**A.** `IMPLEMENTED/R3_DIGITAL_TWIN_IMPLEMENTATION.md` and sub-phase `IMPLEMENTED/R3_*.md`. Recovery/final reports: `R3_DIGITAL_TWIN_RECOVERY_AUDIT.md`, `R3_DIGITAL_TWIN_FINAL_COMPLETION_REPORT.md`.
