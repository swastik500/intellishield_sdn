# R3 — Snapshot Digital Twin

**PROJECT_DOCS novelty copy.** Source: `R3_DIGITAL_TWIN.md`.  
Related: [00_Overview.md](00_Overview.md) · [../07_Viva/Novelty_QNA/03_R3_QNA.md](../07_Viva/Novelty_QNA/03_R3_QNA.md)

**Status:** COMPLETE (Level A — snapshot / observational twin). Twin does **not** launch Mininet. Live OpenFlow sync is **not claimed**.

Evidence: `scripts/r3_level_a_demo.py`, `logs/twin/evidence/level_a_20260930/`, SOC/legacy twin UI (fidelity + replays). Related roadmap: `docs/R3_LEVEL_A_COMPLETION_ROADMAP.md`.

---

## Motivation

Lab experiments need a **reproducible software representation** of the Mininet environment (topology, S1–S5 plans, seeds, fingerprints) plus **observational** ingest of completed runs — without a second traffic generator or a second control plane.

## Architecture

```
Completed lab logs (TrafficScheduler / OsKen — not started by twin)
        ↓
capture_snapshot → TwinObservation
        ↓
replay_scenario  |  simulate_whatif
        ↓
evidence_from_logs / validate_candidate
        ↓
logs/twin/{snapshots,replays,simulations,candidates,datasets}/
        ↓
GET /api/digital-twin/*   (READ_ONLY)
```

Package: `twin/`. Tests: `tests/test_twin_*.py` (R3.1–R3.6).

## Safety

Read-only vs the live SDN. No OpenFlow, no `MitigationEngine`, no overwrite of `logs/models/`. POST `/api/digital-twin/exec` does not exist.

## Honest non-claims

| Claim | Status |
|-------|--------|
| Packet-level network simulator | No |
| Live OpenFlow replica | No |
| Twin-launched Mininet / attacks | No (by design) |
| Used before mitigation DROP | No |
| Observational ingest of lab logs | Yes (code + tests + Level A evidence) |
| Level A demo / fidelity UI | Yes (2026-09-30) |

R1 AutoML and R9 adaptive learning are **not** implemented inside the twin.
