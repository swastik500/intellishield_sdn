# P0 Hardening

**PROJECT_DOCS novelty copy.** Source: `P0.md`.  
Related: [00_Overview.md](00_Overview.md) · [../05_Testing/01_Testing_Strategy.md](../05_Testing/01_Testing_Strategy.md) · [../07_Viva/Novelty_QNA/02_P0_QNA.md](../07_Viva/Novelty_QNA/02_P0_QNA.md)

P0 items are production-hardening fixes applied before/alongside R4–R8.

---

## P0.1 — RL observation scale

**Problem:** ML confidence on 0–100 vs RL expecting 0–1 broke state normalization.  
**Fix:** Normalize confidence in `rl_engine/rl_env.py`.  
**Tests:** `tests/test_rl_observation_p01.py`

## P0.2 — Scenario 4 burst semantics

**Problem:** Burst scenario timing/metadata needed correctness for evaluation windows.  
**Tests:** `tests/test_scenario4_p02.py`  
**Code:** `traffic_generator/attack_scenarios.py`

## P0.3 — Experiment windows / ground truth

**Problem:** Metrics must join scenario/attack logs into consistent attack windows.  
**Code:** `evaluation/experiment_windows.py`  
**Tests:** `tests/test_experiment_windows_p03.py`

## P0.4 — Mitigation strategy selection

**Problem:** Choose FLOW_PAIR vs SRC_MAC safely from attack hints.  
**Code:** `mitigation/mitigation_engine.py`  
**Tests:** `tests/test_mitigation_strategy_p04.py`

## P0.5 — Experiment bundles

**Problem:** Reproducible artifact packaging for paper/lab.  
**Code:** `evaluation/experiment_bundle.py`, `scripts/bundle_experiment.py`  
**Tests:** `tests/test_experiment_bundle_p05.py`

## P0.6 — IEEE metrics fields

**Problem:** Stable metrics CSV/JSON schema for evaluation.  
**Code:** `scripts/compute_metrics.py` + evaluation helpers  
**Tests:** `tests/test_ieee_metrics_p06.py`

---

## Runtime integration

All P0 behaviors are active in the default controller/mitigation/RL/eval paths used in Release 1.0.

## Status

**COMPLETE** for Release 1.0.
