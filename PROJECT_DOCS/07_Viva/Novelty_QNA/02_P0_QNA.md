# P0 Hardening Q&A — Release 1.0 (P0.1–P0.6)

Related: [../../02_Novelties/02_P0_Hardening.md](../../02_Novelties/02_P0_Hardening.md) · [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md) · [FOUNDATION_QNA.md](01_Foundation_QNA.md) · [R7_QNA.md](06_R7_QNA.md) · `GLOSSARY.md`

P0 items are **production-hardening fixes** applied before and alongside R4–R8. All are **COMPLETE** for Release 1.0 and active in default controller/mitigation/RL/eval paths.

> **PROJECT_DOCS copy** — adapted from `P0_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## P0 Overview

### Q1. What is “P0” in IntelliShield?

**Purpose:** Priority-zero engineering fixes that unblock reliable detection, mitigation, RL, and IEEE evaluation — without being full requirement planes (R4–R8).

**Reason:** Research code accumulated scale mismatches (ML 0–100 vs RL 0–1), inconsistent attack windows, and non-reproducible experiment packaging.

**Implementation:** Six numbered items P0.1–P0.6, each with dedicated tests `test_*_p0N.py`.

**Runtime:** All active in Release 1.0 default paths.

**Limits:** P0 does not add new detectors (R2) or live twin fidelity (R3 DoD).

**Related:** [P0.md](../../02_Novelties/02_P0_Hardening.md)

---

### Q2. Why were P0 fixes done before R7/R8?

**Purpose:** Ensure mitigation gate, RL adapter, and metrics rest on correct primitives.

**Reason:** R7 reuses P0.4 strategy selection; P0.1 fixes RL state that influences confidence gate; P0.3/P0.6 define ground-truth alignment for paper metrics.

**Implementation:** P0 merged alongside R4–R8 integration in controller poll cycle.

**Runtime order (conceptual):** detect → fuse → **P0.4 strategy available to R7** → verify → mitigate → **P0.6 metrics offline**.

**Related:** `RUNTIME_FLOW.md`

---

### Q3. Where are P0 tests located?

| Item | Test file |
|------|-----------|
| P0.1 | `tests/test_rl_observation_p01.py` |
| P0.2 | `tests/test_scenario4_p02.py` |
| P0.3 | `tests/test_experiment_windows_p03.py` |
| P0.4 | `tests/test_mitigation_strategy_p04.py` |
| P0.5 | `tests/test_experiment_bundle_p05.py` |
| P0.6 | `tests/test_ieee_metrics_p06.py` |

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

## P0.1 — RL Observation Scale

### Q4. What problem did P0.1 fix?

**Purpose:** Correct ML confidence scaling in the RL observation vector.

**Reason:** `AnomalyDetector.predict()` returns confidence on **0–100** scale; RL PPO state encoder expects **[0, 1]** normalization. Unscaled values saturated dimension [4] and broke policy learning/threshold adaptation.

**Implementation:** `_normalize_ml_confidence()` in `rl_engine/rl_env.py`.

**Runtime:** Every RL state build divides values > 1.0 by 100; values already in [0,1] pass through.

**Limits:** Does not change ML model output — only observation encoding.

**Related:** `rl_engine/rl_env.py`, [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q35

---

### Q5. What is the RL state vector layout after P0.1?

**Purpose:** Document 10-D normalized observation for PPO.

**Dimensions (all target [0,1]):**
- [0] packet_rate_mean / 200,000
- [1] byte_rate_mean / 10,000,000
- [2] entropy_score (already 0–1)
- [3] flow_count / 20
- **[4] ml_confidence — P0.1 normalized**
- [5] pkt_threshold / 5,000
- [6] byte_threshold / 5,000,000
- [7] conf_threshold (0–1)
- [8] recent_attack_count / 10
- [9] recent_fp_count / 10

**Implementation:** Constants `_PKT_NORM`, `_BYTE_NORM`, etc. in `rl_env.py`.

**Runtime:** `build_state(...)` calls `_normalize_ml_confidence(ml_confidence)`.

**Related:** Phase 7 RL docs in `rl_engine/rl_env.py` header

---

### Q6. Why does P0.1 matter for R7 verification?

**Purpose:** RL adapts confidence gate threshold; wrong observations → wrong gate → spurious INELIGIBLE or false VERIFIED.

**Reason:** Ops profile clamps RL output (55–75% production, 60% frozen lab), but garbage state still perturbs adaptation within bounds.

**Implementation:** Controller passes ML confidence into RL env; adapted threshold flows to R7 via `min_confidence_percent` override.

**Runtime:** Many live cycles show `confidence_below_threshold` when gate > fused confidence.

**Related:** [R7_QNA.md](06_R7_QNA.md), [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md)

---

### Q7. How is P0.1 tested?

**Purpose:** Regression guard for scale logic.

**Tests:** `tests/test_rl_observation_p01.py` — verifies 0–100 inputs map to [0,1], legacy 0–1 passthrough, edge cases (0, 100, >100 handling).

**Runtime:** Run `pytest tests/test_rl_observation_p01.py`.

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q8. P0.1 example — confidence 85 from ML

**Input:** `ml_confidence=85.0`

**Implementation:** `85.0 > 1.0` → `85.0 / 100.0 = 0.85`

**Runtime state[4]:** `0.85`

**Reason:** Preserves relative ordering while matching RL training assumptions.

**Related:** `_normalize_ml_confidence` in `rl_engine/rl_env.py`

---

### Q9. What are P0.1 performance characteristics?

**Purpose:** Negligible overhead per poll cycle.

**Implementation:** Single float comparison and optional division — O(1).

**Runtime:** Called once per RL state build (~every MONITOR_INTERVAL when RL enabled).

**Limits:** Not on hot OpenFlow path — stats aggregation dominates.

**Related:** `RUNTIME_FLOW.md`

---

## P0.2 — Scenario 4 Burst Semantics

### Q10. What problem did P0.2 fix?

**Purpose:** Correct burst attack timing and metadata for Scenario 4 (S4).

**Reason:** Burst attacks are **short** (default 8s) — evaluation windows and detectors depend on accurate `ATTACK_START` / `ATTACK_STOP` lifecycle events in `scenario_logs.csv`.

**Implementation:** `scenario_4_burst_attack()` in `traffic_generator/attack_scenarios.py`.

**Runtime:** Logs `SCENARIO_4_BURST` with burst duration, rate, optional multi-burst support.

**Limits:** S4 is a sensitivity test — easy to miss if monitor interval is large.

**Related:** `GLOSSARY.md` — **Burst (S4)**

---

### Q11. What is Scenario 4 research motivation?

**Purpose:** Stress-test detection latency on **narrow temporal windows**.

**Reason:** IEEE metrics include time-to-first-detection; burst floods challenge entropy/ML reactive paths.

**Implementation:** `baseline_sec` normal traffic → `ATTACK_START` → burst for `burst_sec` → `ATTACK_STOP` → optional inter-burst gap.

**Runtime:** Default burst 8s vs MONITOR_INTERVAL ~5s — may require 2 cycles to detect.

**Related:** P0.3 attack windows, P0.6 metrics

---

### Q12. What parameters does `scenario_4_burst_attack` expose?

**Key params:** `burst_sec` (default 8), `burst_rate`, `burst_count`, `inter_burst_interval_sec`, `baseline_sec`.

**Purpose:** Reproducible burst patterns for ablation studies.

**Implementation:** Uses `PROFILE_BURST` from traffic profiles; logs session profile via `log_session_profile`.

**Runtime:** Invoked from scenario menu key `"4"` in attack scenarios registry.

**Related:** `traffic_generator/attack_scenarios.py`

---

### Q13. How does P0.2 interact with P0.3 experiment windows?

**Purpose:** Ground-truth windows must match logged scenario events.

**Reason:** P0.2 ensures `ATTACK_START`/`ATTACK_STOP` align with actual burst launch/stop.

**Implementation:** P0.3 `load_experiment_windows()` parses `scenario_logs.csv` using event sets `ATTACK_START_EVENTS`, `ATTACK_STOP_EVENTS`.

**Runtime:** Misaligned S4 logs → wrong attack windows → inflated false positive rates in metrics.

**Related:** P0.3 below

---

### Q14. How is P0.2 tested?

**Tests:** `tests/test_scenario4_p02.py` — burst timing, event names, metadata consistency.

**Run:** `pytest tests/test_scenario4_p02.py`

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q15. P0.2 runtime example

```bash
# Mininet lab — select scenario 4 from traffic generator menu
# Observe logs/scenario_logs.csv for:
#   ATTACK_START — Burst attack — 8s
#   ATTACK_STOP  — Burst attack stopped
```

**Purpose:** Verify burst lifecycle for metrics join.

**Limits:** Network emulation timing may jitter ±1s — P0.6 uses grace windows.

**Related:** `TROUBLESHOOTING.md`

---

## P0.3 — Experiment Windows / Ground Truth

### Q16. What problem did P0.3 fix?

**Purpose:** Single source of truth for attack-window parsing across training labels and IEEE metrics.

**Reason:** Duplicate/inconsistent window logic in `label_inference.py` and `compute_metrics.py` caused metric disagreements.

**Implementation:** `evaluation/experiment_windows.py` — `AttackWindow`, `load_experiment_windows()`, `load_attack_log_windows()`.

**Runtime:** Consumed by ML label inference and `scripts/compute_metrics.py`.

**Limits:** Requires ground-truth CSV logs from traffic generator — not runtime ML labels.

**Related:** `GLOSSARY.md` — **Attack window**, **Ground truth**

---

### Q17. What inputs does P0.3 consume?

| File | Role |
|------|------|
| `logs/scenario_logs.csv` | ATTACK_START / ATTACK_STOP lifecycle |
| `logs/attack_logs.csv` | LAUNCHED/RUNNING rows + duration fallback |

**Purpose:** Derive contiguous `[attack_start, attack_stop]` intervals per scenario.

**Implementation:** Event sets include aliases (`ATTACK_BEGIN`, `ATTACK1_START`, …).

**Runtime:** `AttackWindow.contains(ts, pad_sec)` for label/metric joins.

**Related:** `evaluation/experiment_windows.py`

---

### Q18. What is an `AttackWindow` dataclass?

**Fields:** `scenario`, `attack_start`, `attack_stop`, `source` (provenance).

**Purpose:** Typed window with `duration_sec`, `contains()`, `to_metrics_dict()`.

**Reason:** Metrics script expects dict shape with datetime objects for latency math.

**Implementation:** Frozen dataclass in P0.3 module.

**Runtime:** One scenario may yield multiple windows (multi-burst S4).

**Related:** P0.2, P0.6

---

### Q19. Why is ground truth separate from detector output?

**Purpose:** Supervised evaluation and IEEE reporting require independent reference intervals.

**Reason:** Using detector alerts as “truth” circularly inflates accuracy.

**Implementation:** Windows from traffic generator logs only.

**Runtime:** False positives computed as detections outside windows (+ grace).

**Limits:** Log clock skew handled via `grace_sec` in metrics (default 60s).

**Related:** `scripts/compute_metrics.py`

---

### Q20. How is P0.3 tested?

**Tests:** `tests/test_experiment_windows_p03.py` — CSV parsing, edge cases, window containment, multi-scenario.

**Run:** `pytest tests/test_experiment_windows_p03.py`

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q21. P0.3 config and constants

**`MONITOR_INTERVAL_DEFAULT = 5`** — referenced for padding/heuristics.

**Timestamp format:** `%Y-%m-%d %H:%M:%S` (legacy CSV — unchanged by Foundation ISO policy).

**Purpose:** Align metric grace with controller poll cadence.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q25

---

### Q22. P0.3 performance

**Purpose:** Offline batch parsing — not on controller hot path.

**Implementation:** CSV scan O(rows); typical lab logs < 10k rows — milliseconds.

**Runtime:** Called at metrics computation and training label generation.

**Limits:** Very large logs unbounded — acceptable for lab scope.

**Related:** P0.6

---

## P0.4 — Mitigation Strategy Selection (FLOW_PAIR / SRC_MAC)

### Q23. What problem did P0.4 fix?

**Purpose:** Safe automatic choice between **FLOW_PAIR** (surgical) and **SRC_MAC** (aggressive) blocking.

**Reason:** Blind SRC_MAC blocks all traffic from attacker MAC — collateral damage on shared hosts. Blind FLOW_PAIR misses volumetric floods targeting many flows.

**Implementation:** `MitigationEngine._select_block_strategy()` in `mitigation/mitigation_engine.py`.

**Runtime:** Also injected into R7 via `VerificationEngine` identify/strategy callables — **no duplicated P0.4 logic**.

**Related:** [R7_QNA.md](06_R7_QNA.md), [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md)

---

### Q24. What is the P0.4 decision policy?

**Purpose:** Map `attack_hint` + victim MAC to strategy.

**Rules (simplified):**
- Unknown/empty hint → `SRC_MAC` if no dst MAC else `FLOW_PAIR`
- `SYN_FLOOD`, `UDP_FLOOD`, `ICMP_FLOOD`, `BURST` → **FLOW_PAIR** (when victim known)
- `VOLUMETRIC_FLOOD` → **SRC_MAC**
- Default unknown hints → **FLOW_PAIR** if dst known

**Implementation:** Sets `FLOW_PAIR_ATTACK_HINTS`, `SRC_MAC_ATTACK_HINTS`.

**Runtime:** R7 identification stage must succeed before VERIFIED; strategy informs mitigation after gate.

**Limits:** Protected MACs still enforced in `flow_blocker` — P0.4 does not bypass.

**Related:** `mitigation/mitigation_engine.py`

---

### Q25. Why FLOW_PAIR for SYN/UDP/ICMP/BURST?

**Purpose:** Surgical block of attack-specific src→dst pair.

**Reason:** Preserves other flows from same source when attack is targeted flood to one victim.

**Research motivation:** SDN value proposition — fine-grained flow rules vs coarse ACLs.

**Runtime:** `block_flow_pair()` installs OpenFlow DROP with pair match.

**Related:** `GLOSSARY.md` — **FLOW_PAIR**

---

### Q26. Why SRC_MAC for volumetric floods?

**Purpose:** Attacker may saturate many victim flows simultaneously.

**Reason:** Single FLOW_PAIR rule leaves other victim flows unblocked under volumetric attack.

**Implementation:** `VOLUMETRIC_FLOOD` hint → SRC_MAC.

**Runtime:** `block_src_mac()` — aggressive, shorter path to containment.

**Limits:** Higher false collateral risk — R7 confidence gate mitigates false blocks.

**Related:** [R7_QNA.md](06_R7_QNA.md)

---

### Q27. How does P0.4 relate to confidence-based block duration?

**Purpose:** Strategy selects **what** to block; confidence selects **how long**.

**Implementation:** Timeouts: ≥90% → 120s; ≥75% → 60s; ≥60% → 30s; <60% → warning only (no block).

**Runtime:** Both gates must pass — R7 VERIFIED + MIN_CONFIDENCE_TO_BLOCK (60%).

**Related:** `mitigation/mitigation_engine.py` thresholds

---

### Q28. How is P0.4 tested?

**Tests:** `tests/test_mitigation_strategy_p04.py` — hint matrix, dst MAC presence, edge hints.

**Run:** `pytest tests/test_mitigation_strategy_p04.py`

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q29. P0.4 runtime example

**Input:** `attack_hint=SYN_FLOOD`, `dst_mac=00:00:00:00:00:02`

**Output strategy:** `FLOW_PAIR`

**OpenFlow action:** `block_flow_pair(attacker_mac, dst_mac)`

**Purpose:** Block only SYN flood path to victim.

**Related:** `RUNTIME_FLOW.md`

---

## P0.5 — Experiment Bundles

### Q30. What problem did P0.5 fix?

**Purpose:** Reproducible artifact packaging for paper/lab submission.

**Reason:** IEEE reviewers expect hashed manifests tying logs, models, metrics, and config to a single experiment ID.

**Implementation:** `evaluation/experiment_bundle.py`, CLI `scripts/bundle_experiment.py`.

**Runtime:** Optional post-step from `compute_metrics.py --bundle`.

**Limits:** Bundles collect **present** files only — missing artifacts skipped silently with manifest notes.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q44

---

### Q31. What goes into an experiment bundle?

**Artifact paths include (when present):**
- Ground truth: `scenario_logs.csv`, `attack_logs.csv`, `traffic_logs.csv`
- Controller telemetry: `flow_stats.csv`, `port_stats.csv`, `controller_stats.csv`
- Entropy/ML: `entropy_logs.csv`, `ml_predictions.csv`, `ml_alerts.csv`, models
- Mitigation: `mitigation_actions.csv`, `mitigation_summary.json`
- Analytics/RL: `drift_alerts.csv`, `rl_decisions.csv`, `ppo_weights.pkl`
- Metrics: `metrics_report.json`, `metrics_report.csv`, `paper_tables.md`

**Purpose:** One tarball/directory per run with `experiment_manifest.json`.

**Implementation:** `BUNDLE_VERSION = "1.0.0"`; SHA256 per file via `sha256_file()`.

**Related:** `evaluation/experiment_bundle.py`

---

### Q32. What is in `experiment_manifest.json`?

**Typical contents:** timestamp, bundle version, git commit (if available), file hashes, window summary from P0.3, metrics snapshot.

**Purpose:** Prove artifact integrity for viva/paper defense.

**Reason:** Prevents “we ran it again and numbers shifted” challenges.

**Runtime:** Generated at bundle creation time.

**Related:** P0.6 metrics report embedding

---

### Q33. How is P0.5 tested?

**Tests:** `tests/test_experiment_bundle_p05.py` — manifest creation, hashing, partial artifacts.

**Run:** `pytest tests/test_experiment_bundle_p05.py`

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q34. P0.5 usage example

```bash
python3 scripts/compute_metrics.py --logs-dir logs --bundle
# Or standalone:
python3 scripts/bundle_experiment.py --logs-dir logs
```

**Purpose:** Produce timestamped bundle directory under logs or specified output.

**Limits:** Large pkl models increase bundle size — expected for ML reproducibility.

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q35. P0.5 performance

**Purpose:** Offline I/O bound operation.

**Implementation:** Streaming SHA256 in 64KiB chunks; file copy via shutil.

**Runtime:** Seconds for typical lab log set; minutes if huge traffic captures included.

**Limits:** Not invoked during live attack handling.

**Related:** N/A hot path

---

## P0.6 — IEEE Metrics Fields

### Q36. What problem did P0.6 fix?

**Purpose:** Stable metrics CSV/JSON schema for IEEE-style evaluation tables.

**Reason:** Ad-hoc print statements and shifting column names break paper regeneration scripts.

**Implementation:** `scripts/compute_metrics.py` + `evaluation/ieee_metrics.py` enrichment.

**Runtime:** Reads P0.3 windows; joins detection/mitigation CSV logs; writes `metrics_report.json` / `.csv`.

**Limits:** Metrics are **offline** — not real-time dashboard KPIs.

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q37. What metrics does P0.6 compute?

**Per attack window (via `analyse_run()`):**
- Time to first detection (entropy, ML, fused paths as available)
- Time to first mitigation / block
- Detection inside window vs false positive flags
- Latency statistics with grace period

**Aggregate report:** averages across scenarios, scenario breakdown, IEEE enrichment fields.

**Purpose:** Quantify SDN security research claims (detection latency, mitigation latency, FP rate).

**Related:** `scripts/compute_metrics.py` docstring

---

### Q38. How does P0.6 use P0.3 windows?

**Purpose:** Align detections to ground-truth intervals.

**Implementation:** `_load_scenario_windows()` → `load_experiment_windows()` → list of dicts for `analyse_run()`.

**Runtime:** `_first_in_window()` finds first alert/detection timestamp within `[start, stop]`.

**Grace:** `grace_sec` default 60s — tolerates log/timing skew.

**Related:** P0.3 Q16–Q18

---

### Q39. What outputs does P0.6 produce?

| Output | Role |
|--------|------|
| `logs/metrics_report.json` | Machine-readable full report |
| `logs/metrics_report.csv` | Tabular summary for spreadsheets |
| `logs/paper_tables.md` | Markdown tables for paper draft |
| stdout | Human-readable summary via `print_report()` |

**Purpose:** Dual audience — scripts and authors.

**Related:** P0.5 bundle inclusion

---

### Q40. How is P0.6 tested?

**Tests:** `tests/test_ieee_metrics_p06.py` — field presence, window join logic, enrichment.

**Run:** `pytest tests/test_ieee_metrics_p06.py`

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q41. P0.6 CLI example

```bash
python3 scripts/compute_metrics.py
python3 scripts/compute_metrics.py --logs-dir ~/intellishield-sdn/logs
python3 scripts/compute_metrics.py --json-out logs/metrics_report.json
python3 scripts/compute_metrics.py --grace-sec 45 --bundle
```

**Purpose:** Regenerate metrics after each lab run.

**Limits:** Requires complete log set from a full scenario run — partial logs yield partial metrics.

**Related:** `TROUBLESHOOTING.md`

---

### Q42. P0.6 research motivation for viva

**Talking points:**
- “We evaluate detection-to-mitigation latency against scripted ground truth, not self-referential alerts.”
- “Grace windows acknowledge Mininet/OS timing jitter.”
- “Metrics schema is versioned in JSON for reproducible paper tables.”

**Related:** [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md) (when present)

---

### Q43. P0.6 performance

**Purpose:** Batch analytics after experiment.

**Implementation:** CSV loads + datetime parsing + window scans — O(alerts × windows).

**Runtime:** Sub-second to few seconds on typical lab logs.

**Limits:** `MAX_SCAN`-style bounds live in R8 persistence, not P0.6 — unbounded CSV read for metrics.

**Related:** [R8_QNA.md](08_R8_QNA.md)

---

## Cross-Cutting P0 Topics

### Q44. Do P0 changes alter OpenFlow behavior directly?

**Partially:** P0.4 affects which DROP rule is installed after R7 VERIFIED.

**Not directly:** P0.1 RL obs, P0.2 burst logs, P0.3 windows, P0.5 bundles, P0.6 metrics are indirect or offline.

**Purpose:** Clarify runtime impact for operators.

**Related:** `RUNTIME_FLOW.md`

---

### Q45. What P0 item would I debug first if metrics look wrong?

**Order:**
1. **P0.2/P0.3** — Are attack windows correct in `scenario_logs.csv`?
2. **P0.6** — Grace sec and log paths
3. **R6/R7** — Detection/eligibility (not P0 but affects mitigation latency)

**Related:** `TROUBLESHOOTING.md`

---

### Q46. Are P0 items configurable via environment?

**Mostly no** — P0 constants are code-level (burst duration, norm constants, strategy hints).

**Exceptions:** Ops profile (Foundation) affects RL gate; metrics `--grace-sec`, `--logs-dir`.

**Purpose:** P0 favors reproducible defaults over runtime toggles.

**Related:** [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md)

---

### Q47. P0 status for Release 1.0?

**COMPLETE** — all six items implemented with tests; active in default paths.

**Not in P0:** R2 SSL, R3 live twin, dashboard HTTP auth, external alerting.

**Related:** [../../02_Novelties/02_P0_Hardening.md](../../02_Novelties/02_P0_Hardening.md), [README.md](README.md)

---

*For verification gate details see [R7_QNA.md](06_R7_QNA.md). For alerting see [R8_QNA.md](08_R8_QNA.md).*
