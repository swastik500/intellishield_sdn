# R4 — Multi-Signal Correlation: Knowledge Base Q&A

**Release 1.0** · IntelliShield SDN · Laboratory prototype  
**Related:** [../../02_Novelties/03_R4_Correlation.md](../../02_Novelties/03_R4_Correlation.md) · `../../../RUNTIME_FLOW.md` · [../../02_Novelties/04_R6_Collaborative_Detection.md](../../02_Novelties/04_R6_Collaborative_Detection.md) · [R6_QNA.md](05_R6_QNA.md) · [R5_QNA.md](07_R5_XAI_QNA.md) · `GLOSSARY.md`

> **PROJECT_DOCS copy** — adapted from `R4_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

This document answers **why** and **how** the R4 cross-layer correlation engine works in Release 1.0. Answers reflect the current `correlation/` package only. Items outside the repository (Redis, dashboard auth, R2 SSL detector) are marked **Not implemented**.

---

## Architecture Reference

```
flow_monitor poll cycle
        │
        ▼
 build_cycle_signals()          correlation/runtime.py
        │
        ▼
 CorrelationEngine.correlate()   correlation/engine.py
        │
        ├── score = S · T · D · A · P   (clamped [0,1])
        ├── severity / status
        └── CorrelationResult DTO
        │
        ▼
 logs/correlation_results.jsonl
        │
        ├── Dashboard  GET /api/correlation-results*
        ├── R6 optional CORRELATION evidence (advisory boost)
        └── R5 RCA correlation snapshot
```

---

## Q&A — Correlation Fundamentals

### 1. What is R4 correlation in IntelliShield?

**Answer:** R4 is the **Multi-Signal Correlation** plane implemented under `correlation/`. It computes a deterministic cross-layer co-occurrence score for signals about the same entity within a short temporal window. **Purpose:** give operators and downstream planes (R6 fusion, R5 RCA) a structured advisory signal that several independent evidence categories agree on the same security-relevant entity. **Runtime:** invoked each controller poll cycle via `safe_correlate_cycle()` in `correlation/runtime.py`. **Related modules:** `correlation/engine.py`, `correlation/adapters.py`. **Related docs:** [R4_CORRELATION.md](../../02_Novelties/03_R4_Correlation.md).

### 2. Why does IntelliShield need correlation if ML and entropy already detect attacks?

**Answer:** Individual detectors fire **independently** and may disagree or miss context. Correlation answers a different question: *do multiple evidence categories co-occur about the same entity in a short window?* ML alone cannot express cross-plane agreement (detection + data-plane + optional control-plane context). Correlation is **advisory evidence**, not a replacement for detectors. **Advantage:** reduces false confidence from a single noisy channel. **Limitation:** low score when only one category is present (diversity floor applies).

### 3. What problem does R4 solve that R6 fusion does not?

**Answer:** R6 fuses **detector opinions** into a signed decision `S ∈ [-1,1]` with ATTACK/SUSPICIOUS/NORMAL labels. R4 scores **signal co-occurrence across categories** (DETECTION, DATA_PLANE, etc.) without issuing a fusion decision. R4 output is a `CorrelationResult` with score, severity, and status — consumed optionally by R6 as CORRELATION evidence (ρ=0.70) and by R5 for RCA snapshots. **Design reason:** separation of concerns — correlation is evidence assembly, fusion is decision synthesis.

### 4. Is R4 a machine-learning model?

**Answer:** **No.** R4 is a **rule-based, deterministic scoring engine** (`correlation/engine.py`). There is no training step, no gradient update, and no black-box inference. Factors S, T, D, A, P are explicit functions documented in `correlation/config.py`. **Why not ML alone:** ML explains *what* the ensemble saw in feature space; correlation explains *which planes agreed* in time — complementary, not substitutable.

### 5. What package path implements R4?

**Answer:** Top-level package `correlation/` with modules:

| Module | Role |
|--------|------|
| `engine.py` | Core scoring |
| `config.py` | Weights, windows, thresholds |
| `runtime.py` | Per-cycle safe hook |
| `adapters.py` | Signal construction from live stats |
| `persistence.py` | JSONL append |
| `categories.py` | `SignalCategory` usage |
| `strength.py` | Health-adjusted strength |
| `identity.py` | Entity key normalization |

### 6. What is a SignalEvent?

**Answer:** A typed input record (`correlation/models.py`) representing one observable signal: source, name, category, strength, health, entity, timestamp. **Purpose:** uniform input to `CorrelationEngine.correlate()`. Stale or unavailable signals are excluded before scoring — missing evidence is not treated as negative evidence.

### 7. What is a CorrelationResult?

**Answer:** Output DTO in `shared_contracts/models.py` containing `correlation_id`, `score`, `severity`, `status`, participating signal IDs, entity key, and reason string. Persisted to `logs/correlation_results.jsonl` and exposed via dashboard API.

### 8. What entity does correlation group signals by?

**Answer:** Signals are filtered to a common **entity key** (e.g., MAC or IP) via `correlation/identity.py`. Cross-entity mixing would inflate false co-occurrence. If no entity is specified, the engine derives one from the dominant signal set.

### 9. What is the default correlation time window?

**Answer:** **30 seconds** (`CorrelationConfig.window_duration_sec = 30.0`). Signals outside the window relative to the reference timestamp are excluded. **Rationale:** align with fusion freshness (R6 also uses 30 s) so correlated evidence remains temporally coherent for downstream planes.

### 10. Why 30 seconds and not 5 minutes?

**Answer:** DDoS events in the lab scenarios (S1–S5) evolve on second-to-minute scales; a 30 s window balances **recency** (attack still active) with **enough samples** for multi-category presence. Longer windows blur causality; shorter windows miss slow-building multi-plane agreement. Thresholds are tunable in `correlation/config.py`.

---

## Q&A — Scoring Model (S·T·D·A·P)

### 11. What is the R4 correlation score formula?

**Answer:**

```
S = weighted mean of category strengths (health-adjusted)
T = temporal compactness in window
D = category diversity factor
A = agreement factor across DETECTION sources
P = persistence boost for repeated strong signals

score = clamp(S · T · D · A · P, 0, 1)
```

Implemented in `correlation/engine.py`. Product form ensures weak any-factor suppresses overall score — all dimensions must contribute for high correlation.

### 12. What does factor S (Strength) represent?

**Answer:** **S** is the health-adjusted, category-weighted mean of signal strengths present in the window. Category weights (defaults):

| Category | Weight |
|----------|-------:|
| DETECTION | 1.00 |
| DATA_PLANE | 0.85 |
| SECURITY_RESPONSE | 0.70 |
| CONTROL_PLANE | 0.55 |
| DRIFT_CLUSTERING | 0.50 |
| UNKNOWN | 0.00 (excluded) |

**UNKNOWN** signals do not enter numeric fusion.

### 13. What does factor T (Temporal) represent?

**Answer:** **T** rewards signals that cluster in time rather than span the full 30 s window. Formula concept: `T = temporal_min + (1 - temporal_min) · (1 - span/W)+` with `temporal_min = 0.55`. **Purpose:** two alerts 29 s apart should score lower than two alerts 2 s apart. **Runtime:** computed from min/max timestamps of included signals.

### 14. What does factor D (Diversity) represent?

**Answer:** **D** measures how many **distinct categories** contribute. Target diversity `diversity_target = 3`; floor `diversity_floor = 0.55` ensures single-category windows can still produce non-zero scores but cannot reach maximum without cross-layer evidence. **Design reason:** penalize "one detector screaming alone" masquerading as correlated attack.

### 15. What does factor A (Agreement) represent?

**Answer:** **A** applies when multiple **DETECTION-category** signals disagree on attack vs normal lean. Defaults: `agreement_boost = 1.08` when aligned; `disagreement_factor = 0.90` when conflicting. **Purpose:** entropy and ML agreeing strengthens correlation; fighting weakens it.

### 16. What does factor P (Persistence) represent?

**Answer:** **P** adds up to `persistence_boost_max = 0.06` when at least `persistence_min_strong = 2` signals exceed `strong_strength_threshold = 0.5`. **Purpose:** reward sustained multi-sample evidence within the window, not a single spike.

### 17. Why multiply factors instead of adding them?

**Answer:** Multiplicative composition enforces **conjunctive evidence**: a high final score requires strength, temporal compactness, diversity, agreement, and optionally persistence simultaneously. Additive models would allow one dominant factor to mask missing cross-layer support — undesirable for advisory cross-layer correlation in security contexts.

### 18. Why clamp the score to [0, 1]?

**Answer:** Keeps `CorrelationResult.score` comparable across cycles, compatible with severity buckets (`severity_low` 0.25 through `severity_critical` 0.85), and safe for R6 correlation boost inputs. Values above 1.0 from boost products would break dashboard sorting semantics.

### 19. What severity bands map from score?

**Answer:** Configured thresholds in `correlation/config.py`:

| Band | Threshold (≥) |
|------|--------------:|
| LOW | 0.25 |
| MEDIUM | 0.45 |
| HIGH | 0.65 |
| CRITICAL | 0.85 |

Severity is **informational** for operators and RCA; R4 does not directly trigger mitigation.

### 20. What status labels does correlation emit?

**Answer:** Status reflects evidence strength vs `correlated_min_score = 0.45` and `correlated_min_categories = 2`. Primary label **CORRELATED** indicates sufficient cross-category co-occurrence. Weaker or empty windows yield lower statuses (e.g., EMPTY, ERROR). Exact strings are defined in engine logic and tests (`tests/test_correlation_engine_r42.py`).

---

## Q&A — Categories and Evidence

### 21. What signal categories does R4 recognize?

**Answer:** Six categories via `correlation/categories.py` / `SignalCategory`:

1. **DETECTION** — entropy, ML ensemble opinions  
2. **DATA_PLANE** — forwarding/volume/error statistics  
3. **SECURITY_RESPONSE** — verification, mitigation, alert confirmation  
4. **CONTROL_PLANE** — controller stress / policy context  
5. **DRIFT_CLUSTERING** — ADWIN/HDBSCAN observational context  
6. **UNKNOWN** — excluded from scoring (weight 0.00)

### 22. Why is DETECTION weighted highest?

**Answer:** DETECTION carries primary security judgments on the live path (entropy + ML). Data-plane and context categories **support** but should not outweigh authoritative detector outputs. Weight 1.00 anchors correlation to actionable detection evidence.

### 23. Why is DRIFT_CLUSTERING weighted lower (0.50)?

**Answer:** ADWIN and HDBSCAN (`advanced_analytics/`) provide **observational drift/cluster context**, not primary attack authorization. Lower weight prevents unsupervised drift spikes from dominating correlation without detector agreement. **Related:** R6 treats ADWIN/HDBSCAN similarly (ρ=0.55, uncertainty shrink).

### 24. Why is UNKNOWN excluded?

**Answer:** UNKNOWN captures lab ground-truth or unspecified signals that lack a defined evidentiary role. Including them at weight 0.00 avoids inventing numeric influence from untyped inputs. **Design principle:** missing taxonomy → exclude, not guess.

### 25. What is SECURITY_RESPONSE category used for?

**Answer:** Downstream confirmation signals — e.g., verification stage outcomes, mitigation applied, alert emitted. Useful for **post-decision correlation** ("did the system's response chain align?") but weighted 0.70 because response evidence is not a substitute for upstream detection.

### 26. Can CONTROL_PLANE signals alone trigger high correlation?

**Answer:** Theoretically a single category hits diversity floor (0.55) but cannot reach CORRELATED status without `correlated_min_categories = 2`. Control-plane alone is **insufficient** for strong correlated label — by design.

### 27. How are signals deduplicated?

**Answer:** `max_signals_per_type = 1` keeps the **strongest** signal per `(source, name, entity)` tuple. **Reason:** prevent duplicate log lines from inflating diversity or persistence counts.

### 28. Does insertion order of signals affect the score?

**Answer:** **No.** `CorrelationEngine.correlate()` sorts inputs by `(timestamp, signal_id)` before processing (`correlation/engine.py`). Determinism supports reproducible tests and audit trails.

### 29. How is correlation_id generated?

**Answer:** Deterministic hash from entity, window, and participating signal identities (see `correlation/engine.py`). Same inputs → same ID, aiding idempotent persistence and dashboard lookup.

### 30. What inputs does build_cycle_signals() collect?

**Answer:** `correlation/adapters.py` and `correlation/runtime.py` assemble `SignalEvent` lists from live detector outputs, flow/port stats, and optional downstream references each poll cycle. Exact adapter mapping is scenario-dependent; see `RUNTIME_FLOW.md`.

---

## Q&A — Health, Stale, and Degraded Signals

### 31. What happens to stale signals?

**Answer:** **Stale signals are excluded entirely.** They do not contribute zero strength — they are **absent** from the scoring set. **Principle:** missing ≠ negative. A stale ML reading must not penalize correlation as if it were a NORMAL vote.

### 32. What happens to unavailable (NOT_AVAILABLE) signals?

**Answer:** Same as stale — **excluded**. The engine never imputes negative evidence from missing channels.

### 33. What is degraded health and how is it handled?

**Answer:** Degraded signals participate but strength is multiplied by `degraded_strength_factor = **0.5**` (`correlation/strength.py`, `apply_health`). **Purpose:** partial participation when a detector reports DEGRADED health without full ERROR drop-out.

### 34. What health states exist for signals?

**Answer:** Aligned with detector health semantics: SUCCESS (full strength), DEGRADED (×0.5), ERROR/STALE/NOT_AVAILABLE (excluded). See `GLOSSARY.md` — **Health factor**.

### 35. Why not treat missing ML as "everything normal"?

**Answer:** Treating absence as negative evidence would create **false negatives** during detector restart, model load failure, or clock skew. Exclusion preserves honest uncertainty — correlation score simply reflects what is actually observed.

### 36. How does freshness interact with the 30 s window?

**Answer:** Window bounds define inclusion; health/stale filters define usability. A signal at t=0 and reference at t=31 s is window-excluded regardless of health. A signal at t=29 s with STALE health is window-included but then dropped.

### 37. Can correlation run with zero valid signals?

**Answer:** Yes — returns EMPTY status with reason `empty_window` and zero score. Runtime continues; no exception propagates to the controller loop.

---

## Q&A — Advisory Role and Mitigation Boundary

### 38. Does R4 install OpenFlow DROP rules?

**Answer:** **No.** R4 is **advisory only**. Mitigation eligibility flows through R7 verification after R6 fusion. Correlation informs fusion (optional boost) and RCA evidence — it never authorizes packet drop by itself.

### 39. Why keep correlation advisory instead of binding?

**Answer:** Cross-layer co-occurrence is **necessary but not sufficient** for automated blocking in a lab SDN controller. Binding correlation to mitigation would amplify false positives when context categories spike without verified attack. Separation preserves R7 as the **verification gate** ([R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md)).

### 40. How does R6 consume R4 output?

**Answer:** When correlation score is attack-leaning, R6 may apply a **correlation support boost** (β = 0.25 default, `fusion/config.py`) to signed score S, with CORRELATION detector type at ρ=0.70. This is optional evidence — disabling R6 fusion (`INTELLISHIELD_R6_FUSION=0`) bypasses this path entirely.

### 41. How does R5 consume R4 output?

**Answer:** `rca/correlation_evidence.py` embeds correlation snapshots in the **evidence chain** of `RootCauseReport`. Operators see whether multi-plane agreement existed at decision time.

### 42. Can high correlation force VERIFIED status in R7?

**Answer:** **No.** R7 applies its own stage gates (confidence floor, streak confirmation, identification). Correlation may boost fusion confidence (calibration path) but does not override R7 policy.

### 43. What is the difference between "advisory" and "informational"?

**Answer:** In this codebase both mean **non-actuating**. Advisory specifically signals downstream planes *may* weight the evidence (R6 boost); informational appears in dashboard/RCA for human review. Neither triggers OpenFlow changes.

---

## Q&A — Runtime, Latency, and Failure Handling

### 44. When in the poll cycle does correlation run?

**Answer:** After cycle signals are built from detectors/stats, before or alongside fusion depending on controller wiring — see `RUNTIME_FLOW.md`. Entry point: `safe_correlate_cycle()` in `correlation/runtime.py`.

### 45. What is safe_correlate_cycle()?

**Answer:** A **fail-isolated wrapper** that catches exceptions from correlation so the OpenFlow control loop never crashes due to R4 errors. On failure, logs error and returns empty/skipped result. Tested in `tests/test_correlation_hardening_r45.py`.

### 46. What latency budget does R4 target?

**Answer:** Performance tests (`tests/test_correlation_perf_r42.py`, `tests/test_correlation_perf_r45.py`) assert correlation completes within cycle budget on synthetic signal volumes representative of lab traffic. Exact millisecond bounds are test-defined — engine is lightweight (no I/O inside `correlate()`).

### 47. Does correlation block the controller thread?

**Answer:** Scoring is **in-process synchronous** on the poll thread. Design assumes sub-millisecond to low-ms compute for typical signal counts. JSONL persistence may add I/O latency but is also wrapped for isolation.

### 48. What happens if correlation JSONL write fails?

**Answer:** Persistence errors should be caught at runtime wrapper level; controller continues processing flows. Dashboard may show empty history until path is writable. Typical path: `logs/correlation_results.jsonl` via `default_correlation_jsonl_path`.

### 49. What happens on malformed SignalEvent input?

**Answer:** Engine returns ERROR status with reason `malformed_input: ...` rather than raising to caller. **Fail-isolated, fail-informative.**

### 50. Is there an environment kill-switch for R4?

**Answer:** **No dedicated env flag** in Release 1.0 (unlike R6's `INTELLISHIELD_R6_FUSION`). Correlation runs when the package imports successfully. Controller startup logs **R4 ACTIVE** on success.

### 51. What if the correlation package fails to import?

**Answer:** Controller degrades gracefully — correlation skipped, no R4 JSONL writes, dashboard correlation panel empty. Other planes (R6/R7) continue if independently available.

---

## Q&A — Persistence and Dashboard

### 52. Where are correlation results stored?

**Answer:** Append-only **JSONL** at `logs/correlation_results.jsonl` (`correlation/persistence.py`). Each line is one serialized `CorrelationResult`.

### 53. Why JSONL instead of Redis or PostgreSQL?

**Answer:** Release 1.0 lab architecture favors **simple, inspectable, file-based evidence** without external service dependencies. **Redis/Postgres: Not implemented.**

### 54. What dashboard endpoints expose R4 data?

**Answer:**

| Endpoint | Purpose |
|----------|---------|
| `GET /api/correlation-results` | List (newest first, filters) |
| `GET /api/correlation-results/{id}` | Single record |
| `GET /api/correlation-results/stats` | Bounded aggregates |

See [API_REFERENCE.md](../../04_Implementation/06_APIs.md). **Dashboard HTTP auth: Not implemented.**

### 55. Does the UI visualize correlation?

**Answer:** Yes — `dashboard/static/index.html` polls correlation endpoints alongside fusion and RCA cards. Detail view fetches `/api/correlation-results/{correlation_id}`.

### 56. Can I filter correlation results by event_id?

**Answer:** Yes — list endpoint supports `event_id`, `since`, `until`, and `limit` query parameters (see dashboard API and `tests/test_correlation_dashboard_r44.py`).

### 57. How do I inspect correlation offline?

**Answer:** `tail -f logs/correlation_results.jsonl | python3 -m json.tool` or query dashboard API with curl. Example in [R4_CORRELATION.md](../../02_Novelties/03_R4_Correlation.md).

---

## Q&A — Testing and Validation

### 58. What tests cover R4?

**Answer:**

| Test file | Focus |
|-----------|-------|
| `tests/test_correlation_inventory_r41.py` | Signal inventory |
| `tests/test_correlation_engine_r42.py` | Core scoring |
| `tests/test_correlation_runtime_r43.py` | Runtime hook |
| `tests/test_correlation_dashboard_r44.py` | API |
| `tests/test_correlation_hardening_r45.py` | Failure isolation |
| `tests/test_correlation_perf_r42.py` / `*_r45.py` | Latency |
| `tests/test_correlation_sensitivity_ablation_r45.py` | Factor ablation |

See [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md).

### 59. How is scoring correctness verified?

**Answer:** Unit tests construct synthetic `SignalEvent` sequences with known category/strength/timestamp patterns and assert expected score, severity, and status within tolerance. Deterministic IDs enable golden comparisons.

### 60. What does sensitivity ablation testing prove?

**Answer:** `test_correlation_sensitivity_ablation_r45.py` varies one factor at a time (e.g., remove diversity, inject disagreement) to confirm score monotonicity and config coupling — supports IEEE-style justification of weight choices.

### 61. Are Mininet runs required to test R4?

**Answer:** **No** for core engine tests — synthetic signals suffice. Integration evidence comes from live lab scenarios documented in IMPLEMENTED/ notes.

---

## Q&A — Design Decisions and Research Positioning

### 62. Why deterministic scoring instead of learned fusion weights?

**Answer:** **Explainability and auditability** for MCA/IEEE evaluation. Every factor is documented in config with rationale strings. Learned end-to-end fusion would complicate viva defense and reproducibility in a lab prototype without production training pipelines.

### 63. Why not use majority vote across signals?

**Answer:** Majority vote ignores **strength, health, category trust, and temporal compactness**. R4's product model and category weights encode domain knowledge that binary votes discard. R6 addresses detector-level voting analogues separately ([R6_QNA.md](05_R6_QNA.md)).

### 64. How does R4 relate to cross-layer correlation literature?

**Answer:** R4 implements a **lightweight evidence fusion** pattern common in multi-sensor security analytics: independent channels, explicit trust weights, temporal windowing, and conjunctive scoring. Suitable citation framing: "deterministic cross-layer co-occurrence engine for SDN DDoS evidence" — see [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md) when present.

### 65. Why separate correlation from fusion (R6)?

**Answer:** **Modularity and testability.** Correlation can be evaluated on signal inventories alone; fusion can be evaluated on detector adapters alone. Combined monolith would blur failure domains and hinder incremental Release 1.0 delivery (R4.1–R4.5 milestones).

### 66. Why include SECURITY_RESPONSE in upstream correlation?

**Answer:** Optional **closed-loop coherence** — when verification and mitigation signals appear in the same window as detection, correlation captures "system self-consistency." Weight 0.70 prevents circular confirmation from overriding weak upstream detection.

### 67. Could correlation replace R7 verification?

**Answer:** **No.** R7 implements multi-stage gates (warm-up, confidence, identification, streak). Correlation lacks attacker identification and policy eligibility semantics. **Verification remains mandatory** for mitigation.

---

## Q&A — Performance and Scalability

### 68. What is the computational complexity of correlate()?

**Answer:** O(n log n) for sort + O(n) for aggregation over n signals in window — typically n ≪ 100 per entity per cycle in lab. No quadratic pairwise detector comparisons.

### 69. Does R4 scale to production ISP traffic?

**Answer:** **Not claimed in Release 1.0.** Design targets Mininet lab poll rates. Production would require signal sampling, sharding by entity, and async persistence — **out of current DoD**.

### 70. Are there memory leaks across cycles?

**Answer:** Engine is stateless per call — no unbounded in-engine history. Window state is passed explicitly or derived from signal timestamps. Long-running controller memory depends on JSONL rotation policy (manual/lab).

### 71. Does correlation run per entity or globally?

**Answer:** Per **entity key** within a cycle. Multiple entities may each produce separate `CorrelationResult` records when multi-entity signals are present.

---

## Q&A — Limitations and Future Work

### 72. What are known R4 limitations in Release 1.0?

**Answer:**

| Limitation | Detail |
|------------|--------|
| Lab scope | Mininet scenarios, not live ISP traces |
| No ML correlation | Rule-based only |
| Advisory only | No direct mitigation |
| File persistence | No distributed store (**Redis: Not implemented**) |
| Static weights | Not online-learned |
| Single controller | No multi-controller correlation |

### 73. Is SSL/TLS detection integrated into R4?

**Answer:** **R2 SSL detector: Not implemented.** `DetectorType.SSL` exists in contracts for future work but emits no live signals into R4 today.

### 74. Will correlation weights be learned in future releases?

**Answer:** Not committed in repository. Current config documents manual rationale. Any future learning must preserve explainability constraints stated in IMPLEMENTED/R4_2 docs.

### 75. Could digital twin (R3) feed correlation?

**Answer:** Twin code exists under `twin/` but **live twin-assisted correlation is out of Release 1.0 DoD**. Hypothetically simulation could emit CONTROL_PLANE or DATA_PLANE signals — not wired in R1.0 live path.

### 76. Is email alerting tied to correlation score?

**Answer:** **Email alerts: Not implemented.** R8 alerting triggers on verification/security events, not raw correlation threshold crossings.

---

## Q&A — Troubleshooting and Operations

### 77. Dashboard shows empty correlation — what to check?

**Answer:**

1. Controller writing `logs/correlation_results.jsonl`?  
2. R4 package imported (startup log **R4 ACTIVE**)?  
3. Path permissions under `logs/`?  
4. Any signals passing stale/health filters?

See `TROUBLESHOOTING.md`.

### 78. Correlation score always low — why?

**Answer:** Common causes: **only one category** present (diversity floor), **detectors disagree** (A factor penalty), **signals span full window** (low T), or **degraded health** halving strengths. Not necessarily a bug — may reflect genuine weak cross-layer agreement.

### 79. Correlation score high but no mitigation — why?

**Answer:** **Expected behavior.** R4 is advisory. Mitigation requires R6 fusion → R7 VERIFIED → mitigation module. High correlation alone does not satisfy verification gates.

### 80. How do I tune correlation for demos?

**Answer:** Adjust `CorrelationConfig` in `correlation/config.py` (window, weights, thresholds). Re-run unit tests after changes. Prefer lab profile consistency documented in [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md).

---

## Q&A — Misconceptions

### 81. "Correlation score 0.9 means 90% probability of attack" — true?

**Answer:** **False.** Score is a **normalized co-occurrence index**, not a calibrated posterior. R6/R7 apply separate confidence semantics. Do not equate R4 score with P(attack).

### 82. "Missing entropy means correlation proves normal" — true?

**Answer:** **False.** Missing signals are **excluded**, not interpreted as normal. Low or empty correlation means insufficient cross-layer evidence, not proof of benign traffic.

### 83. "R4 replaces SIEM correlation rules" — true?

**Answer:** **False.** R4 is an in-controller evidence plane for IntelliShield's poll cycle, not a general SIEM. No Kafka/Splunk integration — **Not implemented**.

### 84. "More signals always increase score" — true?

**Answer:** **False.** Dedup keeps one signal per type; diversity requires **distinct categories**, not duplicate log lines. Spamming same-category events does not inflate D.

### 85. "Correlation and fusion are duplicate features" — true?

**Answer:** **False.** See Q3 — different inputs, outputs, and roles. R4 = cross-category co-occurrence; R6 = detector opinion synthesis.

---

## Q&A — Cross-Plane Integration Summary

### 86. What is the full evidence flow involving R4?

**Answer:**

```
Detectors + stats → SignalEvent[]
        → R4 CorrelationResult (advisory)
        → R6 fusion (optional CORRELATION boost)
        → R7 verification
        → Mitigation (if VERIFIED)
        → R5 RCA (includes correlation snapshot)
        → R8 alert (on VERIFIED)
        → Dashboard (all JSONL planes)
```

### 87. Which shared_contracts types does R4 use?

**Answer:** `CorrelationResult`, `Severity`, enums for health/category, `new_id`, time utilities. Leaf package rule: `shared_contracts/` imports nothing from controller.

### 88. How should viva panels question R4?

**Answer:** Prepare to explain **S·T·D·A·P product rationale**, **advisory boundary**, **stale exclusion principle**, and **difference from ML/fusion**. Draw the ASCII pipeline from this document. Cite test files as validation evidence.

### 89. Where is the authoritative implementation narrative?

**Answer:** [../../02_Novelties/03_R4_Correlation.md](../../02_Novelties/03_R4_Correlation.md) for ops; `IMPLEMENTED/R4_*.md` for milestone history; this Q&A for *why*.

### 90. What should I read next after R4?

**Answer:** [R6_QNA.md](05_R6_QNA.md) (how fusion consumes correlation), [R5_QNA.md](07_R5_XAI_QNA.md) (RCA evidence chain), [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md) (mitigation gate).

---

*End of R4 Q&A (90 questions). Release 1.0 — repository truth only.*
