# R6 — Collaborative Detection & Fusion: Knowledge Base Q&A

**Release 1.0** · IntelliShield SDN · Laboratory prototype  
**Related:** [../../02_Novelties/04_R6_Collaborative_Detection.md](../../02_Novelties/04_R6_Collaborative_Detection.md) · [../../02_Novelties/03_R4_Correlation.md](../../02_Novelties/03_R4_Correlation.md) · [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md) · [R4_QNA.md](04_R4_QNA.md) · [R5_QNA.md](07_R5_XAI_QNA.md) · `GLOSSARY.md`

> **PROJECT_DOCS copy** — adapted from `R6_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

R6 implements **collaborative detection** via reliability-aware fusion in `fusion/`. Multiple detector opinions normalize into evidence, combine into signed score **S ∈ [-1, 1]**, and emit a **FusedDecision** with calibrated **confidence** for R7 gates. Default: **enabled** (`INTELLISHIELD_R6_FUSION=1`). **R2 SSL detector: Not implemented** (type reserved). **ADWIN/HDBSCAN: context only**, not primary attack authors.

---

## Architecture Reference

```
 Detector adapters (ML, Entropy, …)
            │
            ▼
      Evidence assembly
            │
            ▼
     FusionEngine.fuse()
            │
     S, disagreement C, uncertainty U
            │
            ▼
   Decision on S + confidence calibration
            │
            ├──► logs/fused_decisions.jsonl
            ├──► R7 adapter (prediction dict)
            └──► Dashboard /api/fused-decisions*
```

---

## Q&A — Collaborative Detection Fundamentals

### 1. What is collaborative detection in IntelliShield?

**Answer:** R6 **fuses heterogeneous detector outputs** into one authoritative opinion per poll cycle instead of relying on a single detector or ad-hoc dual-path logic. **Purpose:** improve robustness when entropy and ML disagree, weight reliability and health, and supply R7 with a unified prediction + confidence. **Package:** `fusion/`.

### 2. What is a FusedDecision?

**Answer:** Output DTO containing signed score S, decision label (ATTACK/SUSPICIOUS/NORMAL/NONE), calibrated confidence, disagreement/uncertainty metadata, fusion_id, and evidence references. Persisted to `logs/fused_decisions.jsonl`.

### 3. How does R6 differ from legacy dual-path detection?

**Answer:** Legacy path (`INTELLISHIELD_R6_FUSION=0`) runs entropy and ML **without collaborative fusion**. R6 adds weighted combination, disagreement shrink, context uncertainty, optional R4 boost, and agreement-aware confidence calibration.

### 4. What feature flag controls R6?

**Answer:** **`INTELLISHIELD_R6_FUSION`** — default **1** (on). Set **`0`** to force legacy dual-path. Documented in [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md).

### 5. Why introduce fusion if ML already ensembled internally?

**Answer:** Internal ML ensemble combines **homogeneous models** on shared features. R6 combines **heterogeneous detectors** (entropy vs ML vs optional correlation/context) with different reliabilities, health states, and semantics — cross-detector collaboration, not intra-ML stacking.

### 6. Does fusion replace individual detectors?

**Answer:** **No.** Detectors still run; adapters **read** their outputs. Fusion synthesizes; it does not remove entropy or ML engines.

### 7. What is the signed fusion score S?

**Answer:** **S ∈ [-1, 1]** where positive lean indicates attack, negative indicates normal, magnitude indicates strength. Decision thresholds map S to labels (see Q15). Distinct from R4 correlation score ∈ [0,1].

### 8. What modules implement fusion?

**Answer:**

| Module | Role |
|--------|------|
| `fusion/engine.py` | Core fuse logic |
| `fusion/config.py` | ρ, thresholds, penalties |
| `fusion/adapters.py` | Detector normalization |
| `fusion/runtime.py` | Cycle hook + flag |
| `fusion/r7_adapter.py` | Verification input |
| `fusion/registry.py`, `roles.py` | Detector roles |
| `fusion/normalize.py`, `evidence.py` | Evidence assembly |
| `fusion/history.py`, `trace.py` | Debug/trace helpers |

---

## Q&A — Detector Adapters and Evidence

### 9. What is a detector adapter?

**Answer:** Component in `fusion/adapters.py` converting heterogeneous detector output into **common fusion evidence**: `DetectorType`, `DetectionDecision`, confidence/polarity, `DetectorHealth`, freshness timestamp.

### 10. Which detectors are primary in Release 1.0?

**Answer:** **ML** (ρ=1.00) and **Entropy** (ρ=0.95) on the live Mininet path. These drive security decisions when healthy.

### 11. What is DetectorType.SSL?

**Answer:** Enum value reserved for future **R2 SSL detector — Not implemented**. Config lists ρ=0.90 but no live adapter emits SSL evidence in R1.0.

### 12. What role do ADWIN and HDBSCAN play?

**Answer:** **Context only** — ρ=0.55 each. They contribute **uncertainty shrink** on |S|, not primary attack authorization. **Not treated as primary attackers** in fusion policy.

### 13. How does CORRELATION detector type relate to R4?

**Answer:** Optional R4 `CorrelationResult` ingested as CORRELATION evidence (ρ=0.70). When primary detectors are attack-leaning, **correlation support boost** β=0.25 may increase |S|. See [R4_QNA.md](04_R4_QNA.md).

### 14. What is effective fusion weight w?

**Answer:** **w = ρ × h** where ρ is base reliability and h is health factor. Unavailable/error detectors → h=0 → **dropped from fusion**.

### 15. What are default base reliabilities ρ?

**Answer:**

| Detector | ρ |
|----------|--:|
| ML | 1.00 |
| Entropy | 0.95 |
| SSL | 0.90 (reserved, **R2 Not implemented**) |
| Correlation | 0.70 |
| ADWIN | 0.55 |
| HDBSCAN | 0.55 |

From `fusion/config.py` — conservative lab defaults, **not online-learned**.

### 16. What are health factors h?

**Answer:**

| Health | h |
|--------|--:|
| SUCCESS | 1.0 |
| DEGRADED | 0.5 |
| ERROR | 0.0 |

Aligns with R4 degraded factor philosophy.

### 17. What freshness window applies?

**Answer:** **30 seconds** (`freshness_seconds = 30.0`). Stale evidence **excluded** — same principle as R4: missing ≠ negative.

### 18. How is evidence assembled before fuse()?

**Answer:** `fusion/assembly.py` and `fusion/evidence.py` collect adapter outputs, filter stale/error, assign roles (primary vs context), pass list to `FusionEngine.fuse()`.

---

## Q&A — Fusion Engine and Decision Rules

### 19. What does FusionEngine.fuse() return?

**Answer:** `FusedDecision` with S, decision enum, calibrated confidence, disagreement metric C, context uncertainty U, and trace metadata for dashboard/RCA.

### 20. What are decision thresholds on S?

**Answer:**

| Rule | Threshold |
|------|----------:|
| ATTACK | S ≥ **0.55** |
| SUSPICIOUS band | S ≥ **0.20** (below attack) |
| NORMAL | S ≤ **−0.20** |

Defaults in `fusion/config.py`.

### 21. What happens in the mid-band of S?

**Answer:** Between normal and suspicious thresholds, policy may emit SUSPICIOUS when **conflict or context uncertainty** present, else NORMAL/NONE — see engine branch logic and tests (`tests/test_fusion_engine_r62.py`).

### 22. What is disagreement C?

**Answer:** Metric of **conflict among primary detectors**. High disagreement **shrinks |S|**: `S' = S × (1 - disagreement_penalty × C)` with `disagreement_penalty = 0.45`.

### 23. Why shrink |S| on disagreement instead of picking a winner?

**Answer:** **Epistemic humility** — when entropy and ML fight, pretending the higher-reliability detector is certainly correct risks false mitigation. Shrinking magnitude pushes toward SUSPICIOUS/verification scrutiny rather than confident ATTACK.

### 24. Why not simple majority vote?

**Answer:** Majority vote ignores **confidence magnitude, reliability ρ, health h, and context uncertainty**. Two weak NORMAL votes could outvote one strong ATTACK signal incorrectly. Weighted S with disagreement penalty preserves graded evidence.

### 25. What is context uncertainty U?

**Answer:** Combined influence of ADWIN/HDBSCAN context signals (`adwin_uncertainty`, `hdbscan_uncertainty` weights) that **shrinks |S|** and can tip mid-band toward SUSPICIOUS via `context_uncertainty_strength = 0.35`.

### 26. When does correlation boost apply?

**Answer:** When **primary detectors are attack-leaning** and CORRELATION evidence supports, β=0.25 (`correlation_support_strength`) increases |S|. Prevents correlation alone from inventing attacks without primary lean.

### 27. Can fusion emit ATTACK with only correlation evidence?

**Answer:** **No practical path** — primaries must contribute minimum weight (`min_primary_weight`). Correlation ρ=0.70 alone insufficient to cross attack_threshold 0.55 without primary support.

### 28. What is NONE decision?

**Answer:** Insufficient participating weight or indeterminate cycle — fusion abstains from strong label. R7 interprets via adapter mapping.

---

## Q&A — Confidence Calibration

### 29. What is confidence calibration in R6?

**Answer:** **Agreement-aware adjustment** of reported posterior confidence **after** S decision is fixed. Parameters: `agreement_confidence_boost`, `correlation_confidence_boost_cap`, `uncertainty_confidence_penalty` in `fusion/config.py`.

### 30. Does confidence calibration change the ATTACK/NORMAL decision?

**Answer:** **No.** Calibration adjusts **reported confidence for R7 gates only** without changing the S threshold decision rule. Critical design separation documented in config comments.

### 31. Why calibrate confidence separately from S?

**Answer:** Disagreement/context shrink |S| for **decision caution**, but unanimous primaries may still deserve **higher gate confidence** so R7 is not starved of mitigation when context noise suppressed magnitude. Fixes under-confidence without reckless ATTACK labels.

### 32. What is agreement_confidence_boost?

**Answer:** Default **0.25** boost when primaries unanimously attack-lean (high agreement G, low C) — raises calibrated confidence up to caps.

### 33. What is correlation_confidence_boost_cap?

**Answer:** **0.15** maximum additional confidence from correlation support — prevents advisory plane from dominating gate confidence.

### 34. What is uncertainty_confidence_penalty?

**Answer:** Scales down calibrated confidence when context uncertainty U high — default penalty factor **0.50** × uncertainty strength.

### 35. How does R7 use fused confidence?

**Answer:** R7 **confidence gate** (default floor **60%** in lab profile) reads calibrated confidence from fusion adapter output. See [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md).

### 36. What is INTELLISHIELD_OPS_PROFILE interaction?

**Answer:** `lab` profile freezes conf gate at 60%; `production` allows RL adaptive gate ~55–75%. Fusion calibration feeds gate input; profile selects gate policy (`shared_contracts/ops_profile.py`).

---

## Q&A — Runtime, R7 Integration, and Persistence

### 37. What is the fusion runtime flow?

**Answer:**

```
Entropy + ML (+ optional drift/R4)
        ↓
  fuse (if INTELLISHIELD_R6_FUSION != 0)
        ↓
  fused prediction → R7 VerificationInput
        ↓
  persist fusion_id JSONL
```

### 38. What does fusion/r7_adapter.py do?

**Answer:** Maps `FusedDecision` into **VerificationInput** prediction dict expected by R7 — decouples fusion schema from verification schema.

### 39. Where are fused decisions stored?

**Answer:** `logs/fused_decisions.jsonl` append-only. **Redis/Postgres: Not implemented.**

### 40. What dashboard endpoints expose fusion?

**Answer:**

| Endpoint | Purpose |
|----------|---------|
| `GET /api/fused-decisions` | List |
| `GET /api/fused-decisions/{id}` | Detail |
| `GET /api/fused-decisions/stats` | Aggregates |

**Dashboard auth: Not implemented.**

### 41. Example commands to run fusion?

**Answer:**

```bash
export INTELLISHIELD_OPS_PROFILE=lab
# fusion on (default)
osken-manager controller/flow_monitor.py

# force legacy path
export INTELLISHIELD_R6_FUSION=0
```

```bash
curl -s http://127.0.0.1:8080/api/fused-decisions?limit=5 | python3 -m json.tool
curl -s http://127.0.0.1:8080/api/fused-decisions/stats
```

---

## Q&A — Failure Scenarios and Hardening

### 42. What if ML detector errors?

**Answer:** ERROR health → h=0 → ML **excluded**. Fusion may proceed on entropy alone (lower effective weight) or emit NONE/SUSPICIOUS depending on magnitude.

### 43. What if both primaries error?

**Answer:** Insufficient primary weight → weak or NONE decision; R7 likely INELIGIBLE. **Fail-safe toward no mitigation.**

### 44. What if fusion engine throws?

**Answer:** Runtime wrapper catches exception; controller continues. Tested in `tests/test_fusion_hardening_r65.py`. Legacy fallback may apply when flag=0; when flag=1, cycle may skip fusion for that tick.

### 45. What if evidence is stale?

**Answer:** **Excluded** by freshness filter — not counted as NORMAL vote. May appear as missing detector participation.

### 46. What if clocks skew between detectors?

**Answer:** Freshness exclusion may drop valid-looking evidence — **operational risk** in lab if NTP not aligned. Document in troubleshooting; not auto-corrected in R1.0.

### 47. What if INTELLISHIELD_R6_FUSION=0?

**Answer:** **Legacy dual-path** — no collaborative S, no fusion JSONL from R6 engine (unless partial logging differs). R7 may consume legacy prediction shape via alternate adapter path.

### 48. Can disagreement cause false NORMAL?

**Answer:** Shrinking |S| can pull attack lean below 0.55 → SUSPICIOUS or NORMAL band — **intentional** to defer to R7 streak/confirmation rather than immediate ATTACK.

### 49. Does fusion bypass R7?

**Answer:** **Never.** ATTACK fusion decision is **input** to verification, not authorization. R7 fail-closed on errors → INELIGIBLE.

---

## Q&A — Agreement and Disagreement Examples

### 50. Example: ML ATTACK + Entropy ATTACK — outcome?

**Answer:** High agreement, low C → strong positive S, likely ATTACK label, boosted calibrated confidence for R7.

### 51. Example: ML ATTACK + Entropy NORMAL — outcome?

**Answer:** Disagreement penalty shrinks |S| → likely SUSPICIOUS, reduced confidence, R7 streak may delay VERIFIED.

### 52. Example: ML ATTACK + high ADWIN drift — outcome?

**Answer:** Context uncertainty U increases → |S| shrink + confidence penalty; may still be ATTACK if primaries strong, but gates scrutinize more.

### 53. Example: weak ML SUSPICIOUS + strong correlation — outcome?

**Answer:** Correlation boost β applies only when **primary attack-leaning** — weak suspicious may get limited boost; correlation alone cannot create ATTACK.

### 54. Example: healthy entropy alone (ML degraded) — outcome?

**Answer:** ML weight halved or dropped; entropy ρ=0.95×h drives S — possible ATTACK if entropy strong, but reduced total primary mass.

---

## Q&A — Performance and Testing

### 55. What tests cover R6?

**Answer:**

| Test file | Focus |
|-----------|-------|
| `tests/test_fusion_adapters_r61.py` | Adapters |
| `tests/test_fusion_engine_r62.py` | Engine |
| `tests/test_fusion_runtime_r63.py` | Runtime / flag |
| `tests/test_fusion_dashboard_r64.py` | API |
| `tests/test_fusion_hardening_r65.py` | Isolation |
| `tests/test_fusion_perf_r62.py` | Latency |
| `tests/test_ops_confidence_calibration.py` | Ops + calibration |

### 56. What latency budget does fusion target?

**Answer:** `tests/test_fusion_perf_r62.py` — engine fuse on representative evidence counts within cycle budget (in-process, no network).

### 57. Is fusion deterministic?

**Answer:** **Yes** for fixed evidence inputs — supports reproducible unit tests and JSONL replay.

### 58. How to debug fusion decisions?

**Answer:** Inspect `fusion/trace.py` metadata in logs, dashboard detail view, and fused_decisions.jsonl. Compare disagreement C and uncertainty U fields cycle-over-cycle.

---

## Q&A — Design Decisions and Research

### 59. Why ρ fixed instead of learned?

**Answer:** **Explainability** for MCA/IEEE — every weight cites lab conservative defaults in config. Online reliability learning — **Not implemented**.

### 60. Why signed S instead of probability?

**Answer:** Supports **bipolar** normal-vs-attack lean in one scalar compatible with disagreement shrink and symmetric thresholds (±0.20 normal band).

### 61. Why separate decision S from gate confidence?

**Answer:** Prevents **double punishment** — context can shrink decision magnitude while agreement boost preserves mitigation eligibility when operators/policy demand it via R7.

### 62. How does R6 relate to R4?

**Answer:** R4 provides **advisory cross-layer score**; R6 may ingest it as CORRELATION detector with boost. R4 does not replace fusion. Cross-read [R4_QNA.md](04_R4_QNA.md).

### 63. How does R6 feed R5 RCA?

**Answer:** `rca/fusion_evidence.py` embeds FusedDecision slice in evidence chain — see [R5_QNA.md](07_R5_XAI_QNA.md).

### 64. Is Redis used for fusion state?

**Answer:** **Not implemented.** Stateless per-cycle fuse with JSONL history only.

---

## Q&A — Limitations and Misconceptions

### 65. What are Release 1.0 fusion limitations?

**Answer:**

| Limitation | Detail |
|------------|--------|
| Lab detectors only | ML + entropy live |
| R2 SSL | **Not implemented** |
| Static ρ | No online learning |
| Single node | No distributed fusion |
| File persistence | No stream processor |

### 66. Misconception: "Fusion ATTACK immediately blocks traffic" — true?

**Answer:** **False.** R7 verification + policy required before mitigation.

### 67. Misconception: "Majority vote equals fusion" — true?

**Answer:** **False.** See Q24 — weighted S with disagreement and uncertainty.

### 68. Misconception: "ADWIN detected the attack" — true?

**Answer:** **False.** ADWIN is **context uncertainty**, ρ=0.55, not primary authorizer.

### 69. Misconception: "Calibrated confidence changes ATTACK label" — true?

**Answer:** **False.** Calibration affects **R7 gate input only**, not S thresholds.

### 70. Misconception: "INTELLISHIELD_R6_FUSION=0 is recommended for production" — true?

**Answer:** **False.** Flag=0 is **legacy lab comparison path**. Release 1.0 collaborative detection is the default intended path; "production" ops profile adjusts gates, not disables fusion.

---

## Q&A — Advanced Topics

### 71. What is min_primary_weight?

**Answer:** **1e-6** floor — prevents numerical fuse attempt with zero primary mass; practically requires at least one healthy primary detector.

### 72. What is default_decision_confidence?

**Answer:** **0.50** used when producer omitted explicit confidence — avoids null gate input.

### 73. What roles do registry and roles modules play?

**Answer:** Classify detectors as **primary** vs **context** so ADWIN/HDBSCAN cannot dominate weighted sum same as ML/entropy.

### 74. Does fusion support hot-add of new DetectorType?

**Answer:** Contract extensibility via `shared_contracts/enums.py` + adapter registration pattern — new types need adapter, ρ entry, and tests. SSL placeholder demonstrates pattern (**implementation Not done**).

### 75. How does legacy_compare help?

**Answer:** `fusion/legacy_compare.py` supports evaluation comparing R6 fused vs legacy dual-path decisions — research/ablation utility.

---

## Summary Table — R6 vs R4 vs R7

| Aspect | R4 Correlation | R6 Fusion | R7 Verification |
|--------|----------------|-----------|-----------------|
| Score range | [0, 1] | [-1, 1] | Status enum |
| Actuating? | No (advisory) | No (decision input) | Gates mitigation |
| Primary inputs | SignalEvents | Detector evidence | Fusion + stages |
| Kill-switch | None | `INTELLISHIELD_R6_FUSION` | Policy config |

---

### 76. What should viva candidates emphasize for R6?

**Answer:** **w=ρ×h**, **disagreement shrink**, **confidence calibration decoupled from S**, **context vs primary roles**, and **fail-isolation**. Demonstrate flag=0 vs flag=1 curl/dashboard diff.

### 77. Where is authoritative ops documentation?

**Answer:** [../../02_Novelties/04_R6_Collaborative_Detection.md](../../02_Novelties/04_R6_Collaborative_Detection.md) and [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md).

### 78. What related KB doc covers correlation details?

**Answer:** [R4_QNA.md](04_R4_QNA.md) — scoring, advisory role, CORRELATION evidence ingestion.

### 79. What related KB doc covers post-decision narrative?

**Answer:** [R5_QNA.md](07_R5_XAI_QNA.md) — RCA fusion evidence slice.

### 80. End-to-end ASCII (R6 highlighted)?

**Answer:**

```
Entropy ──┐
   ML ────┼──► R6 Fusion ──► R7 Verify ──► Mitigate
 R4 opt ──┘        │              │
                   JSONL          └──► R5 RCA
                   Dashboard
```

---

*End of R6 Q&A (80 questions). Release 1.0 — repository truth only.*
