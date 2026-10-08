# R5 — Explainable AI & Root Cause Analysis: Knowledge Base Q&A

**Release 1.0** · IntelliShield SDN · Laboratory prototype  
**Related:** [../../02_Novelties/06_R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md) · [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md) · [../../02_Novelties/07_R8_Alerting.md](../../02_Novelties/07_R8_Alerting.md) · [R4_QNA.md](04_R4_QNA.md) · [R6_QNA.md](05_R6_QNA.md) · `GLOSSARY.md`

> **PROJECT_DOCS copy** — adapted from `R5_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

R5 combines **Root Cause Analysis (RCA)** in `rca/` and **Explainable AI (XAI)** in `xai/` to produce human-auditable post-decision reports. RCA answers *why did the system act?* XAI answers *which ML features drove the detection?* Both are **fail-isolated** and typically run **after verification** (and optionally mitigation). **Digital-twin-assisted RCA depth: out of Release 1.0 DoD.**

---

## Architecture Reference

```
Detection (entropy / ML)
    → R4 correlation snapshot (if any)
    → R6 fused decision (if any)
    → R7 verification stages + status
    → Mitigation outcome (if blocked)
    → XAI tree / path explanation
        ↓
   RootCauseReport → logs/root_cause_reports.jsonl
        ↓
   Dashboard  GET /api/root-cause-reports*
```

---

## Q&A — RCA Fundamentals

### 1. What is Root Cause Analysis (RCA) in IntelliShield?

**Answer:** RCA is the `rca/` package that assembles a structured **evidence chain** into a `RootCauseReport` DTO. **Purpose:** let operators and researchers answer *why* the controller detected, verified, and optionally mitigated an event. **Runtime:** invoked via `rca/runtime.py` after R7 (typically on VERIFIED or security-relevant cycles). **Output:** JSONL persistence + dashboard API. **Not actuating** — reports only.

### 2. Why does IntelliShield need RCA if logs already exist?

**Answer:** Raw JSONL streams (fusion, verification, alerts) are **fragmented across planes**. RCA **links** them with event IDs, completeness metadata, confidence, and a natural-language summary — one artifact for viva demos, incident review, and IEEE reproducibility packages.

### 3. What package modules implement RCA?

**Answer:**

| Module | Role |
|--------|------|
| `rca/engine.py` | Report assembly |
| `rca/runtime.py` | Controller safe hook |
| `rca/evidence.py` | Base evidence collectors |
| `rca/fusion_evidence.py` | R6 fusion slice |
| `rca/correlation_evidence.py` | R4 snapshot |
| `rca/persistence.py` | JSONL store |
| `rca/completeness.py` | Coverage metrics |
| `rca/confidence.py` | Report confidence |
| `rca/summary.py` | Human-readable text |
| `rca/context.py` | Cycle context binding |

### 4. What is a RootCauseReport?

**Answer:** Typed record in `shared_contracts/models.py` with report/event identifiers, timeline of contributing planes, detector/fusion/verification summaries, completeness and confidence fields, and optional summary string. One report typically maps to one security-relevant cycle or event.

### 5. Where are RCA reports persisted?

**Answer:** Append-only **JSONL** — typical path `logs/root_cause_reports.jsonl` via `rca/persistence.py`. **Redis/Postgres: Not implemented.**

### 6. When is RCA triggered in the runtime flow?

**Answer:** **Typically after R7 verification** completes (and optionally after mitigation). Controller calls R5 runtime safely so OpenFlow processing continues even if RCA fails. Exact hook ordering: `RUNTIME_FLOW.md`.

### 7. Why run RCA after verification rather than immediately on detection?

**Answer:** Pre-verification reports would document **unconfirmed suspicions**, including false positives filtered by R7. Post-verification RCA captures the **decision the system actually stood behind** (VERIFIED path), aligning reports with mitigation and R8 alerts. **Research rationale:** root cause of *action* requires knowing what passed the gate.

### 8. Why include mitigation outcome in the evidence chain?

**Answer:** Mitigation (DROP installed) is part of the **closed-loop story**: detect → verify → act. RCA without mitigation slice would omit whether blocklist actuation succeeded — critical for lab evaluation and operator trust.

### 9. Does RCA run on INELIGIBLE or PENDING verification?

**Answer:** Runtime policy focuses on **security-relevant cycles**; many INELIGIBLE cycles skip full RCA to avoid noise. Engine can still build partial reports when invoked — see `tests/test_rca_engine_r52.py` for synthetic cases. Live lab calibrated run documented **6 RCA reports** ([R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md)).

### 10. Is RCA required for mitigation to occur?

**Answer:** **No.** Mitigation depends on R7 VERIFIED + policy. RCA is **downstream documentation** — its failure must not block mitigation (fail-isolated).

---

## Q&A — XAI Fundamentals

### 11. What is XAI in IntelliShield?

**Answer:** The `xai/` package explains **ML ensemble decisions** — primarily decision-tree path and related feature attributions. **Purpose:** satisfy explainability requirements for MCA/IEEE work where black-box ML alone is insufficient defense.

### 12. What XAI modules exist?

**Answer:**

| Module | Role |
|--------|------|
| `xai/engine.py` | Orchestration |
| `xai/tree_path.py` | Tree traversal explanation |
| `xai/deviations.py` | Path deviation analysis |
| `xai/faithfulness.py` | Explanation fidelity checks |
| `xai/models.py` | Helper structures |
| `xai/legacy_bridge.py` | Bridge to older ML paths |

### 13. What ML model does XAI explain?

**Answer:** The lab **Isolation Forest + Decision Tree** ensemble on ~15-D flow features (`ml_models/`). Explanations reflect **lab-trained models**, not production ISP captures — stated limitation in [R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md).

### 14. What is a decision tree path explanation?

**Answer:** Ordered list of feature thresholds and branches leading to the ML leaf decision — e.g., which flow statistics exceeded trained splits. Enables viva question: *"Which feature fired?"*

### 15. What is faithfulness in XAI?

**Answer:** Whether the explanation **aligns with actual model behavior** when inputs are perturbed. Tested in `tests/test_xai_faithfulness_r55.py`. Low faithfulness → explanation must not be over-trusted in papers.

### 16. Does XAI use SHAP or LIME?

**Answer:** Release 1.0 implements **tree-path-native** explanations in `xai/`, not generic SHAP/LIME libraries. External XAI frameworks — **Not implemented** unless added elsewhere.

### 17. Can XAI explain entropy detector output?

**Answer:** **Partially indirect.** Entropy is not a tree model; RCA may summarize entropy statistics in evidence collectors, but **primary XAI depth targets ML ensemble** paths.

### 18. Is the SSL detector explained by XAI?

**Answer:** **R2 SSL detector: Not implemented** — no SSL paths to explain in Release 1.0.

---

## Q&A — Why Both RCA and XAI?

### 19. Why not RCA alone without XAI?

**Answer:** RCA narrates **system-level evidence** (fusion, verification, mitigation) but does not automatically expose **feature-level ML reasoning**. Without XAI, operators see *that* ML said ATTACK, not *which features* drove it.

### 20. Why not XAI alone without RCA?

**Answer:** XAI covers **one detector plane**. It omits R4 correlation context, R6 disagreement, R7 gate failures, and mitigation outcomes. RCA provides **cross-plane provenance** XAI cannot.

### 21. How are RCA and XAI combined in one report?

**Answer:** `rca/engine.py` embeds or references XAI outputs as a section of `RootCauseReport` — tree path, deviations, faithfulness metadata when available. Single dashboard fetch returns unified artifact.

### 22. Do RCA and XAI share persistence?

**Answer:** RCA report is the **persisted unit** in `root_cause_reports.jsonl`. XAI artifacts are **embedded or referenced** within that report, not a separate production JSONL stream in R1.0.

### 23. What is the evidence chain vs explanation chain?

**Answer:** **Evidence chain** = temporal ordering of plane outputs (detection→R4→R6→R7→mitigation). **Explanation chain** = XAI's internal feature path. RCA merges both into one report narrative.

---

## Q&A — Evidence Chain Detail

### 24. What are the typical evidence chain stages?

**Answer:**

```
1. Detection (entropy / ML)
2. R4 correlation snapshot (if any)
3. R6 fused decision (if any)
4. R7 verification stages + status
5. Mitigation outcome (if blocked)
6. XAI tree/path explanation
```

### 25. How does R4 appear in RCA?

**Answer:** `rca/correlation_evidence.py` attaches correlation score, severity, status, and participating signal summary when a `CorrelationResult` exists for the event window. See [R4_QNA.md](04_R4_QNA.md).

### 26. How does R6 appear in RCA?

**Answer:** `rca/fusion_evidence.py` records fused score S, decision label, confidence, disagreement, and participating detector evidence IDs.

### 27. How does R7 appear in RCA?

**Answer:** Verification stage results, final status (VERIFIED/INELIGIBLE/PENDING), confidence gate outcome, and identification metadata are collected into the report timeline.

### 28. What identifiers link planes in RCA?

**Answer:** `event_id`, `fusion_id`, `correlation_id`, verification references, alert IDs — as available in cycle context (`rca/context.py`). Linkage enables dashboard lookup `/api/root-cause-reports/by-event/{event_id}`.

### 29. What is completeness in RCA?

**Answer:** `rca/completeness.py` measures **how many expected evidence slices** are present (e.g., fusion missing → lower completeness). Helps readers judge report trustworthiness.

### 30. What is confidence in RCA?

**Answer:** `rca/confidence.py` aggregates **report-level confidence** distinct from R6 fusion confidence or R7 gate confidence — meta-quality score for the assembled narrative.

### 31. What is the natural-language summary?

**Answer:** `rca/summary.py` generates a concise text block when sufficient evidence exists — suitable for dashboard display and paper appendices.

---

## Q&A — Dashboard and API

### 32. What dashboard endpoints serve RCA?

**Answer:**

| Endpoint | Purpose |
|----------|---------|
| `GET /api/root-cause-reports` | List reports |
| `GET /api/root-cause-reports/{report_id}` | Detail |
| `GET /api/root-cause-reports/by-event/{event_id}` | Newest for event |

**HTTP authentication: Not implemented** (lab assumption).

### 33. How does the UI use RCA data?

**Answer:** Dashboard polls RCA alongside alerts, correlation, and fusion cards (`dashboard/static/index.html`). Detail panes fetch single report JSON.

### 34. Example curl for RCA?

**Answer:**

```bash
curl -s http://127.0.0.1:8080/api/root-cause-reports?limit=5 | python3 -m json.tool
curl -s http://127.0.0.1:8080/api/root-cause-reports/by-event/<event_id>
```

### 35. Can RCA be queried without Mininet?

**Answer:** **Yes** — unit tests build synthetic fused/verified inputs. Dashboard can serve historical JSONL without live controller.

---

## Q&A — Failure Handling and Performance

### 36. What happens if RCA engine throws?

**Answer:** **Fail-isolated** — exception caught in runtime wrapper; OpenFlow loop continues. No mitigation rollback. Tested in `tests/test_r5_hardening_r55.py`.

### 37. What happens if XAI fails but RCA succeeds?

**Answer:** Report emitted with **partial XAI section** or omission; completeness score reflects gap. RCA must not fail entirely due to XAI alone when configured to degrade gracefully.

### 38. What latency budget does R5 target?

**Answer:** `tests/test_r5_perf_r55.py` bounds RCA+XAI assembly time on synthetic cycles. Tree path extraction dominates when ML explanation requested.

### 39. Does RCA block the poll cycle?

**Answer:** Synchronous on controller thread like other planes — designed for lab cycle rates. Production async queue — **Not implemented**.

### 40. Are RCA writes crash-safe?

**Answer:** JSONL append model — last line may be partial on hard crash (lab risk). No transactional DB.

---

## Q&A — Research, Limitations, and Future

### 41. What is the IEEE/MCA contribution framing for R5?

**Answer:** **Traceable post-decision audit trail** combining multi-plane SDN evidence with ML explainability — addresses "black box SDN security" critique. Cite evidence chain diagram and faithfulness tests.

### 42. What are Release 1.0 RCA/XAI limitations?

**Answer:**

| Limitation | Detail |
|------------|--------|
| Lab models | Not production packet captures |
| Twin depth | **R3 twin-assisted RCA: out of R1.0 DoD** |
| No auth | Dashboard open on :8080 |
| File store | No central SIEM export |
| SSL/R2 | **Not implemented** |

### 43. Will RCA replay digital twin scenarios?

**Answer:** Twin code under `twin/` exists separately; **live twin fidelity and twin-fed RCA depth are out of Release 1.0 DoD**. Future work could inject simulated evidence slices.

### 44. Is email notification sent when RCA completes?

**Answer:** **Email alerts: Not implemented.** R8 alerts on VERIFIED security events, not RCA completion.

### 45. Can RCA reports be used as training labels?

**Answer:** **Not designed for that.** Reports document system reasoning; ground truth remains scenario CSVs (`evaluation/`). Using RCA as labels would circularly embed policy.

### 46. How does R5 relate to R8 alerting?

**Answer:** R8 emits **operator notifications** on VERIFIED events; RCA provides **retrospective detail**. Alert may reference event_id lookupable in RCA API — complementary timelines.

### 47. What tests validate R5?

**Answer:**

| Test file | Focus |
|-----------|-------|
| `tests/test_xai_core_r51.py` | XAI core |
| `tests/test_rca_engine_r52.py` | RCA engine |
| `tests/test_rca_runtime_r53.py` | Runtime |
| `tests/test_rca_dashboard_r54.py` | API |
| `tests/test_xai_faithfulness_r55.py` | Faithfulness |
| `tests/test_rca_correctness_r55.py` | Correctness |
| `tests/test_r5_hardening_r55.py` | Isolation |
| `tests/test_r5_perf_r55.py` | Latency |

### 48. Misconception: "RCA proves ground-truth attack type" — true?

**Answer:** **False.** RCA explains **system belief and actions**, not independent ground truth. Attack typing comes from scenario logs / evaluation windows.

### 49. Misconception: "XAI explanation equals causal network attack story" — true?

**Answer:** **False.** Tree paths show **model decision boundaries**, not packet-level causality across the emulated topology.

### 50. What should I read after R5?

**Answer:** [R4_QNA.md](04_R4_QNA.md) (correlation snapshots), [R6_QNA.md](05_R6_QNA.md) (fusion evidence), [../../02_Novelties/07_R8_Alerting.md](../../02_Novelties/07_R8_Alerting.md) (alert linkage), `../../../RUNTIME_FLOW.md` (full cycle).

---

## Example Report Structure (Conceptual)

| Section | Source plane |
|---------|--------------|
| Header IDs | `rca/context.py` |
| Detection summary | entropy + ML collectors |
| Correlation | R4 snapshot |
| Fusion | R6 `FusedDecision` |
| Verification | R7 stages |
| Mitigation | blocklist / DROP status |
| XAI | tree path + faithfulness |
| Completeness / confidence | `rca/completeness.py`, `rca/confidence.py` |
| Summary text | `rca/summary.py` |

---

*End of R5 Q&A (50 questions). Release 1.0 — repository truth only.*
