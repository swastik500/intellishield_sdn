# R5 — Explainable AI and Root Cause Analysis

**PROJECT_DOCS novelty copy.** Source: `R5_XAI_RCA.md`.  
Related: [05_R7_Verification.md](05_R7_Verification.md) · [07_R8_Alerting.md](07_R8_Alerting.md) · [../07_Viva/Novelty_QNA/07_R5_XAI_QNA.md](../07_Viva/Novelty_QNA/07_R5_XAI_QNA.md)

---

## Root Cause Analysis (RCA)

RCA assembles a structured **evidence chain** after verification so operators can answer *why* the system acted.

Packages: `rca/` (reports) and `xai/` (tree/path explanations).

## Evidence chain

```
Detection (entropy/ML)
    → R4 correlation snapshot (if any)
    → R6 fused decision (if any)
    → R7 verification stages + status
    → Mitigation outcome (if blocked)
    → XAI tree/path explanation
        ↓
   RootCauseReport → logs/root_cause_reports.jsonl
```

Dashboard: `GET /api/root-cause-reports*`.

Live lab (`20260728T181121Z`): **6** RCA reports.

## Novelty angle

Post-decision explainability for viva and paper audit — not a black-box score.

## Limitations

- Explanations reflect lab models and features.
- Twin-assisted RCA depth is not claimed as live OpenFlow sync.

## Tests

`tests/test_xai_core_r51.py`, `tests/test_rca_engine_r52.py`, and related R5 tests.
