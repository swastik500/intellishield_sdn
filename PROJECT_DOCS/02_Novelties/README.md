# Novelties (Release 1.0)

This folder is the **PROJECT_DOCS** copy of novelty documentation from ``. Content is adapted for report, viva, and presentation use. Engineering originals remain under `` and ``.

## Documents

| # | Document | Novelty |
|---|----------|---------|
| 0 | [00_Overview.md](00_Overview.md) | Index of all Release 1.0 novelties |
| 1 | [01_Foundation.md](01_Foundation.md) | Shared contracts |
| 2 | [02_P0_Hardening.md](02_P0_Hardening.md) | P0.1–P0.6 reproducibility |
| 3 | [03_R4_Correlation.md](03_R4_Correlation.md) | Cross-layer correlation (advisory) |
| 4 | [04_R6_Collaborative_Detection.md](04_R6_Collaborative_Detection.md) | Reliability-aware fusion |
| 5 | [05_R7_Verification.md](05_R7_Verification.md) | Mitigation eligibility gate |
| 6 | [06_R5_XAI_RCA.md](06_R5_XAI_RCA.md) | Explainability + root cause |
| 7 | [07_R8_Alerting.md](07_R8_Alerting.md) | Policy-aware alerts |
| 8 | [08_R3_Digital_Twin.md](08_R3_Digital_Twin.md) | Snapshot twin (COMPLETE Level A) |
| 9 | [09_Ops_Calibration.md](09_Ops_Calibration.md) | Lab vs production ops profile |
| 10 | [10_Research_Justification.md](10_Research_Justification.md) | Paper / viva novelty essay |

## Pipeline (what is novel vs a single ML → DROP stack)

```
Entropy + ML
    → R4 Correlation (advisory)
    → R6 Reliability-aware fusion
    → R7 Multi-stage verification
    → OpenFlow mitigation (if VERIFIED)
    → R5 XAI/RCA + R8 alerts
```

Foundation + P0 sit under this pipeline. R3 is a **read-only snapshot twin**, not on the DROP path.

## Related PROJECT_DOCS

- [Project Overview — Novelty](../01_Project_Overview/05_Novelty.md)
- [Presentation — Novelty Explanation](../08_Presentation/07_Novelty_Explanation.md)
- [Viva — Novelty Questions](../07_Viva/08_Novelty_Questions.md)
- [Viva — Full Novelty Q&A](../07_Viva/Novelty_QNA/README.md)

## Original source

| This file | Original |
|-----------|----------|
| 00–10 | `` + `RESEARCH_JUSTIFICATION.md` |
| Q&A banks | `*_QNA.md` → [`../07_Viva/Novelty_QNA/`](../07_Viva/Novelty_QNA/README.md) |
| Overview table | `PROJECT_STATUS_AND_NOVELTIES.md` §4 |
