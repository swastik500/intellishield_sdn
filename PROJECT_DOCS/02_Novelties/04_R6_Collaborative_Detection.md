# R6 — Collaborative / Reliability-Aware Fusion

**PROJECT_DOCS novelty copy.** Source: `R6_COLLABORATIVE_DETECTION.md`.  
Related: [03_R4_Correlation.md](03_R4_Correlation.md) · [05_R7_Verification.md](05_R7_Verification.md) · [09_Ops_Calibration.md](09_Ops_Calibration.md) · [../07_Viva/Novelty_QNA/05_R6_QNA.md](../07_Viva/Novelty_QNA/05_R6_QNA.md)

---

## Collaborative detection

R6 fuses multiple detector opinions into one **FusedDecision** with:

- signed score **S ∈ [-1, 1]**
- decision: `ATTACK` / `SUSPICIOUS` / `NORMAL`
- calibrated **confidence** for R7 gates
- reliability × health weights **w = ρ × h**
- optional R4 correlation support

Disable: `INTELLISHIELD_R6_FUSION=0` → legacy dual-path (entropy/ML without collaborative fusion).

---

## Architecture

```
 Detector adapters (ML, Entropy, …)
            │
            ▼
     FusionEngine.fuse()
            │
     S, disagreement, uncertainty
            │
            ├──► JSONL fused decisions
            ├──► R7 adapter
            └──► Dashboard /api/fused-decisions*
```

Default ρ: ML 1.00, Entropy 0.95, Correlation 0.70, ADWIN/HDBSCAN 0.55.

Decision on **S** (defaults): ATTACK if S ≥ 0.55; SUSPICIOUS ≥ 0.20; NORMAL if S ≤ −0.20.

**Confidence calibration** (agreement-aware) adjusts reported posterior for R7 **without changing** the S decision rule.

SSL detector type is reserved for R2 — **R2 Not implemented**.

## Tests

`tests/test_fusion_engine_r62.py` and related `test_fusion_*.py`.
