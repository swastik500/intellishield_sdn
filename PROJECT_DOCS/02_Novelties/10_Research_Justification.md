# Research Justification

**PROJECT_DOCS novelty copy.** Source: `RESEARCH_JUSTIFICATION.md`.  
Related: [00_Overview.md](00_Overview.md) · [../01_Project_Overview/05_Novelty.md](../01_Project_Overview/05_Novelty.md) · [../08_Presentation/07_Novelty_Explanation.md](../08_Presentation/07_Novelty_Explanation.md)

---

## Research novelty (scoped claim)

IntelliShield’s Release 1.0 novelty is **not** “yet another Isolation Forest on flows.”  
It is a **laboratory-complete collaborative pipeline** that:

1. senses SDN stats,
2. detects with entropy + ML,
3. **correlates** cross-layer signals (R4),
4. **fuses** detectors with reliability/health (R6),
5. **verifies** before actuation (R7),
6. **explains** via XAI/RCA (R5),
7. **alerts** with policy (R8),
8. on shared **contracts** (Foundation) after **P0** reproducibility fixes,

with **live Mininet evidence** under an explicit ops profile.

Claims are for a **controlled lab prototype**, not internet-edge production.

---

## Why these requirements?

| ID | Research gap addressed |
|----|------------------------|
| **Foundation** | Multi-module SDN stacks lack a typed evidence vocabulary. |
| **P0** | Metric/RL/scenario bugs silently invalidate papers. |
| **R4** | Single-detector papers ignore co-occurrence across planes. |
| **R6** | Naive OR/AND/majority ignore reliability and health. |
| **R7** | Detection ≠ authorization; false positives need gates. |
| **R5** | Black-box alerts fail viva/operator trust. |
| **R8** | Without policy, notification floods. |
| **R3** | Need reproducible attack plans and observational replay — not a live OpenFlow replica. |

**R2** SSL zero-day: **Not implemented**. **R1/R9:** **Out of current project scope**.

---

## Why this order?

```
Foundation → P0 → (detection base) → R4 → R6 → R7 → mitigation → R5/R8
```

R3 is observational and **off** the DROP path.

---

## Improvement vs conventional SDN DDoS labs

| Conventional lab system | IntelliShield R1.0 |
|-------------------------|--------------------|
| One detector → DROP | Detect → correlate → fuse → **verify** → DROP |
| Opaque ML score | XAI + RCA evidence chain |
| Ad-hoc logs | Shared contracts + JSONL planes |
| Alert on every anomaly | Default alert on **VERIFIED** |
| Unbounded RL thresholds | Ops profile clamps / lab freeze |
| Metrics afterthought | P0 windows + IEEE fields + bundles |

---

## Paper / viva talking points

1. **Pipeline novelty** over single-classifier SDN papers.
2. **Advisory vs authoritative** separation (R4 vs R7).
3. **Reliability-aware fusion** vs majority vote.
4. **Verification as first-class** research artifact.
5. **Reproducibility** (P0 + contracts + ops profile).
6. Explicit **non-claims** (R2, twin-launched Mininet, production internet).

---

## Honesty caveats

- Not a comparison against commercial scrubbing centers.
- Not packet-level DPI.
- Not authenticated multi-tenant SOC.
- Live evidence is **Mininet S1–S5** under documented profiles.
