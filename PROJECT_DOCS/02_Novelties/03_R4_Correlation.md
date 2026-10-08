# R4 — Multi-Signal Correlation

**PROJECT_DOCS novelty copy.** Source: `R4_CORRELATION.md`.  
Related: [04_R6_Collaborative_Detection.md](04_R6_Collaborative_Detection.md) · [06_R5_XAI_RCA.md](06_R5_XAI_RCA.md) · [../07_Viva/Novelty_QNA/04_R4_QNA.md](../07_Viva/Novelty_QNA/04_R4_QNA.md)

---

## Motivation

Individual detectors (entropy, ML, drift) fire independently. Operators and downstream fusion need a **cross-layer co-occurrence score** that says: several independent evidence categories agree about the same entity in a short window.

## Problem solved

Without correlation, fusion and RCA lack a structured **advisory** signal that combines detection, data-plane, and optional context categories under one score.

---

## Architecture

```
flow_monitor cycle
       │
       ▼
 build_cycle_signals()     correlation/runtime.py
       │
       ▼
 CorrelationEngine.correlate()   correlation/engine.py
       │
       ├── score = S · T · D · A · P   (clamped [0,1])
       ├── severity / status
       └── CorrelationResult DTO
       │
       ▼
 JSONL persistence → logs/correlation_results.jsonl
       │
       ▼
 Dashboard /api/correlation-results*
       │
       ▼
 R6 may consume CORRELATION evidence (advisory boost)
```

| Module | Path | Role |
|--------|------|------|
| Engine | `correlation/engine.py` | Scoring |
| Config | `correlation/config.py` | Weights, windows, severity |
| Runtime | `correlation/runtime.py` | Safe per-cycle hook |
| Adapters | `correlation/adapters.py` | Signal construction |
| Persistence | `correlation/persistence.py` | JSONL store |
| Categories | `correlation/categories.py` | SignalCategory enum usage |

---

## Correlation engine

Score factors (product, then clamp to `[0, 1]`):

| Factor | Meaning |
|--------|---------|
| **S** | Strength (weighted category evidence) |
| **T** | Temporal compactness in window |
| **D** | Category diversity |
| **A** | Agreement across sources |
| **P** | Persistence of strong signals |

Default window: **30 s**. Category weights (defaults): DETECTION 1.00, DATA_PLANE 0.85, SECURITY_RESPONSE 0.70, CONTROL_PLANE 0.55, DRIFT_CLUSTERING 0.50.

R4 is **advisory** for mitigation: it does **not** install OpenFlow rules by itself.

## Logs

- `logs/correlation_results.jsonl`

## Tests

`tests/test_correlation_engine_r42.py` and related `test_correlation_*.py`.
