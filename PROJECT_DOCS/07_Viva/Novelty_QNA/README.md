# Novelty Q&A (Release 1.0)

Full question-and-answer banks for **Foundation, P0, R3–R8**, copied from engineering docs and adapted for PROJECT_DOCS (links point at `02_Novelties/` manuals and viva folders).

**Quick revision:** [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md) (short cheat sheet)  
**Novelty manuals:** [`../../02_Novelties/`](../../02_Novelties/README.md)  
**Glossary (engineering):** ``../../../GLOSSARY.md``

---

## Documents

| # | File | Topic | Approx. depth |
|---|------|-------|---------------|
| 1 | [01_Foundation_QNA.md](01_Foundation_QNA.md) | `shared_contracts/`, DTOs, ops profile | 35+ Qs |
| 2 | [02_P0_QNA.md](02_P0_QNA.md) | P0.1–P0.6 hardening | 30+ Qs |
| 3 | [03_R3_QNA.md](03_R3_QNA.md) | Snapshot twin (COMPLETE Level A) | 15+ Qs |
| 4 | [04_R4_QNA.md](04_R4_QNA.md) | Cross-layer correlation (advisory) | 80+ Qs |
| 5 | [05_R6_QNA.md](05_R6_QNA.md) | Reliability-aware fusion | 50+ Qs |
| 6 | [06_R7_QNA.md](06_R7_QNA.md) | Mitigation verification gate | 80+ Qs |
| 7 | [07_R5_XAI_QNA.md](07_R5_XAI_QNA.md) | XAI + root cause analysis | 35+ Qs |
| 8 | [08_R8_QNA.md](08_R8_QNA.md) | Policy alerting | 50+ Qs |
| 9 | [09_Cross_Cutting_QNA.md](09_Cross_Cutting_QNA.md) | Pipeline, scope, handover | Deep cross-plane |

---

## Recommended reading order (viva prep)

```
GLOSSARY (DOCS) → 01_Foundation → 02_P0
→ 04_R4 → 05_R6 → 06_R7 → 07_R5 → 08_R8
→ 03_R3 (twin — separate from DROP path)
→ 09_Cross_Cutting (integration questions)
→ 08_Novelty_Questions (last-minute drill)
```

Pipeline memory aid: **correlate → fuse → verify → mitigate → explain → alert**. R3 is **read-only replay**, not on the DROP path.

---

## Truthfulness rules

| Rule | Application |
|------|-------------|
| Current code only | Paths like `fusion/engine.py`, `twin/snapshot.py` |
| Not invented | R2 SSL, dashboard auth, Slack/email = **Not implemented** |
| R3 honest status | Snapshot twin coded; **no** live OpenFlow sync or twin-launched Mininet |
| R1 / R9 | **Out of scope** |

---

## Original source

| This folder | Original |
|-------------|----------|
| `01`–`08` | `*_QNA.md` |
| `09` | `QNA.md` |

Engineering ops detail remains in `` (RUNTIME_FLOW, TROUBLESHOOTING, etc.).
