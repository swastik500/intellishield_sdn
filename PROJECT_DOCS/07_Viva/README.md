# Viva Preparation

Question-and-answer bank for **IntelliShield SDN** viva, project defence, and technical oral examination.

## Documents

| # | Document | Topics |
|---|----------|--------|
| 1 | [01_Technical_Questions.md](01_Technical_Questions.md) | SDN, OpenFlow, Mininet, Python, phases |
| 2 | [02_Architecture_Questions.md](02_Architecture_Questions.md) | Design, data flow, integration, trade-offs |
| 3 | [03_Kubernetes_Questions.md](03_Kubernetes_Questions.md) | Containers/orchestration (actual vs future) |
| 4 | [04_AI_Questions.md](04_AI_Questions.md) | Entropy, ML, ADWIN, HDBSCAN, PPO |
| 5 | [05_DevOps_Questions.md](05_DevOps_Questions.md) | Deployment, VM, dashboard, testing, CI |
| 6 | [06_Database_Questions.md](06_Database_Questions.md) | Persistence, CSV/JSON, no SQL |
| 7 | [07_Expected_Answers_Summary.md](07_Expected_Answers_Summary.md) | Quick-reference cheat sheet |
| 8 | [08_Novelty_Questions.md](08_Novelty_Questions.md) | Short novelty drill (Foundation, P0, R3–R8) |
| — | [**Novelty_QNA/**](Novelty_QNA/README.md) | **Full Q&A banks** (~400+ questions, copied from engineering docs) |

## How to Use

1. Read each category file — every question includes an **Expected Answer**.
2. Use `07_Expected_Answers_Summary.md` for last-minute revision.
3. For Release 1.0 planes, use [`Novelty_QNA/`](Novelty_QNA/README.md) (full banks) or [`08_Novelty_Questions.md`](08_Novelty_Questions.md) (short drill).
4. Cross-reference [Implementation](../04_Implementation/) and [Presentation](../08_Presentation/) for depth.

## Honest Positioning

Answers reflect **what is actually implemented**:

- **Kubernetes:** not used — deployment is Ubuntu VM + native processes
- **Database:** no SQL — CSV/JSON/pickle under `logs/`
- **DevOps:** manual VM deploy + dashboard Master Control — no Docker/CI in repo

## Related Documentation

- [Project Overview](../01_Project_Overview/README.md)
- [Novelties](../02_Novelties/README.md) — manuals for Foundation, P0, R3–R8
- [Novelty Q&A](Novelty_QNA/README.md) — full question banks
- [Testing](../05_Testing/README.md)
- [Results](../06_Results/README.md)
