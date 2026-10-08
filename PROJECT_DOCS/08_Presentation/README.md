# Presentation Documentation

Materials for **viva, IEEE defence, and live demonstration** of IntelliShield SDN.

## Documents

| # | Document | Use when |
|---|----------|----------|
| 1 | [01_Presentation_Outline.md](01_Presentation_Outline.md) | Structuring slides (15–20 min talk) |
| 2 | [02_Demo_Script.md](02_Demo_Script.md) | Step-by-step live demo on VM |
| 3 | [03_Speaking_Notes.md](03_Speaking_Notes.md) | What to say per slide / section |
| 4 | [04_Technology_Explanation.md](04_Technology_Explanation.md) | Plain-language tech stack for examiners |
| 5 | [05_Architecture_Explanation.md](05_Architecture_Explanation.md) | Layered design and data flow for slides |
| 6 | [06_Module_Explanation.md](06_Module_Explanation.md) | Eight-phase module walkthrough |
| 7 | [07_Novelty_Explanation.md](07_Novelty_Explanation.md) | Research contribution (Phases 1–8 + R4–R8 / R3) |

**Full novelty manuals:** [`../02_Novelties/`](../02_Novelties/README.md)

## Recommended Flow

1. **Talk** — follow Outline + Speaking Notes (~15 min)
2. **Demo** — follow Demo Script (~8–10 min)
3. **Q&A** — use Technology, Architecture, Module, and Novelty docs as reference

## Prerequisites

- Ubuntu VM with IntelliShield deployed at `~/intellishield-sdn/`
- Controller running: `osken-manager controller/flow_monitor.py`
- Dashboard running: `python3 dashboard/api.py` → `http://<VM-IP>:8080`
- Sudoers configured for Master Control scenarios (see `IMPLEMENTED/PHASE8.md`)

## Related Documentation

- [Project Overview](../01_Project_Overview/README.md)
- [Novelties](../02_Novelties/README.md)
- [System Design](../03_System_Design/README.md)
- [Implementation](../04_Implementation/README.md)
- [Results](../06_Results/README.md)
