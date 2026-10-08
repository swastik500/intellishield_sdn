# System Design

Technical architecture documentation for **IntelliShield SDN** — a self-evolving hybrid framework for DDoS detection and mitigation in Software Defined Networks.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 1 | [01_Overall_Architecture.md](01_Overall_Architecture.md) | Layered architecture, design principles, phase map |
| 2 | [02_Component_Diagram.md](02_Component_Diagram.md) | Major components and inter-module dependencies |
| 3 | [03_Module_Design.md](03_Module_Design.md) | Per-package responsibilities, classes, and interfaces |
| 4 | [04_Workflow.md](04_Workflow.md) | End-to-end operational workflows (monitoring, detection, mitigation, experiments) |
| 5 | [05_Data_Flow.md](05_Data_Flow.md) | How data moves from OpenFlow stats to logs and dashboard |
| 6 | [06_Sequence_Diagram.md](06_Sequence_Diagram.md) | Time-ordered interactions for key scenarios |
| 7 | [07_Deployment_Architecture.md](07_Deployment_Architecture.md) | VM topology, processes, ports, and operator setup |
| 8 | [08_ER_Diagram.md](08_ER_Diagram.md) | Logical data model for logs, entities, and relationships |

## Basis

These documents reflect the **implemented** codebase (eight phases plus Release 1.0 novelty planes):

- `controller/flow_monitor.py` — central OsKen application integrating Phases 1–7 and R4–R8 hooks
- `entropy_engine/`, `ml_models/`, `mitigation/`, `advanced_analytics/`, `rl_engine/`
- `correlation/`, `fusion/`, `verification/`, `rca/`, `xai/`, `alerting/`, `shared_contracts/`
- `twin/` — read-only snapshot twin (not a second control plane)
- `traffic_generator/` — reproducible Mininet experiment scenarios (S1–S5)
- `dashboard/` — FastAPI live UI with Master Control panel
- `scripts/compute_metrics.py` — IEEE experiment metrics reporter

## Related Documentation

- [Project Overview](../01_Project_Overview/README.md) — executive summary, objectives, scope, novelty
- [Novelties](../02_Novelties/README.md) — Foundation, P0, R3–R8 (copied from engineering docs)
- `IMPLEMENTED/` — per-phase implementation notes and verification
