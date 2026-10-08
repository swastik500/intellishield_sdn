# Implementation Documentation

Detailed implementation reference for **IntelliShield SDN**, derived exclusively from the source code and deployed VM configuration. Documents reflect what is **actually built** — not planned infrastructure.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 1 | [01_Technology_Stack.md](01_Technology_Stack.md) | Languages, frameworks, SDN tools, Python packages |
| 2 | [02_AI_Components.md](02_AI_Components.md) | ML, entropy, ADWIN, HDBSCAN, PPO — algorithms and code locations |
| 3 | [03_Kubernetes.md](03_Kubernetes.md) | Container orchestration status (**not implemented**) |
| 4 | [04_Monitoring.md](04_Monitoring.md) | OpenFlow telemetry, logging, metrics, phase health |
| 5 | [05_Dashboard.md](05_Dashboard.md) | FastAPI backend, static UI, Master Control panel |
| 6 | [06_APIs.md](06_APIs.md) | REST endpoints, request/response shapes |
| 7 | [07_Database.md](07_Database.md) | Persistence layer (CSV, JSON, pickle — no SQL database) |
| 8 | [08_Security.md](08_Security.md) | Mitigation safety, traffic guards, dashboard exposure |
| 9 | [09_Configuration.md](09_Configuration.md) | Constants, environment variables, tunable parameters |
| 10 | [10_Deployment.md](10_Deployment.md) | VM setup, processes, startup commands |
| 11 | [11_Module_Reference.md](11_Module_Reference.md) | Every implemented module — files, classes, responsibilities |

## Repository Layout

```text
ddos_network/
├── controller/flow_monitor.py      # OsKen app — Phases 1–7 integration hub
├── entropy_engine/                 # Phase 2
├── traffic_generator/              # Phase 3
├── ml_models/                      # Phase 4
├── mitigation/                     # Phase 5
├── advanced_analytics/             # Phase 6
├── rl_engine/                      # Phase 7
├── twin/                           # R3 snapshot twin (read-only)
├── correlation/ fusion/ verification/
├── rca/ xai/ alerting/             # R5 / R8
├── shared_contracts/               # Foundation
├── dashboard/                      # Phase 8 (api.py, control.py, static/)
├── scripts/compute_metrics.py      # Experiment metrics
├── logs/                           # Runtime CSV/JSON/pickle (git-ignored mostly)
├── verify_phase7.py                # RL unit verification
└── test_phase7.sh                  # RL test wrapper
```

## Related Documentation

- [Novelties](../02_Novelties/README.md) — R4–R8 / Foundation / R3 manuals
- [System Design](../03_System_Design/README.md)
- [Testing](../05_Testing/README.md)
- [Results](../06_Results/README.md)
- `IMPLEMENTED/` — per-phase build notes
