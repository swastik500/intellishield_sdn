# Appendix

## Appendix A — Repository Structure

```
ddos_network/
├── controller/           # Phase 1 — OsKen flow monitor (hub)
├── entropy_engine/       # Phase 2 — Shannon entropy detection
├── traffic_generator/      # Phase 3 — S1–S5 scenarios
├── ml_models/            # Phase 4 — Feature builder, ensemble, explainer
├── mitigation/             # Phase 5 — OpenFlow rule engine
├── advanced_analytics/     # Phase 6 — ADWIN, HDBSCAN
├── rl_engine/              # Phase 7 — PPO threshold tuning
├── dashboard/              # Phase 8 — FastAPI + static UI
├── scripts/                # start_all.sh, compute_metrics.py
├── config/                 # settings.py
├── models/               # Trained .pkl files
├── logs/                 # Runtime CSV/JSON logs
├── IMPLEMENTED/          # Phase completion notes (PHASE1–8.md)
├── PROJECT_DOCS/         # Full documentation set
└── verify_phase7.py      # Automated validation script
```

## Appendix B — Attack Scenarios (S1–S5)

| ID | Name | Duration | Traffic | Attack |
|----|------|----------|---------|--------|
| S1 | Normal baseline | ~60 s | ICMP ping (light) | None |
| S2 | SYN flood | ~60 s | Baseline + SYN flood | `hping3 -S` to victim |
| S3 | UDP flood | ~60 s | Baseline + UDP flood | `hping3 --udp` to victim |
| S4 | Burst flood | ~38 s | Baseline + 8 s SYN burst | Short-duration stress test |
| S5 | Mixed attack | ~90 s | SYN flood then UDP flood | Sequential multi-type |

Ground truth: `logs/scenario_logs.csv` (ATTACK_START / ATTACK_END timestamps).

## Appendix C — 15-Dimensional ML Feature Vector

| Index | Feature | Source |
|-------|---------|--------|
| 1 | Packet rate | Flow stats |
| 2 | Byte rate | Flow stats |
| 3 | Flow duration | Flow stats |
| 4 | Source flow count | Flow stats |
| 5 | Destination flow count | Flow stats |
| 6 | Entropy — source MAC | Entropy engine |
| 7 | Entropy — destination MAC | Entropy engine |
| 8 | Entropy — packet | Entropy engine |
| 9 | Entropy — byte | Entropy engine |
| 10 | Entropy — flow | Entropy engine |
| 11 | Packet/byte ratio | Derived |
| 12 | Rate delta (current − previous) | Derived |
| 13 | Entropy composite score | Entropy engine |
| 14 | Flow count rate | Derived |
| 15 | Max dimension entropy drop | Derived |

## Appendix D — Dashboard REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | System health and phase status |
| GET | `/api/alerts` | Recent entropy alerts |
| GET | `/api/blocks` | Active mitigation blocks |
| GET | `/api/ml` | Latest ML predictions |
| GET | `/api/entropy` | Current entropy state |
| GET | `/api/rl` | RL thresholds and rewards |
| POST | `/api/control/run_scenario` | Execute S1–S5 |
| POST | `/api/control/restart_controller` | Restart OsKen controller |
| POST | `/api/control/compute_metrics` | Run metrics script |
| POST | `/api/control/retrain` | Retrain ML models |

*Full API documentation: `PROJECT_DOCS/04_Implementation/06_APIs.md`*

## Appendix E — Log Files

| File | Contents |
|------|----------|
| `logs/entropy_alerts.csv` | Timestamp, state, dimension scores |
| `logs/ml_predictions.csv` | Label, confidence, attack hint |
| `logs/mitigation_blocks.csv` | src_mac, dst_mac, timeout, timestamp |
| `logs/scenario_logs.csv` | Scenario ID, ATTACK_START/END |
| `logs/flow_stats.csv` | Per-flow rate snapshots |
| `logs/rl_rewards.json` | PPO episode rewards |
| `logs/metrics_summary.json` | Output of `compute_metrics.py` |

## Appendix F — Key Configuration Parameters

| Parameter | Default | Module |
|-----------|---------|--------|
| `MONITOR_INTERVAL` | 5 | `flow_monitor.py` |
| `WINDOW_SIZE` | 10 | `entropy_detector.py` |
| Warm-up cycles | 3 | `flow_monitor.py` |
| Attack streak | 2 | `flow_monitor.py` |
| HDBSCAN interval | 10 cycles | `hdbscan_clusterer.py` |
| IF weight | 0.4 | `ensemble.py` |
| DT weight | 0.6 | `ensemble.py` |
| Block hard_timeout | 30–120 s | `mitigation_engine.py` |
| Dashboard port | 8080 | `dashboard/app.py` |

*Full configuration: `PROJECT_DOCS/04_Implementation/09_Configuration.md`*

## Appendix G — Metrics Computation

`scripts/compute_metrics.py` reads `scenario_logs.csv` and detector logs, aligns events within attack windows, and outputs:

- **Detection latency** — time from ATTACK_START to first ALERT/ATTACK
- **Mitigation latency** — time from ATTACK_START to first block
- **False positive count** — blocks outside attack windows
- **True positive count** — blocks inside attack windows

**Workflow:** Archive `logs/` → run scenario → compute metrics → review `metrics_summary.json`.

## Appendix H — Phase Verification Checklist

| Phase | Verification | Script / Evidence |
|-------|--------------|-------------------|
| 1 | Flow stats, port stats, safety guard | `IMPLEMENTED/PHASE1.md` |
| 2 | Shannon H, entropy states | Unit tests, `IMPLEMENTED/PHASE2.md` |
| 3 | S1–S5 scenarios | `IMPLEMENTED/PHASE3.md` |
| 4 | Ensemble, explainer | `IMPLEMENTED/PHASE4.md` |
| 5 | FLOW_PAIR blocks | `IMPLEMENTED/PHASE5.md` |
| 6 | ADWIN, HDBSCAN | `IMPLEMENTED/PHASE6.md` |
| 7 | PPO, threshold adapter | `verify_phase7.py`, `IMPLEMENTED/PHASE7.md` |
| 8 | Dashboard, Master Control | `IMPLEMENTED/PHASE8.md` |

## Appendix I — Glossary

| Term | Definition |
|------|------------|
| ADWIN | Adaptive Windowing — drift detection algorithm |
| DDoS | Distributed Denial of Service |
| FLOW_PAIR | Mitigation matching both source and destination MAC |
| HDBSCAN | Hierarchical Density-Based Spatial Clustering |
| OpenFlow | Southbound SDN protocol for flow table management |
| OsKen | Python SDN controller framework (Ryu-compatible) |
| PPO | Proximal Policy Optimization — RL algorithm |
| SDN | Software Defined Networking |
| Shannon entropy | Measure of uncertainty in a probability distribution |

## Appendix J — Viva Preparation Pointers

Oral examination Q&A organised by topic:

| Document | Topics |
|----------|--------|
| `07_Viva/01_Technical_Questions.md` | SDN, OpenFlow, DDoS fundamentals |
| `07_Viva/02_Architecture_Questions.md` | Hub design, data flow, phases |
| `07_Viva/03_Kubernetes_Questions.md` | Why K8s not implemented |
| `07_Viva/04_AI_Questions.md` | ML, entropy, RL, ADWIN |
| `07_Viva/05_DevOps_Questions.md` | VM deployment, scripts |
| `07_Viva/06_Database_Questions.md` | CSV vs SQL rationale |
| `07_Viva/07_Expected_Answers_Summary.md` | Quick-reference answers |

## Appendix K — Presentation Materials

| Document | Purpose |
|----------|---------|
| `08_Presentation/01_Presentation_Outline.md` | 21-slide structure |
| `08_Presentation/02_Demo_Script.md` | Live demonstration steps |
| `08_Presentation/03_Speaking_Notes.md` | Narration per slide |
| `08_Presentation/07_Novelty_Explanation.md` | Contribution framing |

## Appendix L — Sample Metrics Output (Illustrative)

*Replace with actual VM run data before submission.*

```json
{
  "scenario": "S2_SYN_FLOOD",
  "detection_latency_s": 8.2,
  "mitigation_latency_s": 13.5,
  "entropy_first_alert_s": 7.1,
  "ml_first_attack_s": 12.4,
  "blocks_installed": 1,
  "false_positives": 0,
  "true_positives": 1
}
```

## Appendix M — Components Not Implemented

| Component | Status | Rationale |
|-----------|--------|-----------|
| Kubernetes | Not implemented | Lab VM scope; documented honestly |
| Docker | Not implemented | Direct process deployment sufficient |
| SQL database | Not implemented | CSV adequate for experiment scale |
| Dashboard auth/TLS | Not implemented | Isolated lab network |
| Multi-switch topology | Not implemented | Single-switch validation scope |

*Details: `PROJECT_DOCS/04_Implementation/03_Kubernetes.md`, `07_Database.md`*

---

*This appendix supplements the main report chapters. For exhaustive module-level documentation, see `PROJECT_DOCS/04_Implementation/11_Module_Reference.md`.*
