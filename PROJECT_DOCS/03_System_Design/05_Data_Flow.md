# Data Flow

## 1. End-to-End Data Flow Overview

```mermaid
flowchart LR
    subgraph Sources["Data Sources"]
        OF["OpenFlow Stats<br/>Flow + Port"]
        PKTS["Mininet Packets<br/>ICMP / TCP / UDP / hping3"]
        SCEN["Scenario Events<br/>ATTACK_START/STOP"]
    end

    subgraph Processing["Processing Pipeline"]
        P1["Phase 1<br/>Feature Extraction"]
        P2["Phase 2<br/>Entropy Analysis"]
        P4["Phase 4<br/>ML Inference"]
        P5["Phase 5<br/>Mitigation Decision"]
        P6["Phase 6<br/>Drift + Cluster"]
        P7["Phase 7<br/>RL Update"]
    end

    subgraph Sinks["Persistence & Consumers"]
        CSV["logs/*.csv"]
        JSON["logs/*.json"]
        OFOUT["OpenFlow DROP Rules"]
        DASH["Dashboard API"]
        MET["compute_metrics.py"]
    end

    OF --> P1
    PKTS --> OF
    SCEN --> CSV

    P1 --> P2 & P4 & P6
    P2 --> P4 & P7
    P4 --> P5 & P6 & P7
    P5 --> OFOUT

    P1 & P2 & P4 & P5 & P6 & P7 --> CSV & JSON
    CSV --> DASH & MET
    JSON --> DASH
```

---

## 2. Per-Cycle Data Flow (5-Second Monitoring Tick)

```mermaid
flowchart TB
    subgraph Input["Input Data"]
        FS["OFPFlowStatsReply<br/>per-flow counters"]
        PS["OFPPortStatsReply<br/>port counters"]
    end

    subgraph Transform["Transformations"]
        T1["List of flow_feature dicts<br/>11 fields each"]
        T2["entropy_result dict<br/>8 metrics + status"]
        T3["15-dim numpy vector<br/>+ meta dict"]
        T4["prediction + explanation dicts"]
        T5["3-dim RL action<br/>threshold deltas"]
    end

    subgraph Output["Outputs per Cycle"]
        O1["flow_stats.csv"]
        O2["port_stats.csv"]
        O3["entropy_logs.csv"]
        O4["detection_alerts.csv"]
        O5["ml_predictions.csv"]
        O6["mitigation_actions.csv"]
        O7["drift_alerts.csv"]
        O8["cluster_labels.csv"]
        O9["rl_decisions.csv"]
    end

    FS --> T1
    T1 --> O1
  PS --> O2
    T1 --> T2 --> O3
    T2 -->|if ALERT| O4
    T1 & T2 --> T3 --> T4
    T4 --> O5
    T4 -->|if ATTACK| O6
    T3 -->|every 10 cycles| O8
    T1 -->|metrics dict| O7
    T4 & T2 --> T5 --> O9
```

---

## 3. Feature Data Flow (Phase 1 → Phase 4)

```mermaid
flowchart LR
    subgraph Raw["Raw OpenFlow Stats"]
        PC["packet_count"]
        BC["byte_count"]
        DUR["duration_sec"]
        SMAC["src_mac / dst_mac"]
    end

    subgraph Aggregated["FeatureBuilder Aggregates"]
        PRM["packet_rate_mean"]
        PRX["packet_rate_max"]
        BRM["byte_rate_mean"]
        FC["flow_count"]
        USC["unique_src_count"]
        FCON["flow_concentration"]
    end

    subgraph Entropy["Phase 2 Metrics"]
        SE["src_entropy"]
        DE["dst_entropy"]
        PE["packet_entropy"]
        ES["entropy_score"]
    end

    subgraph Vector["15-dim ML Vector"]
        V["numpy.ndarray shape (15,)"]
    end

    PC & BC & DUR --> PRM & PRX & BRM & FC
    SMAC --> USC & FCON
    SE & DE & PE & ES --> V
    PRM & PRX & BRM & FC & USC & FCON --> V
    V --> IF["IsolationForest"]
    V --> DT["DecisionTree"]
```

---

## 4. Control-Plane Feedback Data Flow

Mitigation and RL create **feedback loops** back to the data plane and detection gates:

```mermaid
flowchart TD
    ML["ml_predictions.csv<br/>status, confidence"]
    MIT["mitigation_actions.csv<br/>BLOCK events"]
    RL["rl_decisions.csv<br/>thresholds, reward"]

    ML --> RL
    ML --> MIT
    MIT --> OVS["OpenFlow switch<br/>DROP matching packets"]
    RL --> GATES["Updated thresholds<br/>pkt / byte / conf"]
    GATES --> ML
    GATES --> MIT
    OVS -->|reduced traffic| STATS["Next flow stats cycle"]
    STATS --> ML
```

---

## 5. Log File Data Flow Map

```mermaid
flowchart TB
    FM["flow_monitor.py"]
    TG["traffic_generator"]
    CM["compute_metrics.py"]
    API["dashboard/api.py"]

    FM --> F1["flow_stats.csv"]
    FM --> F2["port_stats.csv"]
    FM --> F3["entropy_logs.csv"]
    FM --> F4["detection_alerts.csv"]
    FM --> F5["entropy_baselines.json"]
    FM --> F6["ml_predictions.csv"]
    FM --> F7["ml_alerts.csv"]
    FM --> F8["ml_summary.json"]
    FM --> F9["mitigation_actions.csv"]
    FM --> F10["mitigation_summary.json"]
    FM --> F11["drift_alerts.csv"]
    FM --> F12["cluster_labels.csv"]
    FM --> F13["cluster_summary.json"]
    FM --> F14["rl_decisions.csv"]
    FM --> F15["rl_training.csv"]
    FM --> F16["logs/models/*.pkl"]

    TG --> F17["scenario_logs.csv"]
    TG --> F18["attack_logs.csv"]
    TG --> F19["traffic_logs.csv"]
    TG --> F20["traffic_profiles.json"]

    F3 & F4 & F6 & F9 & F17 --> CM
    CM --> F21["metrics_report.json"]

    F1 & F2 & F3 & F4 & F6 & F9 & F11 & F14 & F21 --> API
```

---

## 6. Dashboard API Data Flow

| Endpoint | Primary Source Files | Data Returned |
|----------|---------------------|---------------|
| `/api/traffic` | `flow_stats.csv` | packet_rate, byte_rate time series |
| `/api/entropy` | `entropy_logs.csv` | 5 entropy dimensions + composite |
| `/api/alerts` | `detection_alerts.csv` | entropy alert events |
| `/api/ml` | `ml_predictions.csv` | status, confidence, attack hint |
| `/api/blocklist` | `mitigation_actions.csv` | recent BLOCK/UNBLOCK actions |
| `/api/rl` | `rl_decisions.csv` | thresholds, reward, ML label |
| `/api/drift` | `drift_alerts.csv` | ADWIN drift events |
| `/api/summary` | multiple CSVs | aggregated stat cards |
| `/api/metrics` | `metrics_report.json` | experiment evaluation summary |
| `/api/status` | file existence checks | phase health indicators |

**Read pattern:** API opens CSV, reads last *N* rows via `csv.DictReader`, parses timestamps, returns JSON. No database intermediary — files are the single source of truth.

---

## 7. Experiment Metrics Data Join

```mermaid
flowchart LR
    SL["scenario_logs.csv<br/>ATTACK_START / STOP"]
    EA["detection_alerts.csv<br/>entropy ALERT/WARNING"]
    MP["ml_predictions.csv<br/>ML ATTACK"]
    MA["mitigation_actions.csv<br/>BLOCK"]

    SL --> WIN["Attack windows<br/>start → stop + grace"]
    WIN --> EA
    WIN --> MP
    WIN --> MA

    EA --> DL["entropy_detection_latency"]
    MP --> ML["ml_detection_latency"]
    MA --> MLAT["mitigation_latency"]
    MA --> FP["false_positive_blocks"]

    DL & ML & MLAT & FP --> REPORT["metrics_report.json"]
```

**Window constraint:** detections counted only within `[attack_start, attack_stop + 60s grace]` to prevent cross-run bleed.

---

## 8. Data Volume and Retention

| Log | Approx. Frequency | Typical Row Size |
|-----|-------------------|------------------|
| `flow_stats.csv` | Every flow × every 5 s | ~150 bytes/row |
| `entropy_logs.csv` | 1 row / switch / 5 s | ~120 bytes/row |
| `ml_predictions.csv` | 1 row / switch / 5 s (post warm-up) | ~200 bytes/row |
| `rl_decisions.csv` | 1 row / switch / 5 s | ~180 bytes/row |
| `scenario_logs.csv` | Event-driven (few per scenario) | ~100 bytes/row |

**Archival:** Master Control `archive_logs` moves CSVs to `logs/archive/<YYYYMMDD_HHMMSS>/` before new experiment runs.

---

## 9. Data Types and Formats

| Format | Usage |
|--------|-------|
| **CSV** | Time-series telemetry, alerts, actions (append-only) |
| **JSON** | Session summaries, baselines, cluster history, metrics report |
| **PKL** | ML models (IsolationForest, DecisionTree, StandardScaler), PPO weights |
| **OpenFlow** | Binary flow mods (not persisted; ephemeral with hard_timeout) |

**Timestamp format:** `YYYY-MM-DD HH:MM:SS` (local VM timezone; dashboard displays controller/log timestamps as written).
