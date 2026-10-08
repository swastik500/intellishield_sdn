# Component Diagram

## 1. Repository Component Map

```mermaid
flowchart TB
    subgraph ControllerPkg["controller/"]
        FM["flow_monitor.py<br/>IntelliShieldFlowMonitor"]
    end

    subgraph EntropyPkg["entropy_engine/"]
        EU["entropy_utils.py"]
        EC["entropy_calculator.py"]
        ED["entropy_detector.py"]
        EL["entropy_logger.py"]
    end

    subgraph MLPkg["ml_models/"]
        FB["feature_builder.py"]
        AD["anomaly_detector.py"]
        MT["model_trainer.py"]
        EX["explainer.py"]
        MLL["ml_logger.py"]
        MU["ml_utils.py"]
    end

    subgraph MitPkg["mitigation/"]
        ME["mitigation_engine.py"]
        FBK["flow_blocker.py"]
        BLM["blocklist_manager.py"]
        MIL["mitigation_logger.py"]
    end

    subgraph AdvPkg["advanced_analytics/"]
        ADW["adwin_detector.py"]
        HDB["hdbscan_clusterer.py"]
    end

    subgraph RLPkg["rl_engine/"]
        PPO["ppo_agent.py"]
        TA["threshold_adapter.py"]
        ENV["rl_env.py"]
        RLL["rl_logger.py"]
    end

    subgraph TGPkg["traffic_generator/"]
        TS["traffic_scheduler.py"]
        AS["attack_scenarios.py"]
        AG["attack_generator.py"]
        NT["normal_traffic.py"]
        TP["traffic_profiles.py"]
        TGL["traffic_logger.py"]
    end

    subgraph DashPkg["dashboard/"]
        API["api.py"]
        CP["control.py"]
        STATIC["static/index.html"]
    end

    subgraph ScriptsPkg["scripts/"]
        CM["compute_metrics.py"]
    end

    FM --> ED & FB & ME & ADW & HDB & PPO
    ED --> EC --> EU
    ED --> EL
    FB --> AD
    AD --> EX
    AD --> MLL
    ME --> FBK & BLM
    ME --> MIL
    ADW --> HDB
    PPO --> TA & ENV
    PPO --> RLL
    TS --> AS & AG & NT & TP
    AS & AG & NT --> TGL
    API --> STATIC
    API --> CP
    CP --> FM & TS & CM & MT
    CM --> TGL & EL & MLL & MIL
```

## 2. Runtime Process Components

```mermaid
C4Context
    title IntelliShield Runtime Processes

    Person(operator, "Operator / Researcher", "Runs experiments, views dashboard")
    Person(attacker, "Simulated Attacker", "Mininet host running hping3 / iperf")

    System_Boundary(vm, "Ubuntu VM (intellishield-sdn)") {
        System(controller, "osken-manager", "IntelliShieldFlowMonitor — Phases 1–7")
        System(mininet, "traffic_scheduler / mn", "Mininet topology + traffic")
        System(dashboard, "dashboard/api.py", "FastAPI on :8080")
        System(ovs, "Open vSwitch", "OpenFlow 1.3 datapath")
    }

    System_Ext(logs, "logs/", "CSV + JSON persistence")
    System_Ext(models, "logs/models/", "Trained ML weights")

    operator --> dashboard : HTTP :8080
    operator --> dashboard : Master Control API
    dashboard --> logs : read / archive
    dashboard --> controller : restart / stop
    dashboard --> mininet : run scenarios

    mininet --> ovs : host traffic
    attacker --> mininet : SYN/UDP flood

    controller --> ovs : OpenFlow rules + stats
    controller --> logs : append telemetry
    controller --> models : load IF/DT/scaler

    mininet --> logs : scenario + attack events
```

## 3. Controller Internal Components

```mermaid
flowchart LR
    subgraph Events["OsKen Event Handlers"]
        E1["switch_features_handler"]
        E2["packet_in_handler"]
        E3["flow_stats_reply_handler"]
        E4["port_stats_reply_handler"]
        E5["state_change_handler"]
        E6["flow_removed_handler"]
    end

    subgraph Core["Core Services"]
        MON["_monitor thread"]
        REG["datapath registry"]
        EXTRACT["_extract_flow_features"]
        FWD["L2 learning + forward"]
    end

    subgraph Hooks["Phase Hooks (per stats cycle)"]
        H2["entropy hook"]
        H4["ML hook"]
        H5["mitigation hook"]
        H6a["ADWIN hook"]
        H6b["HDBSCAN hook"]
        H7["PPO hook"]
    end

    E1 & E2 & E5 --> REG
    E2 --> FWD
    MON --> REG
    MON -->|OFPFlowStatsRequest| E3
    MON -->|OFPPortStatsRequest| E4
    E3 --> EXTRACT --> H2 --> H4
    H4 --> H5
    H4 --> H6b
    E3 --> H6a
    H4 --> H7
```

## 4. Dashboard Component Breakdown

```mermaid
flowchart TB
    subgraph Frontend["static/index.html"]
        GAUGE["Entropy gauge"]
        CHARTS["Traffic / entropy charts"]
        PANELS["ML / RL / drift / blocklist panels"]
        MCP["Master Control Panel"]
    end

    subgraph Backend["api.py"]
        E_STATUS["/api/status"]
        E_SUMMARY["/api/summary"]
        E_TRAFFIC["/api/traffic"]
        E_ENTROPY["/api/entropy"]
        E_ML["/api/ml"]
        E_RL["/api/rl"]
        E_METRICS["/api/metrics"]
        E_CTRL["/api/control/*"]
    end

    subgraph ControlBackend["control.py"]
        JOBS["Job runner<br/>threading + subprocess"]
        ARCH["archive_logs"]
        RESTART["_restart_controller_worker"]
        SCEN["run_scenario / batch"]
    end

    MCP --> E_CTRL
    GAUGE & CHARTS & PANELS --> E_STATUS & E_SUMMARY & E_TRAFFIC & E_ENTROPY & E_ML & E_RL & E_METRICS
    E_CTRL --> JOBS
    JOBS --> ARCH & RESTART & SCEN
```

## 5. Component Dependency Matrix

| Component | Depends On | Provides To |
|-----------|------------|-------------|
| `flow_monitor.py` | OsKen, all phase packages | OpenFlow control, unified hook orchestration |
| `entropy_engine` | Phase 1 flow features | Entropy metrics, alerts, baselines |
| `ml_models` | Phase 1 + 2 features | Predictions, attack hints, trained models |
| `mitigation` | Phase 4 predictions, Phase 1 MACs | OpenFlow DROP rules, blocklist state |
| `advanced_analytics` | Phase 4 vectors, Phase 2 metrics | Drift alerts, cluster labels |
| `rl_engine` | ML + entropy feedback | Adaptive thresholds, RL decision log |
| `traffic_generator` | Mininet | Ground-truth scenario timeline |
| `dashboard` | `logs/` CSV files | Live UI, experiment orchestration |
| `compute_metrics.py` | scenario + detection + mitigation logs | IEEE latency / FP report |

## 6. External Interfaces

| Interface | Protocol | Direction | Purpose |
|-----------|----------|-----------|---------|
| Controller ↔ OVS | OpenFlow 1.3 (TCP 6653) | Bidirectional | Stats, PacketIn, FlowMod |
| Mininet ↔ Controller | OpenFlow remote | Outbound from OVS | Connect datapath |
| Dashboard ↔ Browser | HTTP (8080) | Outbound | UI + REST API |
| Dashboard ↔ Filesystem | Local I/O | Read/write | Log tailing, archive, job output |
| Master Control ↔ subprocess | `osken-manager`, `sudo python3 -m traffic_generator...` | Spawn | Automated experiments |
