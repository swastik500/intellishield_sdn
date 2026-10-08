# Architecture Explanation

Presentation-ready architecture narrative with diagrams for slides and viva boards.

---

## 1. One-Sentence Architecture

> IntelliShield is a **layered, event-driven SDN application** where a single OsKen controller polls OpenFlow statistics, runs detection and mitigation hooks every five seconds, logs results to CSV, and exposes them through a FastAPI dashboard.

---

## 2. Three-Layer Model

```mermaid
flowchart TB
    subgraph L3["Presentation Layer — Phase 8"]
        DASH["Dashboard UI"]
        API["FastAPI REST"]
        MC["Master Control"]
    end

    subgraph L2["Application Layer — Phases 2–7"]
        ENT["Entropy"]
        ML["ML Ensemble"]
        MIT["Mitigation"]
        ADW["ADWIN"]
        HDB["HDBSCAN"]
        RL["PPO RL"]
    end

    subgraph L1["Control + Data Plane — Phase 1 + 3"]
        CTRL["flow_monitor.py"]
        OVS["Open vSwitch"]
        HOSTS["Mininet Hosts"]
    end

    L3 -->|read logs / control| L1
    L2 --> CTRL
    CTRL --> OVS --> HOSTS
    HOSTS -->|traffic| OVS
```

| Layer | Responsibility | Key file |
|-------|----------------|----------|
| **Presentation** | Visualise, orchestrate experiments | `dashboard/api.py` |
| **Application** | Detect, classify, mitigate, adapt | Phase packages |
| **Control** | Telemetry, forwarding, OpenFlow | `flow_monitor.py` |
| **Data** | Packet forwarding | OVS + Mininet |

---

## 3. The Central Hub Pattern

**Design decision:** All phases integrate through **one controller class** — not microservices.

```mermaid
flowchart LR
    FM["IntelliShieldFlowMonitor"]

    FM --> P2["entropy_engine"]
    FM --> P4["ml_models"]
    FM --> P5["mitigation"]
    FM --> P6["advanced_analytics"]
    FM --> P7["rl_engine"]

    P3["traffic_generator"] -.->|generates traffic| FM
```

**Benefits for presentation:**

- Single process to deploy and debug
- Shared feature dict per poll cycle — no serialization overhead
- Graceful degradation if optional import fails

---

## 4. Five-Second Monitoring Cycle

```mermaid
sequenceDiagram
    participant MON as _monitor thread
    participant OVS as Switch
    participant FM as flow_monitor
    participant LOG as logs/

    loop Every 5 seconds
        MON->>OVS: FlowStats + PortStats
        OVS-->>FM: Statistics reply
        FM->>FM: Extract features
        FM->>FM: Entropy analyze
        alt Warm-up complete
            FM->>FM: ML predict
            FM->>FM: Mitigation if ATTACK
            FM->>FM: ADWIN + HDBSCAN + PPO
        end
        FM->>LOG: Append CSV rows
    end
```

**Key timing gates:**

| Gate | Effect |
|------|--------|
| Warm-up (~3 cycles) | ML, mitigation, RL deferred |
| Attack streak (2 cycles) | Block only after confirmation |
| RL conf gate (~80%) | Mitigation requires high confidence |

---

## 5. Detection Pipeline Architecture

```mermaid
flowchart TD
    STATS["OpenFlow flow stats"] --> FEAT["flow_feature dicts"]
    FEAT --> ENT["EntropyDetector<br/>5 dimensions"]
    FEAT --> FB["FeatureBuilder<br/>15-dim vector"]
    ENT --> FB
    FB --> ML["AnomalyDetector<br/>IF + DT"]
    FEAT --> ADW["ADWIN<br/>drift"]
    FB --> HDB["HDBSCAN<br/>batch clusters"]

    ENT -->|ALERT| DEC{"Confirmed?"}
    ML -->|ATTACK| DEC
    DEC -->|yes| MIT["MitigationEngine<br/>OpenFlow DROP"]
    ML & ENT --> RL["PPO<br/>threshold update"]
    RL -->|conf gate| MIT
```

**Defence in depth message:** No single detector is trusted alone — entropy provides fast interpretable signal; ML provides classification; ADWIN provides early warning; streak gates reduce false positives.

---

## 6. Mitigation Architecture

```mermaid
flowchart LR
    ALERT["ATTACK confirmed"] --> ID["identify_attackers()<br/>top pkt-rate MAC"]
    ID --> WL{"Whitelisted?"}
    WL -->|no| STRAT{"Attack hint"}
    STRAT -->|SYN/UDP| FP["FLOW_PAIR block"]
    STRAT -->|volumetric| SM["SRC_MAC block"]
    FP & SM --> OF["OFPFlowMod<br/>priority 200<br/>hard_timeout"]
    OF --> OVS["Switch enforces DROP"]
```

**Surgical mitigation message:** FLOW_PAIR preserves collateral traffic — only the attacker→victim Ethernet flow is dropped.

---

## 7. Data Flow Architecture

```mermaid
flowchart LR
    OF["OpenFlow Stats"] --> CTRL["Controller"]
    CTRL --> CSV["logs/*.csv"]
    TG["Scenarios"] --> SCEN["scenario_logs.csv"]
    CSV --> DASH["Dashboard API"]
    CSV --> MET["compute_metrics.py"]
    SCEN --> MET
    MET --> JSON["metrics_report.json"]
    JSON --> DASH
```

**Logs as system of record:** Dashboard never talks to controller directly for telemetry — it reads the same CSV files researchers analyse offline. Decoupled, auditable, simple.

---

## 8. Experiment Architecture

```mermaid
flowchart TB
    OP["Operator / Dashboard"] --> ARCH["Archive logs"]
    ARCH --> RESTART["Restart controller"]
    RESTART --> SCEN["Run S1–S5"]
    SCEN --> LOGS["Fresh CSV logs"]
    LOGS --> MET["compute_metrics.py"]
    MET --> RPT["metrics_report.json"]
    RPT --> DEMO["Dashboard / Paper tables"]
```

Ground truth in `scenario_logs.csv` (ATTACK_START/STOP) enables automated latency measurement.

---

## 9. Deployment Architecture

```mermaid
flowchart TB
    MAC["macOS dev host"] -->|scp/git| VM["Ubuntu 22.04 VM"]
    subgraph VM
        P1["osken-manager"]
        P2["dashboard :8080"]
        P3["traffic_scheduler"]
        OVS["OVS"]
    end
    BROWSER["Examiner browser"] --> P2
    P1 <--> OVS
    P3 --> OVS
```

**Not shown:** Kubernetes, load balancers, database servers — because they do not exist in this implementation.

---

## 10. Architecture Talking Points

### For "Why monolithic controller?"

> Research prototype prioritising integration speed and reproducibility over distributed scalability. One poll cycle, one feature batch, one decision chain — no network latency between services.

### For "Why file-based logs?"

> IEEE experiments need auditable timestamps. CSV is human-readable, pandas-friendly, and requires zero infrastructure. Dashboard tail-reads last N rows — sufficient for lab scale.

### For "How does RL fit?"

> RL does not replace detectors — it **tunes their gates**. PPO adjusts how aggressive detection and mitigation are based on recent true/false positive feedback.

### For "What happens on controller crash?"

> OpenFlow rules expire via hard_timeout. Dashboard Master Control can restart controller. Logs on disk survive process crash.

---

## 11. Slide-Ready Architecture Bullets

- **Single controller hub** integrates 7 detection/mitigation phases
- **5-second poll loop** drives all analytics synchronously
- **Defence in depth:** entropy → ADWIN → ML → streak → mitigate
- **Surgical OpenFlow blocks** with auto-expiry
- **Online PPO** adapts thresholds during operation
- **CSV-centric** observability + FastAPI dashboard
- **Reproducible scenarios** with ground-truth timestamps
