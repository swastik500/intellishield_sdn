# Workflow

## 1. System Lifecycle Workflows

### 1.1 Cold Start (First Run)

```mermaid
flowchart TD
    A["Install deps on VM<br/>Mininet, OsKen, pip packages"]
    B["Train ML models<br/>model_trainer --synthetic"]
    C["Start controller<br/>osken-manager controller/flow_monitor.py"]
    D["Start dashboard<br/>python3 dashboard/api.py"]
    E["Run scenario<br/>traffic_scheduler --scenario 1"]
    F["Verify logs + dashboard"]

    A --> B --> C
    C --> D
    D --> E --> F
```

### 1.2 Steady-State Monitoring Loop

Every **5 seconds** per connected switch:

```mermaid
flowchart TD
    START["Monitor tick"]
    POLL["Request flow + port stats"]
    EXTRACT["Extract flow feature batch"]
    ENT["Phase 2: Entropy analyze"]
    WARM{"Warm-up<br/>complete?"}
    ML["Phase 4: Build vector + predict"]
    STREAK{"ATTACK confirmed<br/>N cycles?"}
    MIT["Phase 5: Block attacker"]
    ADWIN["Phase 6: ADWIN update"]
    HDB["Phase 6: HDBSCAN buffer"]
    RL["Phase 7: PPO step + threshold update"]
    LOG["Append all CSV logs"]
    END["Wait MONITOR_INTERVAL"]

    START --> POLL --> EXTRACT --> ENT --> WARM
    WARM -->|no| LOG
    WARM -->|yes| ML
    ML --> STREAK
    STREAK -->|yes| MIT
    STREAK -->|no| ADWIN
    MIT --> ADWIN
    ADWIN --> HDB --> RL --> LOG --> END --> START
```

---

## 2. Detection Workflow

### 2.1 Multi-Stage Detection Pipeline

```mermaid
stateDiagram-v2
    [*] --> NormalTraffic
    NormalTraffic --> EntropyWarning : dimension threshold breached
    EntropyWarning --> EntropyAlert : composite score collapse
    EntropyAlert --> MLSuspicious : ensemble uncertain
    EntropyAlert --> MLAttack : IF+DT agree ATTACK
    MLSuspicious --> MLAttack : consecutive suspicious cycles
    MLAttack --> MitigationPending : streak < confirm threshold
    MitigationPending --> MitigationActive : streak ≥ confirm threshold
    MitigationActive --> BlockInstalled : conf ≥ RL gate
    BlockInstalled --> NormalTraffic : hard_timeout expires
    MLAttack --> NormalTraffic : attack ends, streak reset
```

### 2.2 Attack Type Hint Resolution

```mermaid
flowchart LR
    ML_HINT["ML Explainer hint"]
    ENT_HINT["Entropy-derived hint<br/>_map_entropy_attack_hint"]
    FALLBACK["SYN_FLOOD fallback<br/>ATTACK + pkt_max > 500"]
    FINAL["Final attack_type_hint"]

    ML_HINT --> CHECK{"Uncertain?<br/>UNKNOWN_ANOMALY"}
    CHECK -->|yes| ENT_HINT --> FINAL
    CHECK -->|no| FINAL
    ENT_HINT --> STILL{"Still unknown?"}
    STILL -->|yes| FALLBACK --> FINAL
    STILL -->|no| FINAL
```

---

## 3. Mitigation Workflow

```mermaid
flowchart TD
    ALERT["ML status ATTACK<br/>or confirmed SUSPICIOUS streak"]
    CONF{"confidence ≥<br/>conf_threshold?"}
    SKIP["Log warning only<br/>no block"]
    ID["identify_attackers()<br/>top pkt_rate MAC"]
    WL{"MAC whitelisted<br/>or already blocked?"}
    TYPE["Choose block type<br/>FLOW_PAIR preferred"]
    RULE["Install OFPFlowMod DROP<br/>priority 200, hard_timeout"]
    CSV["Log mitigation_actions.csv"]
    OVS["Switch enforces block"]

    ALERT --> CONF
    CONF -->|no| SKIP
    CONF -->|yes| ID --> WL
    WL -->|block| TYPE --> RULE --> CSV --> OVS
    WL -->|skip| SKIP
```

**Timeout tiers:**

| ML Confidence | Block Duration |
|---------------|----------------|
| ≥ 90% | 120 s |
| ≥ 75% | 60 s |
| ≥ 60% | 30 s |
| < RL conf gate | No block |

---

## 4. Reinforcement Learning Workflow

```mermaid
flowchart TD
    OBS["Observe 10-dim state<br/>rates, entropy, ML conf, thresholds"]
    ACT["PPO sample action<br/>3-dim Gaussian"]
    APPLY["ThresholdAdapter.apply_action<br/>bounded pkt/byte/conf"]
    REWARD["compute_reward<br/>TP/FP/FN signals"]
    REM["ppo_agent.remember<br/>store transition"]
    UPDATE{"Buffer full?<br/>every N cycles"}
    TRAIN["PPO clipped update<br/>save ppo_weights.pkl"]
    LOG["rl_decisions.csv"]

    OBS --> ACT --> APPLY --> REWARD --> REM --> LOG
    REM --> UPDATE
    UPDATE -->|yes| TRAIN
```

RL runs **online** during live monitoring — thresholds adapt continuously based on recent detection outcomes.

---

## 5. Experiment Workflow (Manual)

```mermaid
flowchart TD
    A1["Archive prior logs<br/>mv logs/*.csv → logs/archive/"]
    A2["Restart controller<br/>osken-manager + 20s warmup"]
    A3["Run scenario S1–S5<br/>sudo traffic_scheduler --scenario N"]
    A4["Inspect logs<br/>entropy, ML, mitigation CSVs"]
    A5["Compute metrics<br/>scripts/compute_metrics.py"]
    A6["Review dashboard<br/>:8080 + /api/metrics"]

    A1 --> A2 --> A3 --> A4 --> A5 --> A6
```

---

## 6. Experiment Workflow (Master Control UI)

```mermaid
flowchart TD
    UI["Operator clicks button<br/>Master Control Panel"]
    API["POST /api/control/*"]
    JOB["control.py spawns Job thread"]
    ACTION{"Action type"}

    ARCH["archive_logs"]
    RESTART["_restart_controller_worker"]
    SCEN["run_scenario / batch"]
    MET["compute_metrics"]
    TRAIN["train_models"]

    UI --> API --> JOB --> ACTION
    ACTION --> ARCH & RESTART & SCEN & MET & TRAIN
    JOB --> POLL["UI polls /api/control/jobs/{id}"]
    POLL --> LOG["control-log div updates"]
```

**Batch eval flow** (`Run S3+S4+S5`):

1. Archive existing logs
2. Restart controller with 20 s warmup
3. Run scenarios 3, 4, 5 sequentially
4. Execute `compute_metrics.py`
5. Write `logs/metrics_report.json`

---

## 7. Dashboard Refresh Workflow

```mermaid
sequenceDiagram
    participant Browser
    participant API as FastAPI api.py
    participant FS as logs/*.csv

    loop Every 5 seconds
        Browser->>API: GET /api/summary
        API->>FS: tail CSV rows
        FS-->>API: parsed JSON
        API-->>Browser: stat cards

        Browser->>API: GET /api/entropy?n=60
        API-->>Browser: time series

        Browser->>API: GET /api/ml?n=60
        API-->>Browser: prediction history
    end

    loop Every 3 seconds
        Browser->>API: GET /api/control/status
        API-->>Browser: controller running + active job
    end
```

---

## 8. Scenario Ground-Truth Workflow (Phase 3)

Each scenario writes lifecycle events to `scenario_logs.csv`:

| Event | Meaning |
|-------|---------|
| `SCENARIO_START` | Scenario name and profile logged |
| `ATTACK_START` / `ATTACK1_START` | Ground-truth attack onset |
| `ATTACK_STOP` / `ATTACK1_STOP` | Attack cessation (including S4 burst after auto-stop) |
| `SCENARIO_END` | Scenario complete |

`compute_metrics.py` uses these windows to measure:

- **Detection latency** — first entropy/ML alert after `ATTACK_START`
- **Mitigation latency** — first BLOCK after `ATTACK_START`
- **False positives** — blocks during non-attack windows

---

## 9. Failure and Recovery Workflows

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Controller crash | Dashboard shows controller stopped | Master Control → Restart Controller |
| Corrupt CSV headers | `compute_metrics` header fallback | Archive logs, restart controller |
| ML models missing | Controller auto-trains synthetic on startup | `train_models` from UI |
| Scenario sudo denied | Job log shows permission error | Configure `/etc/sudoers.d/intellishield` |
| Stale logs mixing runs | Inflated latency metrics | Archive before each experiment batch |
