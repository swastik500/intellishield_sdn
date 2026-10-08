# ER Diagram — Logical Data Model

## 1. Overview

IntelliShield SDN does not use a relational database. Persistence is **file-based** (CSV + JSON). This document defines the **logical entity-relationship model** implied by log schemas, in-memory state, and cross-file joins used by `compute_metrics.py` and the dashboard.

Entities are grouped by **producing module**. Relationships use `switch_id` (OpenFlow DPID), `timestamp`, and `scenario_name` as join keys.

---

## 2. Core Entity Relationship Diagram

```mermaid
erDiagram
    SWITCH ||--o{ FLOW_STAT : "produces"
    SWITCH ||--o{ PORT_STAT : "produces"
    SWITCH ||--o{ ENTROPY_METRIC : "produces"
    SWITCH ||--o{ DETECTION_ALERT : "triggers"
    SWITCH ||--o{ ML_PREDICTION : "produces"
    SWITCH ||--o{ ML_ALERT : "triggers"
    SWITCH ||--o{ MITIGATION_ACTION : "executes"
    SWITCH ||--o{ DRIFT_ALERT : "detects"
    SWITCH ||--o{ CLUSTER_LABEL : "assigns"
    SWITCH ||--o{ RL_DECISION : "records"
    SWITCH ||--o| ENTROPY_BASELINE : "maintains"

    SCENARIO ||--o{ SCENARIO_EVENT : "logs"
    SCENARIO ||--o{ ATTACK_LOG : "contains"
    SCENARIO ||--o{ TRAFFIC_LOG : "contains"
    SCENARIO ||--o| TRAFFIC_PROFILE : "snapshots"

    SCENARIO_EVENT ||--o{ ATTACK_WINDOW : "defines"
    ATTACK_WINDOW ||--o{ DETECTION_ALERT : "measured_by"
    ATTACK_WINDOW ||--o{ ML_PREDICTION : "measured_by"
    ATTACK_WINDOW ||--o{ MITIGATION_ACTION : "measured_by"

    ML_PREDICTION ||--o| ML_ALERT : "may_raise"
    ML_PREDICTION }o--|| FEATURE_VECTOR : "derived_from"
    FLOW_STAT }o--|| FEATURE_VECTOR : "aggregated_into"
    ENTROPY_METRIC }o--|| FEATURE_VECTOR : "included_in"

    MITIGATION_ACTION }o--o| BLOCKLIST_ENTRY : "tracked_by"
    RL_DECISION }o--|| THRESHOLD_STATE : "updates"

    EXPERIMENT_RUN ||--o{ ATTACK_WINDOW : "aggregates"
    EXPERIMENT_RUN ||--o| METRICS_REPORT : "produces"

    SWITCH {
        int switch_id PK
        string dpid
        string status
    }

    FLOW_STAT {
        datetime timestamp PK
        int switch_id FK
        string src_mac
        string dst_mac
        int in_port
        int packet_count
        int byte_count
        float packet_rate
        float byte_rate
        float duration_sec
    }

    PORT_STAT {
        datetime timestamp PK
        int switch_id FK
        int port_no
        int rx_packets
        int tx_packets
        int rx_bytes
        int tx_bytes
    }

    ENTROPY_METRIC {
        datetime timestamp PK
        int switch_id FK
        int n_flows
        float src_entropy
        float dst_entropy
        float packet_entropy
        float byte_entropy
        float flow_entropy
        float entropy_score
        string status
        float confidence
    }

    DETECTION_ALERT {
        datetime timestamp PK
        int switch_id FK
        string alert_type
        string dimension
        float entropy_value
        float threshold
        float entropy_score
        float confidence
        string status
    }

    ML_PREDICTION {
        datetime timestamp PK
        int switch_id FK
        string status
        float confidence
        float iso_score
        int dt_label
        float dt_confidence
        string attack_type_hint
        float packet_rate_mean
        int flow_count
    }

    MITIGATION_ACTION {
        datetime timestamp PK
        int switch_id FK
        string action
        string src_mac
        string dst_mac
        string block_type
        string attack_hint
        float confidence
        int timeout_sec
        string status
        string reason
    }

    SCENARIO {
        string scenario_name PK
        int scenario_id
        int duration_sec
    }

    SCENARIO_EVENT {
        datetime timestamp PK
        string scenario_name FK
        string event_type
        string description
        string status
    }

    ATTACK_WINDOW {
        string scenario_name FK
        datetime attack_start
        datetime attack_stop
    }

    METRICS_REPORT {
        datetime generated_at PK
        json per_scenario_latencies
        int false_positive_blocks
    }
```

---

## 3. Entity Catalog by Log File

### 3.1 Phase 1 — Controller Telemetry

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `FLOW_STAT` | `flow_stats.csv` | timestamp + switch_id + src_mac + dst_mac | switch_id |
| `PORT_STAT` | `port_stats.csv` | timestamp + switch_id + port_no | switch_id |

### 3.2 Phase 2 — Entropy Engine

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `ENTROPY_METRIC` | `entropy_logs.csv` | timestamp + switch_id | switch_id |
| `DETECTION_ALERT` | `detection_alerts.csv` | timestamp + switch_id + alert_type | switch_id |
| `ENTROPY_BASELINE` | `entropy_baselines.json` | switch_id + dimension | switch_id |

### 3.3 Phase 3 — Traffic Generator

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `TRAFFIC_LOG` | `traffic_logs.csv` | timestamp + source_host | scenario (implicit) |
| `ATTACK_LOG` | `attack_logs.csv` | timestamp + attack_type | scenario (implicit) |
| `SCENARIO_EVENT` | `scenario_logs.csv` | timestamp + event_type | scenario_name |
| `TRAFFIC_PROFILE` | `traffic_profiles.json` | session timestamp | — |

### 3.4 Phase 4 — ML Models

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `ML_PREDICTION` | `ml_predictions.csv` | timestamp + switch_id | switch_id |
| `ML_ALERT` | `ml_alerts.csv` | timestamp + switch_id | switch_id, ML_PREDICTION |
| `ML_SUMMARY` | `ml_summary.json` | session | switch_id |
| `ML_MODEL` | `logs/models/*.pkl` | model_type | — |

### 3.5 Phase 5 — Mitigation

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `MITIGATION_ACTION` | `mitigation_actions.csv` | timestamp + action + src_mac | switch_id |
| `MITIGATION_SUMMARY` | `mitigation_summary.json` | session | switch_id |
| `BLOCKLIST_ENTRY` | in-memory (`BlocklistManager`) | switch_id + src_mac | switch_id |

### 3.6 Phase 6 — Advanced Analytics

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `DRIFT_ALERT` | `drift_alerts.csv` | timestamp + metric | switch_id |
| `CLUSTER_LABEL` | `cluster_labels.csv` | timestamp + vector_index | switch_id, cluster_id |
| `CLUSTER_SUMMARY` | `cluster_summary.json` | run_id | switch_id |

### 3.7 Phase 7 — RL Engine

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `RL_DECISION` | `rl_decisions.csv` | timestamp + switch_id | switch_id |
| `RL_TRAINING` | `rl_training.csv` | update_timestamp | — |
| `THRESHOLD_STATE` | in-memory (`ThresholdAdapter`) | — | — |
| `PPO_WEIGHTS` | `ppo_weights.pkl` | — | — |

### 3.8 Evaluation

| Entity | File | Primary Key | Foreign Keys |
|--------|------|-------------|--------------|
| `ATTACK_WINDOW` | derived from `scenario_logs.csv` | scenario_name + attack_start | scenario_name |
| `METRICS_REPORT` | `metrics_report.json` | generated_at | ATTACK_WINDOW |

---

## 4. Attribute Schemas (Detailed)

### FLOW_STAT (`flow_stats.csv`)

```text
timestamp, switch_id, src_mac, dst_mac, in_port, priority,
packet_count, byte_count, packet_rate, byte_rate, duration_sec
```

### ENTROPY_METRIC (`entropy_logs.csv`)

```text
timestamp, switch_id, n_flows, src_entropy, dst_entropy,
packet_entropy, byte_entropy, flow_entropy, entropy_score, status, confidence
```

### ML_PREDICTION (`ml_predictions.csv`)

```text
timestamp, switch_id, status, confidence, iso_score,
dt_label, dt_confidence, attack_type_hint, src_entropy,
dst_entropy, entropy_score, packet_rate_mean, flow_count
```

### MITIGATION_ACTION (`mitigation_actions.csv`)

```text
timestamp, action, dpid, src_mac, dst_mac, block_type,
attack_hint, confidence, timeout_sec, status, reason
```

### SCENARIO_EVENT (`scenario_logs.csv`)

```text
timestamp, scenario_name, event_type, description, status
```

**`event_type` values:** `SCENARIO_START`, `ATTACK_START`, `ATTACK_STOP`, `ATTACK1_START`, `ATTACK1_STOP`, `ATTACK2_START`, `ATTACK2_STOP`, `END`

### RL_DECISION (`rl_decisions.csv`)

```text
timestamp, switch_id, packet_rate, byte_rate, entropy_score,
flow_count, ml_label, ml_confidence, pkt_threshold, byte_threshold,
conf_threshold, action_0, action_1, action_2, reward
```

---

## 5. Relationship Cardinality Details

```mermaid
erDiagram
    SCENARIO ||--|{ SCENARIO_EVENT : "1 scenario → many events"
    SCENARIO_EVENT }o--|| ATTACK_WINDOW : "START+STOP pair forms window"

    SWITCH ||--|{ FLOW_STAT : "1 switch → many flow rows per poll"
    FLOW_STAT }|..|{ FEATURE_VECTOR : "batch aggregated per cycle"

    ENTROPY_METRIC ||--o| DETECTION_ALERT : "ALERT/WARNING spawns alert row"
    FEATURE_VECTOR ||--|| ML_PREDICTION : "1 vector → 1 prediction per cycle"

    ML_PREDICTION ||--o| MITIGATION_ACTION : "ATTACK may trigger BLOCK"
    MITIGATION_ACTION ||--|| BLOCKLIST_ENTRY : "1 block → 1 active entry"

    ML_PREDICTION ||--|| RL_DECISION : "same cycle observation"
    RL_DECISION }o--|| THRESHOLD_STATE : "action updates thresholds"
```

---

## 6. Join Keys for Metrics Computation

`scripts/compute_metrics.py` performs these logical joins:

| Join | Left Entity | Right Entity | Key | Purpose |
|------|-------------|--------------|-----|---------|
| J1 | `ATTACK_WINDOW` | `DETECTION_ALERT` | timestamp ∈ window | Entropy detection latency |
| J2 | `ATTACK_WINDOW` | `ML_PREDICTION` | timestamp ∈ window, status=ATTACK | ML detection latency |
| J3 | `ATTACK_WINDOW` | `MITIGATION_ACTION` | timestamp ∈ window, action=BLOCK | Mitigation latency |
| J4 | complement(windows) | `MITIGATION_ACTION` | timestamp ∉ attack windows | False-positive blocks |

---

## 7. In-Memory Entities (Not Persisted to CSV)

| Entity | Module | Attributes | Lifecycle |
|--------|--------|------------|-----------|
| `BLOCKLIST_ENTRY` | `blocklist_manager.py` | src_mac, dpid, expires_at, attack_hint | Until timeout or manual unblock |
| `THRESHOLD_STATE` | `threshold_adapter.py` | pkt_threshold, byte_threshold, conf_threshold | Session-long; checkpointed via RL logs |
| `ENTROPY_WINDOW` | `entropy_detector.py` | deque of flow features per switch | Sliding window per DPID |
| `PPO_REPLAY_BUFFER` | `ppo_agent.py` | state, action, reward transitions | Rolling buffer for policy updates |
| `HDBSCAN_BUFFER` | `hdbscan_clusterer.py` | last N feature vectors | Cleared after clustering run |

---

## 8. Archive Entity

```mermaid
erDiagram
    LOG_ARCHIVE {
        string archive_path PK
        datetime archived_at
        string source_operator
    }

    LOG_ARCHIVE ||--|{ FLOW_STAT : "contains snapshot"
    LOG_ARCHIVE ||--|{ ENTROPY_METRIC : "contains snapshot"
    LOG_ARCHIVE ||--|{ ML_PREDICTION : "contains snapshot"
    LOG_ARCHIVE ||--|{ MITIGATION_ACTION : "contains snapshot"
    LOG_ARCHIVE ||--|{ SCENARIO_EVENT : "contains snapshot"
```

**Path pattern:** `logs/archive/YYYYMMDD_HHMMSS/*.csv`

Archives preserve experiment isolation so `compute_metrics.py` does not cross-contaminate detection timestamps across runs.

---

## 9. Entity Lifecycle Summary

```mermaid
stateDiagram-v2
    [*] --> ScenarioStart : traffic_scheduler starts
    ScenarioStart --> TrafficFlowing : hosts generate traffic
    TrafficFlowing --> AttackActive : ATTACK_START logged
    AttackActive --> Detected : entropy/ML alert
    Detected --> Mitigated : BLOCK action
    Mitigated --> AttackActive : block expires
    AttackActive --> ScenarioEnd : ATTACK_STOP / END
    ScenarioEnd --> MetricsComputed : compute_metrics.py
    MetricsComputed --> Archived : Master Control archive
    Archived --> [*]
```

This logical model supports IEEE-style evaluation queries (detection latency, false positives, per-scenario breakdown) without requiring a SQL database — joins are performed in Python over CSV files at analysis time.
