# Sequence Diagrams

## 1. System Bootstrap Sequence

```mermaid
sequenceDiagram
    actor Op as Operator
    participant MN as Mininet / traffic_scheduler
    participant OVS as Open vSwitch
    participant CTRL as osken-manager<br/>flow_monitor.py
    participant LOG as logs/
    participant DASH as dashboard/api.py

    Op->>CTRL: osken-manager controller/flow_monitor.py
    CTRL->>CTRL: Import Phases 2–7 (graceful fallback)
    CTRL->>LOG: Create CSV headers if missing
    CTRL->>LOG: Load ML models from logs/models/
    CTRL->>CTRL: hub.spawn(_monitor)

    Op->>DASH: python3 dashboard/api.py
    DASH-->>Op: Listening on :8080

    Op->>MN: sudo traffic_scheduler --scenario 2
    MN->>OVS: Create topology (5 hosts, 1 switch)
    OVS->>CTRL: OpenFlow connection (DPID 1)
    CTRL->>CTRL: _register_datapath(1)
    CTRL->>OVS: Install table-miss flow (priority 0)

    MN->>LOG: scenario_logs.csv SCENARIO_START
    MN->>MN: Launch baseline ICMP + SYN flood
```

---

## 2. Normal Monitoring Cycle (No Attack)

```mermaid
sequenceDiagram
    participant MON as _monitor thread
    participant OVS as Switch DPID 1
    participant FM as flow_stats_reply_handler
    participant ENT as EntropyDetector
    participant LOG as logs/

    MON->>OVS: OFPFlowStatsRequest
    MON->>OVS: OFPPortStatsRequest
    OVS-->>FM: FlowStatsReply (4 flows)
    OVS-->>FM: PortStatsReply

    FM->>FM: _extract_flow_features × 4
    FM->>LOG: flow_stats.csv (4 rows)
    FM->>LOG: port_stats.csv

    FM->>ENT: add_flows(1, feature_batch)
    FM->>ENT: analyze(1)
    ENT-->>FM: status=NORMAL, score≈0.98
    FM->>LOG: entropy_logs.csv

    Note over FM: Warm-up cycles skip ML/mitigation/RL
```

---

## 3. SYN Flood Detection and Mitigation Sequence

```mermaid
sequenceDiagram
    actor H1 as Attacker h1
    participant OVS as Open vSwitch
    participant FM as flow_monitor
    participant ENT as EntropyDetector
    participant ML as AnomalyDetector
    participant MIT as MitigationEngine
    participant FB as FlowBlocker
    participant RL as PPOAgent
    participant LOG as logs/

    H1->>OVS: SYN flood packets → h2
    OVS->>FM: PacketIn + FlowStatsReply

    FM->>ENT: analyze(1)
    ENT-->>FM: status=ALERT, src_entropy≈0.04
    FM->>LOG: detection_alerts.csv

    FM->>ML: predict(15-dim vector)
    ML-->>FM: status=ATTACK, conf=85%, hint=SYN_FLOOD
    FM->>LOG: ml_predictions.csv

    loop Attack confirmation streak
        FM->>FM: _attack_streak[1] += 1
    end

    FM->>MIT: handle_alert(dpid, prediction, flows)
    MIT->>MIT: identify_attackers() → attacker MAC
    MIT->>FB: block FLOW_PAIR(src, dst)
    FB->>OVS: OFPFlowMod DROP priority=200
    MIT->>LOG: mitigation_actions.csv

    FM->>RL: step(state) → action
    RL-->>FM: threshold deltas
    FM->>LOG: rl_decisions.csv
```

---

## 4. Packet Forwarding and Learning Sequence

```mermaid
sequenceDiagram
    participant H1 as Host h1
    participant OVS as Switch
    participant CTRL as packet_in_handler
    participant FLOW as OpenFlow table

    H1->>OVS: Ethernet frame (unknown dst)
    OVS->>CTRL: PacketIn (table miss)
    CTRL->>CTRL: Learn src MAC → port mapping
    CTRL->>FLOW: Install flow: match in_port+src → output flood
    CTRL->>OVS: PacketOut to correct port(s)

    Note over CTRL: ARP broadcasts (ff:ff:ff:ff:ff:ff) are forwarded,<br/>not dropped. Only LLDP (0x88CC) ignored.
```

---

## 5. ADWIN Early-Warning Sequence

```mermaid
sequenceDiagram
    participant FM as flow_monitor
    participant ADW as ADWINDetector
    participant ML as AnomalyDetector
    participant LOG as logs/

    Note over FM: Attack traffic begins — pkt_rate jumps

    FM->>ADW: update_all(1, {packet_rate_mean: 80000, ...})
    ADW->>ADW: Hoeffding bound test → drift detected
    ADW-->>FM: drift event
    FM->>LOG: drift_alerts.csv
    FM->>FM: Console: CONCEPT DRIFT DETECTED

    Note over ML: ML may still be warming up or<br/>one cycle behind ADWIN

    FM->>ML: predict(vector)
    ML-->>FM: status=ATTACK (next cycle)
```

---

## 6. HDBSCAN Batch Clustering Sequence

```mermaid
sequenceDiagram
    participant FM as flow_monitor
    participant HDB as HDBSCANClusterer
    participant LOG as logs/

    loop Every monitoring cycle
        FM->>HDB: add_vector(1, vec, FEATURE_NAMES)
    end

    Note over HDB: Buffer reaches 10 vectors (~50s)

    HDB->>HDB: sklearn HDBSCAN fit_predict
    HDB->>HDB: Label clusters NORMAL/ATTACK/SUSPICIOUS
    HDB->>LOG: cluster_labels.csv
    HDB->>LOG: cluster_summary.json
    HDB-->>FM: Console cluster report
```

---

## 7. Master Control — Restart Controller Sequence

```mermaid
sequenceDiagram
    actor Op as Operator
    participant UI as Dashboard UI
    participant API as api.py
    participant CP as control.py
    participant PROC as osken-manager process
    participant LOG as /tmp/controller.log

    Op->>UI: Click "Restart Controller"
    UI->>API: POST /api/control/controller/restart
    API->>CP: restart_controller()
    CP-->>UI: {job_id, status: running}

    CP->>CP: _controller_pids() via /proc/cmdline
    CP->>PROC: SIGTERM → SIGKILL if needed
    CP->>PROC: Popen(osken-manager, detached)
    CP->>LOG: append stdout/stderr
    CP->>CP: sleep(20) warmup
    CP->>CP: controller_running() check
    CP-->>UI: job status=success

    loop Poll every 2s
        UI->>API: GET /api/control/jobs/{id}
        API-->>UI: job log tail
    end
```

---

## 8. Master Control — Batch Experiment Sequence

```mermaid
sequenceDiagram
    actor Op as Operator
    participant UI as Dashboard
    participant CP as control.py
    participant ARCH as logs/archive/
    participant CTRL as Controller
    participant TG as traffic_scheduler
    participant MET as compute_metrics.py

    Op->>UI: Click "Run S3+S4+S5"
    UI->>CP: POST /api/control/scenarios/batch

    CP->>ARCH: mv logs/*.csv
    CP->>CTRL: restart + 20s warmup

    loop Scenarios 3, 4, 5
        CP->>TG: sudo python3 -m traffic_generator.traffic_scheduler --scenario N
        TG-->>CP: exit code
    end

    CP->>MET: python3 scripts/compute_metrics.py --json-out
    MET-->>CP: metrics_report.json
    CP-->>UI: job success + log tail
```

---

## 9. Dashboard Live Polling Sequence

```mermaid
sequenceDiagram
    participant Browser
    participant API as FastAPI
    participant CSV as logs/*.csv

    Browser->>API: GET /api/summary
    API->>CSV: read tail rows
    CSV-->>API: latest entropy, ML, blocks
    API-->>Browser: JSON stat cards

    Browser->>API: GET /api/entropy?n=60
    API->>CSV: entropy_logs.csv last 60
    API-->>Browser: chart data

    Browser->>API: GET /api/ml?n=60
    API->>CSV: ml_predictions.csv
    API-->>Browser: ML status timeline

    Browser->>Browser: drawGauge + update charts
```

---

## 10. Block Expiry Sequence

```mermaid
sequenceDiagram
    participant MIT as MitigationEngine
    participant OVS as Switch
    participant CTRL as flow_removed_handler
    participant BL as BlocklistManager
    participant LOG as logs/

    Note over OVS: hard_timeout expires (60s)

    OVS->>CTRL: FlowRemoved message
    CTRL->>BL: remove expired block entry
    CTRL->>LOG: mitigation_actions.csv UNBLOCK/expired
    CTRL->>CTRL: Console: block expired notification

    Note over OVS: Attacker traffic may resume<br/>unless re-detected
```

---

## 11. Scenario Ground-Truth vs Detection Sequence (S2 SYN Flood)

```mermaid
sequenceDiagram
    participant TG as attack_scenarios
    participant LOG as scenario_logs.csv
    participant ENT as EntropyDetector
    participant ML as AnomalyDetector
    participant MET as compute_metrics

    TG->>LOG: SCENARIO_START
    TG->>LOG: ATTACK_START (t=0)

    Note over TG: 60s baseline then SYN flood

    ENT->>LOG: detection_alerts ALERT (t=Δ1)
    ML->>LOG: ml_predictions ATTACK (t=Δ2)

    TG->>LOG: ATTACK_STOP (t=60)
    TG->>LOG: SCENARIO_END

    MET->>LOG: Load attack window [START, STOP+60s]
    MET->>MET: Δ1, Δ2 = detection latencies
    MET->>MET: Write metrics_report.json
```
