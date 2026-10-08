# IntelliShield SDN — Usage Guide

> **Project:** IntelliShield SDN — Self-Evolving Hybrid Framework for DDoS Detection and Mitigation in Software Defined Networks
> **Type:** MCA Final-Year IEEE Research Prototype
> **Author:** IntelliShield SDN Research Team

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Environment & Prerequisites](#2-environment--prerequisites)
3. [Project Structure](#3-project-structure)
4. [Quick Start (5-Minute Demo)](#4-quick-start-5-minute-demo)
5. [Phase-by-Phase Usage](#5-phase-by-phase-usage)
   - [Phase 1 — Flow Statistics Monitoring](#phase-1--flow-statistics-monitoring)
   - [Phase 2 — Entropy Detection Engine](#phase-2--entropy-detection-engine)
   - [Phase 3 — Traffic Generation & Attack Simulation](#phase-3--traffic-generation--attack-simulation)
   - [Phase 4 — ML Anomaly Detection](#phase-4--ml-anomaly-detection)
   - [Phase 5 — Automated Mitigation](#phase-5--automated-mitigation)
   - [Phase 6 — Behaviour Analyst (ADWIN + HDBSCAN)](#phase-6--behaviour-analyst-adwin--hdbscan)
6. [Running Experiments](#6-running-experiments)
7. [Interpreting Console Output](#7-interpreting-console-output)
8. [Log Files Reference](#8-log-files-reference)
9. [Manual Mininet Commands](#9-manual-mininet-commands)
10. [Troubleshooting](#10-troubleshooting)
11. [Project Roadmap Status](#11-project-roadmap-status)

---

## 1. System Overview

IntelliShield SDN is a **layered cybersecurity research framework** that detects and mitigates DDoS attacks in an OpenFlow 1.3 Software Defined Network. Each phase builds on the previous:

```
                    ┌─────────────────────────────────────────┐
                    │         IntelliShield SDN Stack          │
                    ├─────────────────────────────────────────┤
  Phase 1  ─────►  │  Flow Statistics Monitor (OsKen + OVS)  │
                    │  Polls every 5s via OFPFlowStatsReq     │
                    ├─────────────────────────────────────────┤
  Phase 2  ─────►  │  Entropy Detection Engine               │
                    │  5-dimensional Shannon entropy analysis  │
                    ├─────────────────────────────────────────┤
  Phase 3  ─────►  │  Traffic Generation & Attack Simulation  │
                    │  hping3 / iperf / Mininet scenarios      │
                    ├─────────────────────────────────────────┤
  Phase 4  ─────►  │  ML Anomaly Detection                   │
                    │  Isolation Forest + Decision Tree (15-d) │
                    ├─────────────────────────────────────────┤
  Phase 5  ─────►  │  Automated Mitigation Engine            │
                    │  OpenFlow DROP rules via OFPFlowMod     │
                    └─────────────────────────────────────────┘
```

**Detection latency:** ~5–10 seconds (driven by 5s poll interval)
**Mitigation latency:** ~0ms after detection (OpenFlow rule is immediate)

---

## 2. Environment & Prerequisites

### VM Details

| Item | Value |
|------|-------|
| OS | Ubuntu 22.04 LTS |
| VM IP | `192.168.64.5` |
| VM User | `akshay` |
| Project Dir | `~/intellishield-sdn/` |
| Python | 3.10 |

### Required Software (already installed on VM)

```bash
# SDN Stack
osken-manager          # OsKen SDN controller
ovs-vswitchd           # Open vSwitch
mininet                # Network emulator
hping3                 # DDoS traffic generator
iperf                  # Bandwidth testing

# Python packages
scikit-learn==1.7.2    # ML models
numpy==2.2.6           # Numerical computing
pandas==2.3.3          # Data analysis
```

### Verify Environment

```bash
ssh akshay@192.168.64.5
cd ~/intellishield-sdn

# Check all components
python3 -c "import sklearn, numpy, pandas; print('ML deps OK')"
osken-manager --version
mn --version
hping3 --version
```

---

## 3. Project Structure

```
~/intellishield-sdn/
│
├── controller/
│   └── flow_monitor.py          ← Main OsKen controller (all phases integrated)
│
├── entropy_engine/              ← Phase 2: Entropy Detection
│   ├── entropy_calculator.py    ← Shannon entropy math
│   ├── entropy_detector.py      ← 5-dim detection + composite score
│   ├── entropy_logger.py        ← CSV logging
│   └── entropy_utils.py         ← Utility functions
│
├── traffic_generator/           ← Phase 3: Attack Simulation
│   ├── traffic_profiles.py      ← Profile dataclasses + templates
│   ├── normal_traffic.py        ← ICMP/TCP/UDP/HTTP/Mixed generators
│   ├── attack_generator.py      ← SYN/UDP/ICMP flood engines
│   ├── attack_scenarios.py      ← 5 predefined IEEE scenarios
│   ├── traffic_scheduler.py     ← Standalone CLI orchestrator
│   └── traffic_logger.py        ← Event logging
│
├── ml_models/                   ← Phase 4: ML Detection
│   ├── feature_builder.py       ← 15-dim feature vector builder
│   ├── anomaly_detector.py      ← IsolationForest + DecisionTree
│   ├── model_trainer.py         ← Training pipeline
│   ├── explainer.py             ← Explainability + attack type hints
│   └── ml_logger.py             ← Prediction logging
│
├── mitigation/                  ← Phase 5: Automated Response
│   ├── flow_blocker.py          ← OpenFlow DROP rule installer
│   ├── blocklist_manager.py     ← Block state + whitelist
│   ├── mitigation_engine.py     ← Confidence-based orchestrator
│   └── mitigation_logger.py     ← Action logging
│
├── logs/                        ← All output data (auto-created)
│   ├── flow_stats.csv           ← Phase 1 flow telemetry
│   ├── port_stats.csv           ← Phase 1 port counters
│   ├── entropy_logs.csv         ← Phase 2 entropy time series
│   ├── detection_alerts.csv     ← Phase 2 alert events
│   ├── traffic_logs.csv         ← Phase 3 traffic events
│   ├── attack_logs.csv          ← Phase 3 attack events
│   ├── scenario_logs.csv        ← Phase 3 scenario timestamps
│   ├── ml_features.csv          ← Phase 4 feature vectors
│   ├── ml_predictions.csv       ← Phase 4 per-cycle predictions
│   ├── ml_alerts.csv            ← Phase 4 attack predictions
│   ├── mitigation_actions.csv   ← Phase 5 block/unblock log
│   └── models/                  ← Phase 4 saved ML models
│       ├── isolation_forest.pkl
│       ├── decision_tree.pkl
│       └── scaler.pkl
│
└── IMPLEMENTED/                 ← Phase documentation
    ├── PHASE1.md
    ├── PHASE2.md
    ├── PHASE3.md
    ├── PHASE4.md
    └── PHASE5.md
```

---

## 4. Quick Start (5-Minute Demo)

This runs the full detection + mitigation pipeline in ~5 minutes.

### Step 1 — SSH into VM

```bash
ssh akshay@192.168.64.5
cd ~/intellishield-sdn
```

### Step 2 — Start the Controller (Terminal 1)

```bash
osken-manager controller/flow_monitor.py
```

Wait for:
```
[IntelliShieldController] Phase 1: Flow Statistics Monitoring Engine
[ENTROPY]     Phase 2 Entropy Detector: ACTIVE
[ML]          Phase 4 ML Detector: ACTIVE  (trained=True)
[MITIGATION]  Phase 5 Mitigation Engine: ACTIVE
```

### Step 3 — Start Mininet (Terminal 2)

```bash
sudo mn --controller=remote --switch ovs,protocols=OpenFlow13 \
        --topo tree,depth=2,fanout=3
```

### Step 4 — Watch Normal Traffic (Terminal 2 — Mininet CLI)

```bash
# Generate normal traffic
mininet> h1 ping h2 -c 50 -i 0.2 &
mininet> h2 ping h3 -c 50 -i 0.3 &
```

**Expected controller output (Terminal 1):**
```
  ✅ [ML] NORMAL       conf= 77.5%  iso=0.124  hint=NORMAL
```

### Step 5 — Launch a DDoS Attack

```bash
# SYN Flood attack from h1 → h2
mininet> h1 hping3 -S --flood --faster -p 80 10.0.0.2 &
```

**Expected controller output (Terminal 1) within 5–10 seconds:**
```
  🚨 [ML] ATTACK       conf= 85.2%  iso=0.921  hint=SYN_FLOOD

  ────────────────────────────────────────
  🚫 [MITIGATION] BLOCK  |  Status: SUCCESS
  Blocked MAC  : 02:e4:b2:3a:4e:5f
  Attack Hint  : SYN_FLOOD
  Confidence   : 85.2%
  Block Timeout: 60s (auto-expires)
  ────────────────────────────────────────
```

### Step 6 — Stop Attack

```bash
mininet> h1 pkill -f hping3
```

---

## 5. Phase-by-Phase Usage

---

### Phase 1 — Flow Statistics Monitoring

**Module:** `controller/flow_monitor.py`
**Function:** Polls OVS switches every 5 seconds for flow + port statistics

#### What It Does

- Sends `OFPFlowStatsRequest` and `OFPPortStatsRequest` to each connected switch
- Extracts: packet rate, byte rate, flow duration, source/destination MAC, in-port
- Logs all data to `logs/flow_stats.csv` and `logs/port_stats.csv`
- Fires threshold alerts (packet_rate > 500 pkt/s, byte_rate > 500KB/s)

#### How to Start

```bash
# Start controller only (no Mininet)
osken-manager controller/flow_monitor.py

# Then in another terminal, start Mininet
sudo mn --controller=remote --switch ovs,protocols=OpenFlow13 \
        --topo tree,depth=2,fanout=3
```

#### Key Configuration (flow_monitor.py)

```python
MONITOR_INTERVAL = 5       # Poll every N seconds (increase to reduce CPU)
PKT_RATE_WARN_THRESHOLD = 500     # pkt/s before Phase 1 alert fires
BYTE_RATE_WARN_THRESHOLD = 500000 # B/s before alert fires
```

#### Sample Output

```
==========================================================
  [FLOW STATISTICS]  Switch DPID: 1  |  2026-06-07 03:00:00
  Active flows: 4
==========================================================
  Switch ID      : 1
  Source MAC     : 02:e4:b2:3a:4e:5f
  Destination MAC: 0e:21:ec:a5:c8:06
  In Port        : 1
  Priority       : 1
  Packets        : 1024
  Bytes          : 55296
  Packet Rate    : 24.5 pkt/s
  Byte Rate      : 1323.4 B/s
  Duration       : 41.8 sec
```

#### CSV Output

```
logs/flow_stats.csv
timestamp, switch_id, src_mac, dst_mac, in_port, priority,
packet_count, byte_count, packet_rate, byte_rate, duration_sec
```

---

### Phase 2 — Entropy Detection Engine

**Module:** `entropy_engine/`
**Function:** 5-dimensional Shannon entropy analysis on each monitoring cycle

#### How It Works

Every 5-second poll, Phase 2 computes entropy across 5 dimensions:

| Dimension | Normal Value | Attack Value |
|-----------|-------------|-------------|
| `src_entropy` | 0.7–1.0 | 0.0–0.2 |
| `dst_entropy` | 0.7–1.0 | 0.0–0.2 |
| `packet_entropy` | 0.6–1.0 | 0.0–0.15 |
| `byte_entropy` | 0.6–1.0 | 0.0–0.15 |
| `flow_entropy` | 0.6–1.0 | 0.0–0.2 |
| **`entropy_score`** | **0.55–1.0** | **0.0–0.15** |

**Formula:**
```
H(X) = -Σ p(x) * log₂(p(x))    [Shannon entropy]
entropy_score = 0.30*src + 0.30*dst + 0.15*pkt + 0.15*byte + 0.10*flow
```

#### Sample Alert

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ⚠️   ENTROPY ALERT DETECTED
  Alert Type    : SRC_MAC_ENTROPY_COLLAPSE
  Current Value : 0.0400
  Threshold     : 0.3000
  Confidence    : 86.7%
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

#### CSV Output

```
logs/entropy_logs.csv
timestamp, switch_id, src_entropy, dst_entropy, packet_entropy,
byte_entropy, flow_entropy, entropy_score, n_flows, alert_fired
```

---

### Phase 3 — Traffic Generation & Attack Simulation

**Module:** `traffic_generator/`
**Function:** Reproducible Mininet-based traffic and attack scenarios for research evaluation

#### Automated Scenario Execution

```bash
# Requires controller running in Terminal 1
# In Terminal 2:
cd ~/intellishield-sdn

# Run Scenario 2: SYN Flood (most useful for demos)
sudo python3 -m traffic_generator.traffic_scheduler --scenario 2

# Run all 5 scenarios back-to-back
sudo python3 -m traffic_generator.traffic_scheduler --all
```

#### 5 Available Scenarios

| ID | Scenario | Duration | Purpose |
|----|---------|---------|---------|
| `1` | Normal traffic baseline | 60s | Capture normal entropy baseline |
| `2` | SYN flood attack | 60s | Primary DDoS detection demo |
| `3` | UDP flood attack | 60s | Bandwidth-based detection demo |
| `4` | Burst attack (8s) | 38s | Sensitivity test — narrow window |
| `5` | Mixed SYN + UDP | 75s | Sequential attack evaluation |

#### Timeline for Scenario 2 (SYN Flood)

```
0s   → Normal ICMP traffic starts (baseline)
20s  → SYN flood launches: h1 → h2 @ ~100,000 pkt/s
50s  → SYN flood stops
60s  → Recovery monitoring ends
```

#### Manual Attack Commands (inside Mininet CLI)

```bash
# SYN Flood
mininet> h1 hping3 -S --flood --faster --rand-source -p 80 10.0.0.2 &

# UDP Flood
mininet> h1 hping3 --udp --flood -p 53 --data 1400 10.0.0.2 &

# ICMP Flood
mininet> h1 hping3 --icmp --flood --faster 10.0.0.2 &

# Stop all attacks
mininet> h1 pkill -f hping3

# Normal TCP traffic
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.0.2 -t 30 &

# Normal UDP traffic
mininet> h2 iperf -s -u &
mininet> h1 iperf -c 10.0.0.2 -u -b 1M -t 30 &
```

---

### Phase 4 — ML Anomaly Detection

**Module:** `ml_models/`
**Function:** Dual-model ML classification of each monitoring cycle

#### Models

| Model | Type | Training | Use |
|-------|------|---------|-----|
| **Isolation Forest** | Unsupervised | Normal traffic only | Novel/zero-day detection |
| **Decision Tree** | Supervised | Labelled normal + attack | Known attack classification |

**Ensemble:** `score = 0.4 × IF_score + 0.6 × DT_probability`

#### Feature Vector (15 dimensions)

```
Flow features  (8): packet_rate_mean, packet_rate_max, byte_rate_mean,
                    byte_rate_max, flow_count, duration_mean,
                    unique_src_count, unique_dst_count

Entropy features(6): src_entropy, dst_entropy, packet_entropy,
                     byte_entropy, flow_entropy, entropy_score

Derived        (1): flow_concentration = 1 - src_entropy
```

#### Train Models

```bash
cd ~/intellishield-sdn

# Quick start: synthetic data (no experiments needed)
python3 -m ml_models.model_trainer --synthetic

# Real data: from experiment logs (after running Phase 3 scenarios)
python3 -m ml_models.model_trainer --from-csv

# Custom sample counts
python3 -m ml_models.model_trainer --synthetic --n-normal 500 --n-attack 300
```

#### Status Labels

| Label | Confidence | Action |
|-------|-----------|--------|
| `NORMAL` | — | No action |
| `SUSPICIOUS` | 60–75% | Log alert, no block |
| `ATTACK` | ≥75% | → Phase 5 Mitigation |

#### Sample Prediction Output

```
  ✅ [ML] NORMAL       conf= 77.5%  iso=0.124  hint=NORMAL
  🚨 [ML] ATTACK       conf= 85.2%  iso=0.921  hint=SYN_FLOOD
```

---

### Phase 5 — Automated Mitigation

**Module:** `mitigation/`
**Function:** Installs OpenFlow DROP rules on OVS switches automatically

#### How It Works

When Phase 4 detects `ATTACK` with confidence ≥ 60%:

1. Identifies attacker MAC from highest packet-rate flow (Phase 1 data)
2. Checks blocklist (whitelist + duplicate check)
3. Calculates block duration from confidence:

```
conf ≥ 90%  →  120 second block
conf ≥ 75%  →   60 second block
conf ≥ 60%  →   30 second block
```

4. Installs `OFPFlowMod` DROP rule on the switch:
   - **Priority:** 200 (overrides all normal forwarding rules)
   - **Match:** `eth_src = attacker_mac`
   - **Action:** None (DROP)
   - **hard_timeout:** auto-expires with no cleanup needed

#### Manual Override Commands

```bash
# From Python (in a separate script or interactive shell):
from mitigation.mitigation_engine import MitigationEngine

engine = MitigationEngine()
# engine.set_datapaths(datapaths)   # inject from controller

# Manual unblock
engine.unblock_mac(dpid=1, mac="02:e4:b2:3a:4e:5f", reason="MANUAL")

# Emergency: remove ALL block rules from switch 1
engine.unblock_all_on_switch(dpid=1)

# View current blocks
engine._blocklist.print_status()
```

#### Blocklist Query

```bash
python3 << EOF
import sys; sys.path.insert(0, "/home/akshay/intellishield-sdn")
from mitigation.blocklist_manager import BlocklistManager
b = BlocklistManager()
b.print_status()
stats = b.get_stats()
print(stats)
EOF
```

---

### Phase 6 — Behaviour Analyst (ADWIN + HDBSCAN)

**Module:** `advanced_analytics/`
**Function:** Early-warning drift detection + automatic traffic cluster discovery

#### Component 1 — ADWIN (Early Warning)

ADWIN monitors 4 network metrics in real-time and fires an alert the moment any of them changes significantly. It acts as the **first alarm** — typically 1 full monitoring cycle (5s) before the ML models confirm an attack.

Metrics tracked per switch:
- `packet_rate_mean` — packets per second
- `flow_count` — number of active connections
- `entropy_score` — traffic variety score
- `byte_rate_mean` — data throughput

**ADWIN console output during attack onset:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ⚡ [ADWIN] CONCEPT DRIFT DETECTED
  Metric    : packet_rate_mean
  Switch    : DPID 1
  Old mean  : 272.3   →   New mean : 80496.4  (Δ = 80224.1)
  → Early-warning: network behaviour has shifted!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

#### Component 2 — HDBSCAN (Traffic Clustering)

Every **10 monitoring cycles (~50 seconds)**, HDBSCAN groups all recent feature vectors into clusters and labels them:

| Label | Meaning |
|-------|---------|
| `NORMAL` | Regular, expected traffic |
| `ATTACK` | Confirmed attack pattern |
| `SUSPICIOUS` | Unusual but not confirmed |
| `NOISE` | Unknown / potential new attack type |

**HDBSCAN console output (every 10 cycles):**
```
============================================================
  [HDBSCAN] Clustering Run #3  |  Switch 1
  50 vectors  →  2 clusters found
  Normal: 1   Attack: 1   Suspicious: 0   Noise: 0
────────────────────────────────────────────────────────────
  Cluster   Label       Size    Pkt/s       Entropy
────────────────────────────────────────────────────────────
  0         ✅ NORMAL    35      198.4       0.8430
  1         🚨 ATTACK    15      91240.3     0.0420
============================================================
```

#### New Log Files (Phase 6)

| File | Contents |
|------|----------|
| `logs/drift_alerts.csv` | Timestamp, metric, old mean, new mean, switch |
| `logs/cluster_labels.csv` | Cluster ID, label, entropy, packet rate per vector |
| `logs/cluster_summary.json` | Full HDBSCAN run history |

#### Manually Run Clustering

```bash
cd ~/intellishield-sdn
python3 -m advanced_analytics.adwin_detector    # self-test ADWIN
python3 -m advanced_analytics.hdbscan_clusterer # self-test HDBSCAN
```

#### Tuning ADWIN Sensitivity

The `delta` parameter controls how sensitive ADWIN is:
- `delta=0.002` — high sensitivity (default, good for demos and experiments)
- `delta=0.05` — lower sensitivity (fewer alerts during normal variation)

Edit in `flow_monitor.py` inside the `__init__` block:
```python
self._adwin = ADWINManager(delta=0.002, max_window=150)
```

---

## 6. Running Experiments

### Standard Research Run (All Phases Active)

#### Terminal 1 — Controller

```bash
ssh akshay@192.168.64.5
cd ~/intellishield-sdn
osken-manager controller/flow_monitor.py
```

#### Terminal 2 — Experiment Automation

```bash
ssh akshay@192.168.64.5
cd ~/intellishield-sdn

# Scenario 2: SYN Flood (PRIMARY DEMO)
sudo python3 -m traffic_generator.traffic_scheduler --scenario 2

# Scenario 3: UDP Flood
sudo python3 -m traffic_generator.traffic_scheduler --scenario 3

# Full research run — all 5 scenarios
sudo python3 -m traffic_generator.traffic_scheduler --all
```

### Manual Mininet Run

#### Terminal 2 — Mininet

```bash
sudo mn --controller=remote \
        --switch ovs,protocols=OpenFlow13 \
        --topo tree,depth=2,fanout=3 \
        --mac
```

#### Inside Mininet CLI

```bash
# Verify connectivity
mininet> pingall

# Phase 1 — Trigger telemetry (wait 5s for first poll)
mininet> h1 ping h2 -c 20

# Phase 2 — Trigger entropy analysis
mininet> h1 ping h2 -c 100 -i 0.05 &
mininet> h2 ping h3 -c 100 -i 0.05 &
mininet> h3 ping h1 -c 100 -i 0.05 &

# Phase 3 + 4 + 5 — Launch SYN flood
mininet> h1 hping3 -S --flood --faster -p 80 10.0.0.2 &

# Stop attack
mininet> h1 pkill -f hping3
```

---

## 7. Interpreting Console Output

### Controller Output Key

```
==========================================================
  [FLOW STATISTICS]  Switch DPID: 1  |  2026-06-07 03:00:00
  Active flows: 4                            ← Phase 1
==========================================================
  Packet Rate    : 24.5 pkt/s               ← Phase 1 metric
  Byte Rate      : 1323.4 B/s               ← Phase 1 metric

  ⚠️  [WARNING] HIGH PACKET RATE: 100,745 pkt/s  ← Phase 1 threshold alert
----------------------------------------------------------
  [PORT STATISTICS]  Switch DPID: 1         ← Phase 1 port stats
----------------------------------------------------------

  ⚠️  ENTROPY ALERT: SRC_MAC_ENTROPY_COLLAPSE  ← Phase 2 entropy alert
  entropy_score: 0.04  (threshold: 0.30)

  ✅ [ML] NORMAL   conf=77.5%  iso=0.124   ← Phase 4 ML prediction
  🚨 [ML] ATTACK   conf=85.2%  iso=0.921   ← Phase 4 attack detected

  [ML EXPLANATION]  Status: ATTACK          ← Phase 4 explainer
  ⚠  src_entropy: 0.04  BELOW normal → entropy collapse

  🚫 [MITIGATION] BLOCK  |  Status: SUCCESS  ← Phase 5 mitigation
  Blocked MAC  : 02:e4:b2:3a:4e:5f
  Block Timeout: 60s (auto-expires)
```

### Status Emoji Guide

| Emoji | Meaning |
|-------|---------|
| ✅ | Normal / Success |
| ⚠️ | Threshold warning |
| 🚨 | Attack detected |
| 🚫 | MAC blocked |
| ❓ | Unknown / error |

---

## 8. Log Files Reference

All logs are in `~/intellishield-sdn/logs/`

| File | Phase | Contents |
|------|-------|---------|
| `flow_stats.csv` | 1 | Per-flow telemetry every 5 seconds |
| `port_stats.csv` | 1 | Per-port RX/TX packet and byte counters |
| `entropy_logs.csv` | 2 | 5-dim entropy values per cycle |
| `detection_alerts.csv` | 2 | Entropy collapse events |
| `traffic_logs.csv` | 3 | Normal traffic events |
| `attack_logs.csv` | 3 | Attack launch/stop timestamps |
| `scenario_logs.csv` | 3 | Scenario lifecycle events |
| `ml_features.csv` | 4 | 15-dim feature vectors |
| `ml_predictions.csv` | 4 | Per-cycle ML prediction results |
| `ml_alerts.csv` | 4 | Attack/Suspicious events only |
| `mitigation_actions.csv` | 5 | Block/Unblock actions |
| `mitigation_summary.json` | 5 | Session statistics |
| `entropy_baselines.json` | 2 | Learned normal entropy baselines |
| `models/` | 4 | Saved sklearn model `.pkl` files |

### Useful Analysis Commands

```bash
cd ~/intellishield-sdn/logs

# View last 5 flow stats
tail -5 flow_stats.csv

# View last 5 ML predictions
tail -5 ml_predictions.csv | column -t -s,

# Count total attacks detected
grep "ATTACK" ml_predictions.csv | wc -l

# View all mitigation events
cat mitigation_actions.csv | column -t -s,

# Check current blocklist
cat mitigation_summary.json | python3 -m json.tool

# Plot entropy time series (requires matplotlib)
python3 -c "
import pandas as pd
import matplotlib.pyplot as plt
df = pd.read_csv('entropy_logs.csv')
df['entropy_score'].plot(title='Entropy Score over Time')
plt.axhline(0.3, color='red', linestyle='--', label='threshold')
plt.savefig('entropy_plot.png')
print('Saved entropy_plot.png')
"
```

---

## 9. Manual Mininet Commands

### Topology Options

```bash
# Default: tree topology (recommended for experiments)
sudo mn --controller=remote --switch ovs,protocols=OpenFlow13 \
        --topo tree,depth=2,fanout=3 --mac

# Linear: h1 - s1 - s2 - h2
sudo mn --controller=remote --switch ovs,protocols=OpenFlow13 \
        --topo linear,4 --mac

# Single switch: all hosts on one switch (simplest)
sudo mn --controller=remote --switch ovs,protocols=OpenFlow13 \
        --topo single,5 --mac
```

### Useful Mininet CLI Commands

```bash
mininet> nodes         # List all nodes
mininet> net           # Show topology
mininet> dump          # Show host IP/MAC info
mininet> pingall       # Test all-to-all connectivity
mininet> iperf h1 h2   # Quick iperf test

# Run command on specific host
mininet> h1 ifconfig
mininet> h1 ping h2 -c 5
mininet> h1 hping3 -S -p 80 10.0.0.2 -c 100

# Run in background
mininet> h1 iperf -s &
mininet> h1 hping3 -S --flood 10.0.0.2 &

# Check running processes
mininet> h1 ps aux

# Kill background processes
mininet> h1 pkill -f hping3
mininet> h1 pkill -f iperf
```

### OVS Commands (run as root)

```bash
# Check OpenFlow rules installed on s1
sudo ovs-ofctl dump-flows s1

# Check high-priority DROP rules (Phase 5 mitigation)
sudo ovs-ofctl dump-flows s1 | grep "priority=200"

# Manually clear all flows
sudo ovs-ofctl del-flows s1

# Check OVS controller connection
sudo ovs-vsctl show
```

---

## 10. Troubleshooting

### Controller Not Connecting

```bash
# Check controller is listening on port 6653
netstat -tlnp | grep 6653

# Check OVS is pointing to correct controller
sudo ovs-vsctl show

# Set controller manually on switch
sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6653
```

### No Flow Statistics Appearing

```bash
# Check Mininet switch has OpenFlow 1.3
sudo ovs-vsctl set bridge s1 protocols=OpenFlow13

# Check flows exist on switch
sudo ovs-ofctl dump-flows s1

# Generate traffic to create flows
mininet> h1 ping h2 -c 5
```

### ML Models Not Loading

```bash
cd ~/intellishield-sdn

# Retrain models
python3 -m ml_models.model_trainer --synthetic

# Check models exist
ls logs/models/
```

### hping3 Permission Error

```bash
# hping3 requires root inside Mininet
mininet> h1 sudo hping3 -S --flood 10.0.0.2 &

# Or run as root on host directly
sudo hping3 -S --flood -p 80 10.0.0.2 &
```

### Mitigation Not Blocking

```bash
# Check mitigation is active in controller log
grep "MITIGATION" controller_output.log

# Verify DROP rules on switch
sudo ovs-ofctl dump-flows s1 | grep "priority=200"

# Check blocklist log
cat logs/mitigation_actions.csv

# Manually check if confidence is too low (< 60%)
# Lower threshold in mitigation/mitigation_engine.py:
MIN_CONFIDENCE_TO_BLOCK = 50.0   # was 60.0
```

### Entropy Always Shows NORMAL During Attack

```bash
# The entropy window needs at least 10 flow updates
# Ensure attack runs for > 30 seconds before checking

# Check entropy CSV directly
tail -10 logs/entropy_logs.csv

# Verify entropy thresholds in entropy_engine/entropy_detector.py
grep "ALERT_THRESHOLD" entropy_engine/entropy_detector.py
```

### Cleanup After Experiments

```bash
# Inside Mininet CLI
mininet> exit

# Clean Mininet state
sudo mn -c

# Kill leftover hping3/iperf
sudo pkill -f hping3
sudo pkill -f iperf

# Reset logs (optional — backup first!)
cd ~/intellishield-sdn/logs
cp flow_stats.csv flow_stats_backup_$(date +%Y%m%d).csv
> flow_stats.csv
```

---

## 11. Project Roadmap Status

```
✅ Phase 1 — Flow Statistics Monitoring Engine
   controller/flow_monitor.py
   OpenFlow polling, CSV logging, threshold alerts

✅ Phase 2 — Entropy-Based DDoS Detection Engine
   entropy_engine/
   5-dimensional Shannon entropy, composite score, sliding window

✅ Phase 3 — Traffic Generation & Attack Simulation
   traffic_generator/
   5 scenarios, SYN/UDP/ICMP/burst floods, Mininet automation

✅ Phase 4 — ML Anomaly Detection
   ml_models/
   IsolationForest + DecisionTree, 15-dim features, explainability

✅ Phase 5 — Automated Mitigation Engine
   mitigation/
   OpenFlow DROP rules, confidence-based timeout, whitelist

✅ Phase 6 — Behaviour Analyst (ADWIN + HDBSCAN)
   advanced_analytics/
   Online drift detection, traffic cluster discovery

🔜 Phase 7 — PPO Reinforcement Learning Adaptive Thresholds
   - PPO agent learns optimal detection thresholds
   - Replaces static confidence gates with a learned policy
   - State: feature vector + block history + false-positive rate
   - Reward: true-positive rate - false-positive rate - detection-latency

🔜 Phase 8 — Real-Time Dashboard
   - Live web UI showing all phases simultaneously
   - Entropy time series chart
   - ML confidence gauge
   - Active blocklist table
   - Attack timeline
```

---

## Notes for IEEE Research Report

When writing the experimental methodology section, cite these parameters:

| Parameter | Value | Reference |
|-----------|-------|-----------|
| Poll interval | 5 seconds | `flow_monitor.py:MONITOR_INTERVAL` |
| Entropy window | 10 samples | `entropy_detector.py:WINDOW_SIZE` |
| ML feature dims | 15 | `feature_builder.py:FEATURE_NAMES` |
| Block priority | 200 | `flow_blocker.py:BLOCK_PRIORITY` |
| IF contamination | 10% | `anomaly_detector.py:ISO_CONTAMINATION` |
| Min confidence | 60% | `mitigation_engine.py:MIN_CONFIDENCE_TO_BLOCK` |
| Detection latency | ~5–10s | Driven by MONITOR_INTERVAL |
| Mitigation latency | ~0ms | OpenFlow rule is instant |
| Synthetic training | 300N + 200A | `model_trainer.py:generate_synthetic_data()` |

---

*IntelliShield SDN — Usage Guide v1.0*
*Last updated: 2026-06-16*
