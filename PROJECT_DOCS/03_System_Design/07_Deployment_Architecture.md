# Deployment Architecture

## 1. Physical Deployment Topology

IntelliShield SDN runs on a **macOS development host** with an **Ubuntu 22.04 LTS virtual machine** hosting all SDN runtime components.

```mermaid
flowchart TB
    subgraph Host["macOS Host"]
        DEV["Cursor / Git<br/>ddos_network repo"]
        SSH["ssh / scp<br/>to VM"]
    end

    subgraph VM["Ubuntu 22.04 VM<br/>~/intellishield-sdn/"]
        CTRL["Process: osken-manager<br/>controller/flow_monitor.py"]
        DASH["Process: python3 dashboard/api.py<br/>:8080"]
        MN["Process: traffic_scheduler<br/>(on demand, sudo)"]
        OVS["Service: openvswitch-switch"]
        MNEM["Mininet emulated hosts<br/>h1–h5, s1"]
    end

    DEV -->|sync code| SSH --> VM
    Host -->|http://192.168.x.x:8080| DASH

    CTRL <-->|OpenFlow TCP 6653| OVS
    MNEM --> OVS
    MN --> MNEM
```

---

## 2. Network Ports and Protocols

| Service | Port | Protocol | Bind Address | Notes |
|---------|------|----------|--------------|-------|
| OpenFlow controller | 6653 | TCP | 0.0.0.0 (OsKen default) | OVS connects as client |
| Dashboard API + UI | 8080 | HTTP | 0.0.0.0 | FastAPI uvicorn |
| Mininet data plane | — | Ethernet (virtual) | 10.0.0.0/8 | Emulated L2/L3 |
| SSH | 22 | TCP | VM IP | Remote administration |

---

## 3. Process Architecture on VM

```mermaid
flowchart LR
    subgraph LongRunning["Long-Running Processes"]
        P1["osken-manager<br/>IntelliShieldFlowMonitor"]
        P2["dashboard/api.py<br/>FastAPI + Master Control"]
    end

    subgraph OnDemand["On-Demand Processes"]
        P3["traffic_scheduler<br/>--scenario N"]
        P4["compute_metrics.py"]
        P5["model_trainer"]
    end

    subgraph System["System Services"]
        S1["openvswitch-switch"]
    end

    P3 -->|spawns| MN["Mininet + hosts<br/>hping3, ping, iperf"]
    MN --> S1
    P1 --> S1
    P2 -->|subprocess| P3 & P4 & P5
    P2 -->|restart/stop| P1
```

**Typical demo session:**

1. Terminal A: `osken-manager controller/flow_monitor.py`
2. Terminal B: `python3 dashboard/api.py`
3. Browser: `http://<VM-IP>:8080`
4. Master Control UI or Terminal C: run scenario

---

## 4. Directory Layout on VM

```text
~/intellishield-sdn/
├── controller/
│   └── flow_monitor.py          # OsKen application entry point
├── entropy_engine/
├── ml_models/
├── mitigation/
├── advanced_analytics/
├── rl_engine/
├── traffic_generator/
├── dashboard/
│   ├── api.py                   # HTTP :8080
│   ├── control.py               # Master Control job runner
│   ├── static/index.html
│   └── requirements.txt
├── scripts/
│   └── compute_metrics.py
├── logs/                        # Runtime-generated (not in git)
│   ├── *.csv
│   ├── *.json
│   ├── models/*.pkl
│   ├── ppo_weights.pkl
│   └── archive/<timestamp>/
└── verify_phase7.py
```

---

## 5. Deployment Diagram (C4 Container Level)

```mermaid
C4Deployment
    title IntelliShield SDN Deployment

    Deployment_Node(host, "macOS Host", "Development") {
        Deployment_Node(vm, "Ubuntu 22.04 VM", "UTM / VirtualBox") {
            Container(controller, "OsKen Controller", "Python", "Phases 1–7 integrated")
            Container(dashboard, "Dashboard", "FastAPI", "Phase 8 UI + API")
            Container(mininet, "Traffic Generator", "Mininet", "Phase 3 scenarios")
            ContainerDb(logs, "Log Store", "CSV/JSON files", "logs/")
            Container(ovs, "OVS", "Open vSwitch", "OpenFlow 1.3 datapath")
        }
    }

    Rel(mininet, ovs, "emulated traffic")
    Rel(ovs, controller, "OpenFlow 1.3", "6653")
    Rel(controller, logs, "append")
    Rel(mininet, logs, "scenario events")
    Rel(dashboard, logs, "read / archive")
    Rel(dashboard, controller, "restart/stop")
    Rel(dashboard, mininet, "spawn scenarios")
```

---

## 6. Mininet Topology

```mermaid
flowchart TB
    subgraph MininetTopo["IntelliShieldTopo — 5 hosts, 1 switch"]
        H1["h1<br/>10.0.0.1"]
        H2["h2<br/>10.0.0.2"]
        H3["h3<br/>10.0.0.3"]
        H4["h4<br/>10.0.0.4"]
        H5["h5<br/>10.0.0.5"]
        S1["s1<br/>OVS bridge<br/>DPID 1"]
    end

    CTRL["RemoteController<br/>127.0.0.1:6653"]

    H1 & H2 & H3 & H4 & H5 --- S1
    S1 <-->|OpenFlow| CTRL
```

| Host | Typical Role |
|------|--------------|
| h1 | Attacker (SYN/UDP flood via hping3) |
| h2 | Victim / iperf server |
| h3–h5 | Background normal traffic |

---

## 7. Software Dependencies

| Component | Package / Tool | Install |
|-----------|----------------|---------|
| SDN framework | `python3-os-ken` | `sudo apt install python3-os-ken` |
| Emulation | `mininet` | `sudo apt install mininet` |
| Switch | `openvswitch-switch` | `sudo apt install openvswitch-switch` |
| ML | `scikit-learn`, `numpy` | `pip3 install scikit-learn numpy` |
| Dashboard | `fastapi`, `uvicorn` | `pip3 install -r dashboard/requirements.txt` |
| Attack tools | `hping3`, `iperf` | `sudo apt install hping3 iperf` |

---

## 8. Environment Configuration

| Variable / Setting | Purpose |
|--------------------|---------|
| `INTELLISHIELD_SUDO_PASS` | Dashboard Master Control sudo password for scenarios |
| `/etc/sudoers.d/intellishield` | Passwordless `traffic_scheduler` for dashboard |
| `timedatectl set-timezone Asia/Kolkata` | VM local time for log timestamps |
| `sys.path` insert in `flow_monitor.py` | Import sibling packages from project root |

**Sudoers entry (recommended for UI scenarios):**

```bash
echo 'akshay ALL=(ALL) NOPASSWD: /usr/bin/python3 -m traffic_generator.traffic_scheduler *' \
  | sudo tee /etc/sudoers.d/intellishield
sudo chmod 440 /etc/sudoers.d/intellishield
```

---

## 9. Startup Commands Reference

```bash
# Terminal 1 — Controller
cd ~/intellishield-sdn
osken-manager controller/flow_monitor.py

# Terminal 2 — Dashboard
cd ~/intellishield-sdn
pip3 install -r dashboard/requirements.txt   # first time only
python3 dashboard/api.py

# Terminal 3 — Scenario (manual)
cd ~/intellishield-sdn
sudo python3 -m traffic_generator.traffic_scheduler --scenario 2

# Metrics (manual or via UI)
python3 scripts/compute_metrics.py --json-out logs/metrics_report.json
```

---

## 10. Sync from Development Host

```mermaid
flowchart LR
    MAC["macOS<br/>ddos_network/"]
    SCP["scp / rsync / git pull"]
    VM["VM<br/>~/intellishield-sdn/"]
    RESTART["Restart controller<br/>+ dashboard"]

    MAC --> SCP --> VM --> RESTART
```

After code sync, restart the controller to load Python changes. Dashboard auto-reloads only if started with `--reload` (not default).

---

## 11. Scaling and Production Notes

This deployment is **research/lab-oriented**, not production-hardened:

| Aspect | Current Design | Production Consideration |
|--------|----------------|-------------------------|
| High availability | Single controller process | Controller clustering (e.g., ONOS, Ryu HA) |
| Log storage | Local CSV files | Time-series DB (InfluxDB, Elasticsearch) |
| Security | HTTP dashboard on :8080 | TLS, authentication, network ACLs |
| Topology | Single-switch Mininet | Multi-switch physical/fabric deployment |
| RL training | Online during monitoring | Offline training pipeline |

For IEEE experiments and viva demonstration, the single-VM Mininet deployment is the intended and validated configuration.
