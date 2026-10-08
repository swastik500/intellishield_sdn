# Technical Questions

Each entry: **Question** → **Expected Answer**

---

## SDN & OpenFlow

### Q1. What is Software Defined Networking?

**Expected Answer:** SDN separates the network control plane from the data plane. The controller has a global view of the network and programs switches via a southbound API. In our project we use OpenFlow 1.3 between OsKen and Open vSwitch, which allows us to read flow statistics and install DROP rules for DDoS mitigation programmatically.

---

### Q2. Why did you choose OpenFlow 1.3?

**Expected Answer:** OpenFlow 1.3 is widely supported by Open vSwitch and OsKen. It provides standard FlowStats, PortStats, PacketIn, and FlowMod messages that we need for telemetry and mitigation. Mininet connects to our remote controller using OpenFlow 1.3 (`protocols=OpenFlow13`).

---

### Q3. What OpenFlow messages does your controller use?

**Expected Answer:**

| Message | Purpose |
|---------|---------|
| `OFPPacketIn` | L2 MAC learning and forwarding |
| `OFPFlowStatsRequest/Reply` | Per-flow packet/byte rates (Phase 1) |
| `OFPPortStatsRequest/Reply` | Port counters |
| `OFPFlowMod` | Install forwarding rules and DROP mitigation (priority 200) |
| `OFPFlowRemoved` | Detect block expiry via hard_timeout |

---

### Q4. What is OsKen and how is it different from a traditional router?

**Expected Answer:** OsKen is an open-source SDN controller framework (Python). Unlike a traditional router that makes local forwarding decisions, OsKen centralises control — our `IntelliShieldFlowMonitor` application runs inside OsKen and decides forwarding and security policy for all connected switches.

---

### Q5. Why Mininet instead of a physical network?

**Expected Answer:** Mininet provides a reproducible, low-cost lab environment on a single Ubuntu VM. We can run identical attack scenarios (S1–S5) with ground-truth logging. It is appropriate for MCA/IEEE prototype validation. We acknowledge it does not represent production line-rate hardware.

---

## Controller & Phase 1

### Q6. What does `flow_monitor.py` do?

**Expected Answer:** It is the central OsKen application (Phase 1). It acts as an L2 learning switch, polls flow and port statistics every 5 seconds, extracts per-flow features, and orchestrates hooks for entropy (Phase 2), ML (Phase 4), mitigation (Phase 5), ADWIN/HDBSCAN (Phase 6), and PPO (Phase 7). All intelligence converges in this single file.

---

### Q7. What is the monitoring interval and why 5 seconds?

**Expected Answer:** `MONITOR_INTERVAL = 5` seconds. This is the trade-off between detection responsiveness and controller/OVS load. Detection latency is typically 5–20 seconds in steady state, bounded by this poll period plus warm-up and attack-confirmation gates. It can be reduced for faster detection at higher CPU cost.

---

### Q8. What is a flow feature dictionary?

**Expected Answer:** Phase 1 extracts eleven fields per OpenFlow flow: timestamp, switch_id, src_mac, dst_mac, in_port, priority, packet_count, byte_count, packet_rate, byte_rate, duration_sec. This dict is the canonical input for entropy, ML feature building, and mitigation attacker identification.

---

### Q9. Why was ARP handling fixed in the controller?

**Expected Answer:** An early bug dropped all broadcast frames including ARP (`ff:ff:ff:ff:ff:ff`), causing "Destination Host Unreachable" on ping. The fix separates concerns: only LLDP (`0x88CC`) is dropped in the forwarding path; broadcast MACs are filtered from stats reporting only via `IGNORED_STATS_MACS`, not from forwarding.

---

## Traffic & Scenarios

### Q10. How do you simulate attacks?

**Expected Answer:** Phase 3 `traffic_generator` uses Mininet with `hping3` for SYN/UDP/ICMP floods and `ping`/`iperf` for normal traffic. Five scenarios (S1–S5) are predefined in `attack_scenarios.py`. Each logs lifecycle events to `scenario_logs.csv` including ATTACK_START and ATTACK_STOP for metrics ground truth.

---

### Q11. What safety measures exist in the traffic generator?

**Expected Answer:** `ALLOWED_SUBNETS` in `attack_generator.py` restricts targets to lab subnets (10.0.0.x, etc.). External IPs are rejected with `[SAFETY] BLOCKED`. Attack processes are tracked by PID and killed on scenario end.

---

## Mitigation

### Q12. How does mitigation work technically?

**Expected Answer:** `MitigationEngine` receives ML or entropy-confirmed alerts, identifies the top packet-rate source MAC, checks whitelist and confidence gate, then calls `flow_blocker` to install an OpenFlow FlowMod with empty instructions (DROP), priority 200, and hard_timeout 30–120 seconds. FLOW_PAIR blocks only src+dst MAC; SRC_MAC blocks all traffic from the attacker.

---

### Q13. What is FLOW_PAIR mitigation?

**Expected Answer:** Instead of blocking an entire host MAC globally, we match both `eth_src` and `eth_dst` so only the attacker-to-victim flow is dropped. Legitimate traffic between other host pairs continues — reducing collateral damage during experiments.

---

## Metrics & Evaluation

### Q14. How do you measure detection latency?

**Expected Answer:** `scripts/compute_metrics.py` parses `scenario_logs.csv` for attack windows (ATTACK_START to ATTACK_STOP), then finds the first entropy ALERT/WARNING or ML ATTACK within that window plus 60-second grace. Latency = first detection timestamp minus attack start.

---

### Q15. How many phases are implemented?

**Expected Answer:** All eight phases: (1) flow monitoring, (2) entropy, (3) traffic generation, (4) ML, (5) mitigation, (6) ADWIN+HDBSCAN, (7) PPO RL, (8) dashboard. Phases 1–7 run in the controller; Phase 8 is a separate FastAPI process reading logs.

---

## Limitations (technical)

### Q16. What are the main technical limitations?

**Expected Answer:**

- 5-second poll floor on detection speed
- Single-switch Mininet topology
- MAC-layer blocking only (not IP spoofing at scale)
- ML bootstrapped on synthetic data (retrainable from logs)
- Dashboard has no authentication

---

### Q17. What happens if the controller crashes?

**Expected Answer:** OpenFlow mitigation rules expire via hard_timeout automatically. Logs on disk survive. Dashboard Master Control can restart the controller. In-memory state (blocklist, entropy window, PPO buffer) is lost but rebuilds from new traffic.

---

### Q18. Can this run on macOS directly?

**Expected Answer:** Development/editing yes; full runtime no — OsKen, Mininet, and the integrated stack are validated on Ubuntu 22.04 VM. macOS may lack numpy for `verify_phase7.py` without pip install.
