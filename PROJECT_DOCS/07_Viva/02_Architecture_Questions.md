# Architecture Questions

Each entry: **Question** → **Expected Answer**

---

## High-Level Design

### Q1. Describe the overall architecture of IntelliShield.

**Expected Answer:** Three layers: (1) Data plane — Mininet hosts and Open vSwitch with OpenFlow 1.3; (2) Control/application — OsKen controller running `flow_monitor.py` with integrated detection, mitigation, analytics, and RL hooks every 5 seconds; (3) Presentation — FastAPI dashboard on port 8080 reading CSV logs and offering Master Control for experiments. Persistence is file-based under `logs/`.

---

### Q2. Why a monolithic controller instead of microservices?

**Expected Answer:** For a research prototype, a single controller hub minimises integration complexity. All phases share one feature batch per poll cycle with no inter-service latency. Optional phases degrade gracefully via try/except imports. Microservices would add deployment overhead without benefit at lab scale.

---

### Q3. What architectural pattern does the project follow?

**Expected Answer:** Layered, event-driven, hook-based architecture. OsKen handles OpenFlow events; a background thread polls statistics; phase modules attach as optional hooks. Logs are the system of record (log-centric persistence).

---

## Integration

### Q4. How are the eight phases connected?

**Expected Answer:** Phase 1 extracts flow features → Phase 2 entropy analysis → Phase 4 builds 15-dim vector and ML predict → Phase 5 mitigates on confirmed ATTACK → Phase 6 ADWIN updates on metrics and HDBSCAN buffers vectors → Phase 7 PPO steps on ML+entropy feedback and adjusts thresholds wired to mitigation. Phase 3 generates traffic independently. Phase 8 reads all logs.

---

### Q5. What is the warm-up period?

**Expected Answer:** First ~3 monitoring cycles after controller start skip ML, mitigation, HDBSCAN, and PPO so the entropy sliding window can fill. ADWIN and flow stats logging still run during warm-up. This prevents false ML alerts on incomplete windows.

---

### Q6. What is the attack confirmation streak?

**Expected Answer:** ML must report ATTACK or SUSPICIOUS for 2 consecutive 5-second cycles before mitigation fires. This reduces single-spike false positives. Entropy has a separate `_entropy_attack_streak` for dual-trigger path.

---

## Data Flow

### Q7. Explain the data flow from switch to dashboard.

**Expected Answer:** OVS → OpenFlow stats reply → controller extracts features → phases append to CSV → dashboard `read_csv_tail()` polls last N rows every 5 seconds → JSON API → browser charts. Dashboard does not query the controller directly for telemetry.

---

### Q8. Why use CSV files instead of a message queue?

**Expected Answer:** Simplicity, auditability, and IEEE reproducibility. Researchers can open logs in Excel/pandas, archive per experiment, and share artifacts. No Kafka/Redis infrastructure needed for a single-VM lab prototype.

---

## Design Decisions

### Q9. Why defence in depth for detection?

**Expected Answer:** No single detector is sufficient. Entropy is fast and interpretable; ADWIN catches distribution shifts; ML classifies attack types; HDBSCAN profiles traffic groups. Layers complement each other — entropy can catch floods when ML is uncertain, and ML adds context when entropy alone is ambiguous.

---

### Q10. How does RL fit architecturally?

**Expected Answer:** RL does not replace detectors. PPO tunes operational gates — packet threshold, byte threshold, ML confidence for blocking — based on reward from recent TP/FP/FN outcomes. `MitigationEngine.set_threshold_adapter()` wires RL conf_threshold to the block decision.

---

### Q11. What is graceful degradation?

**Expected Answer:** Each phase imports with try/except. If sklearn is missing, ML disables but monitoring continues. If rl_engine fails, static thresholds apply. The controller remains a functional L2 switch and stats monitor.

---

## Scalability & Production

### Q12. How would architecture change for production?

**Expected Answer:** Multi-switch topology, distributed controller HA, time-series database, authenticated dashboard, event-driven PacketIn sampling for sub-second detection, and containerised analytics services. Current design optimises for reproducible lab evaluation, not ISP scale.

---

### Q13. Single point of failure?

**Expected Answer:** Yes — one controller process. Acceptable for research prototype. Production would need controller clustering (e.g., ONOS/Ryu HA) — documented as future scope, not implemented.

---

## Diagrams (be ready to draw)

### Q14. Draw the closed-loop architecture.

**Expected Answer:** (Draw on board)

```
Traffic → OVS → Controller (poll 5s)
    → Entropy + ML + ADWIN
    → Mitigation (OpenFlow DROP)
    → CSV logs
    → Metrics script
    → PPO adapts thresholds → back to gates
Dashboard reads logs in parallel
```

---

### Q15. What is the role of Phase 3 in architecture?

**Expected Answer:** Phase 3 is the experiment driver — it creates Mininet topology, generates reproducible normal/attack traffic, and writes ground-truth timestamps. It is not in the hot detection path but enables validated evaluation of phases 1–2 and 4–7.

---

## Trade-offs

### Q16. Main architectural trade-offs?

**Expected Answer:**

| Choice | Benefit | Cost |
|--------|---------|------|
| 5 s polling | Low load | Detection latency floor |
| Monolithic controller | Simple integration | No horizontal scale |
| CSV persistence | Portable, auditable | No concurrent write safety |
| FILE_PAIR mitigation | Low collateral | MAC-layer only |
| Online PPO | Adaptive | Training stability risk |

---

### Q17. Why is the dashboard a separate process?

**Expected Answer:** Decoupling — dashboard crash does not affect detection/mitigation. OsKen event loop stays unblocked. Dashboard is read-mostly on logs plus optional subprocess for experiments. Phase 8 depends on phases 1–7 outputs, not vice versa.
