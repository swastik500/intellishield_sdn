# Presentation Outline

**Title:** IntelliShield SDN — Self-Evolving Hybrid Framework for DDoS Detection and Mitigation in Software Defined Networks

**Duration:** 15–20 minutes (+ 8–10 min live demo + Q&A)

**Audience:** Examiners, IEEE reviewers, faculty panel

---

## Slide Structure

### Section 1 — Introduction (2 slides, ~2 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 1 | Title slide | Project name, your name, institution, date |
| 2 | Problem statement | DDoS threatens availability; traditional IDS lacks SDN programmability; static thresholds fail under changing traffic |

**One-liner:** *"We built a closed-loop SDN security system that detects, explains, and mitigates DDoS attacks automatically."*

---

### Section 2 — Objectives & Scope (2 slides, ~2 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 3 | Objectives | Real-time detection; hybrid ML + entropy; surgical mitigation; adaptive RL tuning; reproducible evaluation |
| 4 | Scope | In: Mininet lab, OpenFlow 1.3, SYN/UDP/burst attacks. Out: production ISP deployment, hardware switches |

---

### Section 3 — Literature Gap & Novelty (2 slides, ~2 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 5 | Related work gap | Many systems detect only; few close the loop; few combine entropy + ML + RL in SDN |
| 6 | Our novelty | Hybrid pipeline, FLOW_PAIR mitigation, PPO adaptation, dashboard + reproducible scenarios |

---

### Section 4 — Architecture (3 slides, ~3 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 7 | High-level architecture | Data plane (Mininet/OVS) → Control plane (OsKen) → Detection apps → Dashboard |
| 8 | Eight-phase map | P1 monitor → P2 entropy → P3 traffic → P4 ML → P5 mitigate → P6 analytics → P7 RL → P8 dashboard |
| 9 | Closed-loop diagram | Monitor → Detect → Decide → Mitigate → Evaluate → Adapt (RL feedback) |

**Diagram:** Use mermaid from `05_Architecture_Explanation.md`.

---

### Section 5 — Technology & AI (3 slides, ~3 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 10 | Technology stack | Python, OsKen, Mininet, OVS, FastAPI, scikit-learn, NumPy PPO |
| 11 | Detection layers | Entropy (fast) + ADWIN (drift) + ML ensemble (IF + DT) + HDBSCAN (profiling) |
| 12 | Reinforcement learning | PPO tunes pkt/byte/confidence thresholds online; reward = TP − FP − FN |

---

### Section 6 — Implementation Highlights (2 slides, ~2 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 13 | Central controller hub | Single `flow_monitor.py` integrates all phases every 5 s |
| 14 | Mitigation policy | Confidence gate + attack streak confirmation + FLOW_PAIR surgical block + auto-expiry |

---

### Section 7 — Experiments & Results (3 slides, ~3 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 15 | Experiment setup | Ubuntu VM, 5 hosts, 1 switch, scenarios S1–S5 |
| 16 | Results table | S1 NORMAL/no blocks; S2 SYN → ALERT → ATTACK → BLOCK; latencies 5–20 s |
| 17 | Metrics | `compute_metrics.py` — detection latency, mitigation latency, false positives |

**Table to show:**

| Scenario | Entropy | ML | Mitigation |
|----------|---------|-----|------------|
| S1 Normal | NORMAL | NORMAL | None |
| S2 SYN flood | ALERT | ATTACK | FLOW_PAIR block |

---

### Section 8 — Demo Preview (1 slide, ~1 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 18 | Live demo plan | Dashboard → Archive → S2 SYN flood → show entropy collapse + block + metrics |

---

### Section 9 — Limitations & Future Work (2 slides, ~2 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 19 | Limitations | 5 s poll floor; lab emulation only; synthetic ML bootstrap; no dashboard auth |
| 20 | Future work | More attack types; multi-switch; pytest CI; comparison baselines |

---

### Section 10 — Conclusion (1 slide, ~1 min)

| Slide | Title | Key points |
|-------|-------|------------|
| 21 | Conclusion | End-to-end SDN DDoS framework implemented and validated; reproducible; demo-ready |

**Closing line:** *"IntelliShield demonstrates that entropy, hybrid ML, adaptive RL, and surgical OpenFlow mitigation can work together as a single self-evolving SDN security pipeline."*

---

## Timing Summary

| Section | Slides | Minutes |
|---------|--------|---------|
| Introduction | 1–2 | 2 |
| Objectives & scope | 3–4 | 2 |
| Novelty | 5–6 | 2 |
| Architecture | 7–9 | 3 |
| Technology & AI | 10–12 | 3 |
| Implementation | 13–14 | 2 |
| Results | 15–17 | 3 |
| Demo preview | 18 | 1 |
| Limitations & future | 19–20 | 2 |
| Conclusion | 21 | 1 |
| **Total** | **21** | **~18 min** |

---

## Optional Backup Slides

| Slide | Title | When to use |
|-------|-------|-------------|
| B1 | Entropy math | If examiner asks how Shannon entropy works |
| B2 | 15-dim feature vector | If examiner asks about ML input |
| B3 | OpenFlow DROP rule | If examiner asks about mitigation mechanism |
| B4 | PPO state/action | If examiner asks about RL details |
| B5 | Full API list | If examiner asks about dashboard |
| B6 | Test results | If examiner asks about validation |

---

## Presentation Modes

| Mode | Slides | Demo |
|------|--------|------|
| **Full viva** | 1–21 | Yes (8–10 min) |
| **Short pitch** | 1–2, 7, 10, 16, 21 | Optional 3 min |
| **Demo-only** | 18 + live | Full demo script |
| **IEEE poster** | 7, 9, 11, 16 + QR to dashboard | Loop S2 on VM |
