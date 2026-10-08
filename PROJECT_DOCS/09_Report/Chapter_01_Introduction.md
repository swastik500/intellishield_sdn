# Chapter 1 — Introduction

## 1.1 Background

Modern organisations depend on continuous network availability. Distributed Denial-of-Service (DDoS) attacks overwhelm targets by flooding links, exhausting switch flow tables, or saturating host resources. Traditional networks distribute control across many devices, making coordinated detection and response slow and inconsistent.

Software Defined Networking (SDN) separates the **control plane** from the **data plane**. A central controller maintains a global view of the network and can install forwarding or blocking rules programmatically via southbound APIs such as OpenFlow. This programmability makes SDN a natural platform for automated DDoS defence — provided detection is accurate, mitigation is surgical, and the system adapts to changing traffic.

## 1.2 Problem Statement

Despite SDN's advantages, many deployments and research prototypes suffer from:

1. **Static thresholds** that do not adapt to evolving baselines.
2. **Single-technique detection** (signature-only or ML-only) with limited robustness.
3. **Detection without mitigation** — alerts without automated response.
4. **Broad blocking** that disrupts legitimate traffic.
5. **Poor operator visibility** and non-reproducible evaluation.

The core problem addressed by this project is:

> How can an SDN environment automatically detect, explain, and mitigate DDoS attacks in near real time while minimising false positives, preserving legitimate traffic, and adapting to evolving network behaviour?

## 1.3 Proposed Solution — IntelliShield SDN

**IntelliShield SDN** is a research prototype that answers this problem through an eight-phase integrated pipeline:

| Phase | Component |
|-------|-----------|
| 1 | OpenFlow flow and port statistics monitoring |
| 2 | Multi-dimensional Shannon entropy detection |
| 3 | Reproducible Mininet traffic and attack scenarios |
| 4 | Hybrid ML ensemble (Isolation Forest + Decision Tree) |
| 5 | Automated surgical OpenFlow mitigation |
| 6 | ADWIN drift detection and HDBSCAN clustering |
| 7 | PPO reinforcement learning for threshold adaptation |
| 8 | Live dashboard with Master Control |

All detection and mitigation intelligence converges in a single OsKen controller application. Results are persisted to structured logs and exposed through a browser-based dashboard.

Release 1.0 additionally implements **collaborative evidence planes** (shared contracts, P0 hardening, R4 correlation, R6 fusion, R7 verification, R5 RCA/XAI, R8 alerting, ops profile) and a **read-only snapshot digital twin**. See [`PROJECT_DOCS/02_Novelties/`](../02_Novelties/README.md).

## 1.4 Objectives

### Primary Objective

To design and implement a complete SDN-based framework that detects and mitigates DDoS attacks automatically, accurately, and quickly in a controlled laboratory network.

### Specific Objectives

1. Build real-time SDN traffic monitoring with reusable flow features.
2. Detect entropy collapse across five traffic dimensions.
3. Create reproducible DDoS evaluation scenarios (S1–S5).
4. Implement hybrid ML classification with explainable outputs.
5. Automate surgical OpenFlow mitigation with confidence gates.
6. Add ADWIN drift detection, HDBSCAN profiling, and PPO threshold tuning.
7. Provide operational visibility and browser-based experiment control.
8. Generate report-ready experimental metrics (latency, false positives).

## 1.5 Scope

**In scope:** OpenFlow 1.3 Mininet lab (five hosts, one switch); SYN/UDP/burst/mixed attacks; entropy + ML + RL; CSV-based logging; Ubuntu VM deployment.

**Out of scope:** Production ISP deployment; multi-switch WAN; hardware benchmarking; dashboard authentication/TLS; comprehensive coverage of all DDoS families.

This project is a **research prototype and academic demonstration system**, not a commercial security product.

## 1.6 Organisation of the Report

| Chapter | Content |
|---------|---------|
| 2 | Literature review and theoretical background |
| 3 | System analysis — requirements and feasibility |
| 4 | System design — architecture, modules, data model |
| 5 | Implementation — technology and phase-wise build |
| 6 | Testing, results, and discussion |
| 7 | Conclusion and future work |

Supporting diagrams and module-level detail appear in `PROJECT_DOCS/03_System_Design/`, `PROJECT_DOCS/04_Implementation/`, and novelty write-ups in `PROJECT_DOCS/02_Novelties/`.

## 1.7 Summary

IntelliShield SDN combines SDN programmability with entropy heuristics, hybrid machine learning, drift analytics, reinforcement learning, and surgical mitigation in one closed-loop framework validated through reproducible Mininet experiments and automated metrics reporting.
