# Executive Summary

## Project Title

**IntelliShield SDN: Self-Evolving Hybrid Framework for DDoS Detection and Mitigation in Software Defined Networks**

## Summary

`IntelliShield SDN` is an SDN-based cybersecurity research prototype that detects, explains, and mitigates distributed denial-of-service (DDoS) attacks in near real time. The system is built around an OpenFlow 1.3 network managed by an OsKen controller and evaluated inside a Mininet-based laboratory environment.

The repository implements a layered defense pipeline. First, the controller continuously polls switch flow and port statistics. Next, an entropy engine analyzes traffic concentration and diversity using Shannon entropy across multiple dimensions. These measurements are combined with flow-derived features and passed to a hybrid machine learning layer that uses an Isolation Forest and a Decision Tree to classify traffic as `NORMAL`, `SUSPICIOUS`, or `ATTACK`. When an attack is confirmed, an automated mitigation engine installs OpenFlow drop rules that surgically block only the attacker-to-victim flow pair instead of broadly blocking the entire network segment.

Beyond static detection, the project also includes advanced analytics and adaptation features. ADWIN-based drift detection provides early warning when traffic distributions shift, while HDBSCAN clustering helps profile normal, attack, and anomalous traffic groups. A reinforcement learning module tunes thresholds over time to reduce false positives and improve resilience under changing traffic conditions. Finally, a live dashboard exposes real-time monitoring, experiment metrics, and a master control panel for running scenarios, computing metrics, and retraining models from the browser.

In its current implemented form, the repository covers the full project lifecycle: monitoring, detection, simulation, mitigation, adaptive tuning, analytics, and operator visibility. Release 1.0 adds a **collaborative evidence pipeline** (shared contracts, correlation, fusion, verification, RCA/XAI, policy alerts) and a **read-only snapshot digital twin** — see `PROJECT_DOCS/02_Novelties/`. Recent validation shows a clean normal baseline in Scenario 1, reliable detection and mitigation in Scenario 2, surgical `FLOW_PAIR` blocking of the attacking host, and machine-generated experiment metrics suitable for demos, reports, and IEEE-style evaluation.
