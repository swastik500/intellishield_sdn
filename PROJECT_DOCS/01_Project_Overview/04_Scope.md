# Scope

## In Scope

This project focuses on the design, implementation, and validation of a laboratory-scale SDN security framework for DDoS detection and mitigation.

### Network Environment

- OpenFlow 1.3 SDN topology running in Mininet
- Open vSwitch data plane
- OsKen controller-based control plane
- Linux VM deployment and browser-accessible dashboard

### Functional Scope

- Periodic collection of flow and port statistics
- Entropy-based anomaly detection across multiple traffic dimensions
- Traffic simulation for benign and malicious scenarios
- Hybrid ML-based classification with explainability
- Automatic mitigation through OpenFlow drop rules
- Drift detection and traffic clustering
- Reinforcement-learning-based threshold adaptation
- Live dashboard and experiment orchestration
- Metrics generation for controlled experiment evaluation

### Attack Scope

The repository is structured around the attack scenarios currently implemented in `traffic_generator/attack_scenarios.py`:

- Normal baseline traffic
- SYN flood
- UDP flood
- Burst flood
- Mixed sequential SYN + UDP attack

### Evaluation Scope

- Controlled repeatable experiments
- Validation of detection latency
- Validation of mitigation behavior
- Verification that legitimate traffic is preserved
- Demonstration-ready logs, summaries, and visual outputs

## Out of Scope

The following areas are outside the intended scope of the current repository:

- Production deployment in a large enterprise or ISP network
- Multi-switch WAN-scale orchestration
- Hardware traffic generators or physical switch benchmarking
- Full zero-trust policy management
- Authentication, authorization, and hardened multi-user security for the dashboard
- Public internet exposure of the control UI
- End-to-end encrypted telemetry pipelines
- Comprehensive support for all DDoS families beyond the implemented scenarios

## Practical Scope Boundary

This project should be understood as a **research prototype and academic demonstration system**, not a finished commercial security product. Its value lies in proving an integrated architecture that combines monitoring, entropy analysis, machine learning, adaptive control, mitigation, and visualization in one coherent SDN defense workflow.
