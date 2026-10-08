# Objectives

## Primary Objective

To design and implement a complete SDN-based framework that can detect and mitigate DDoS attacks automatically, accurately, and quickly in a controlled laboratory network.

## Specific Objectives

### 1. Build a real-time SDN traffic monitoring layer

- Collect per-flow and per-port statistics from OpenFlow switches at fixed intervals.
- Transform raw switch counters into reusable traffic features such as packet rate, byte rate, and flow duration.

### 2. Detect abnormal concentration patterns using entropy

- Apply Shannon entropy across multiple traffic dimensions.
- Generate `NORMAL`, `WARNING`, and `ALERT` states based on entropy collapse and composite scores.
- Provide an early-warning signal before full attack confirmation.

### 3. Create reproducible DDoS evaluation scenarios

- Simulate controlled baseline and attack traffic in Mininet.
- Support multiple attack types such as SYN flood, UDP flood, burst attacks, and mixed attacks.
- Produce repeatable experiment logs for training and evaluation.

### 4. Implement hybrid machine learning for traffic classification

- Construct a 15-dimensional feature vector from flow and entropy signals.
- Combine unsupervised and supervised ML models to classify traffic.
- Produce explainable outputs including attack hints and confidence scores.

### 5. Automate attack mitigation inside the SDN controller

- Convert confirmed attack decisions into OpenFlow blocking rules.
- Prefer surgical mitigation that targets the attacker-victim pair rather than broad blocking.
- Support confidence-based timeouts and automatic unblock behavior.

### 6. Add adaptive and analytical intelligence

- Detect concept drift in live traffic using ADWIN.
- Cluster traffic behavior using HDBSCAN for profiling and anomaly grouping.
- Tune thresholds dynamically using reinforcement learning.

### 7. Provide operational visibility and experiment control

- Expose live telemetry, alerts, blocks, and metrics through a dashboard.
- Provide a browser-based control panel to run scenarios, restart the controller, compute metrics, and retrain models.

### 8. Generate report-ready experimental evidence

- Measure entropy latency, ML latency, mitigation latency, and block outcomes.
- Preserve logs and metrics in machine-readable form for academic reporting and validation.
