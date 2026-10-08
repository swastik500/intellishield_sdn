# Problem Statement

Modern networks are increasingly vulnerable to DDoS attacks that overwhelm services by flooding them with malicious traffic. In traditional network environments, detection and mitigation are often slow, manual, reactive, and distributed across multiple devices without a centralized decision plane. This delay allows attack traffic to consume bandwidth, exhaust switch or host resources, and degrade the availability of legitimate services.

Software Defined Networking (SDN) improves controllability by separating the control plane from the data plane, but many SDN deployments still rely on static rules, fixed thresholds, or single-technique detection methods. These approaches are often insufficient for real-world attack conditions because:

1. Static thresholds do not adapt well to changing traffic patterns.
2. Signature-only or single-model systems struggle with previously unseen attacks.
3. Broad mitigation strategies can over-block and disrupt legitimate traffic.
4. Operators lack integrated visibility into detection, mitigation, and system behavior.
5. Existing research prototypes often stop at detection and do not provide a full closed-loop response pipeline.

The core problem addressed by this project is therefore:

> How can an SDN environment automatically detect, explain, and mitigate DDoS attacks in real time while minimizing false positives, preserving legitimate traffic, and adapting to evolving network behavior?

This repository answers that problem by combining flow monitoring, entropy analysis, hybrid machine learning, adaptive threshold tuning, and surgical OpenFlow-based mitigation into one integrated framework. The project is specifically designed not only to detect attacks but to do so fast enough for operational use, with sufficient explainability and controllability for academic evaluation and live demonstration.
