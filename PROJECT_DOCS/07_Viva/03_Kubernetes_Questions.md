# Kubernetes Questions

Each entry: **Question** → **Expected Answer**

**Important:** Kubernetes is **not implemented** in IntelliShield. Answer honestly, then describe actual deployment and optional future direction.

---

## Direct Questions

### Q1. Did you deploy IntelliShield on Kubernetes?

**Expected Answer:** No. IntelliShield is deployed as native OS processes on a single Ubuntu 22.04 VM. There is no Dockerfile, docker-compose, Helm chart, or Kubernetes manifest in the repository. The controller runs via `osken-manager`, the dashboard via `python3 dashboard/api.py`, and scenarios via `sudo python3 -m traffic_generator.traffic_scheduler`.

---

### Q2. Why is Kubernetes not used?

**Expected Answer:** The project scope is a laboratory research prototype for MCA/IEEE evaluation. A single VM with Mininet, OsKen, and Open vSwitch is sufficient for reproducible experiments. Kubernetes would add complexity without benefit for one-switch Mininet emulation. We prioritised integration and demonstrability over cloud-native orchestration.

---

### Q3. Is the project containerised with Docker?

**Expected Answer:** No. No Dockerfile or container images exist in the repo. All dependencies are installed directly on the Ubuntu VM via apt and pip.

---

## If Examiner Insists on K8s Knowledge

### Q4. How *would* you containerise IntelliShield in future?

**Expected Answer:** (Hypothetical — not implemented)

- **Controller container:** OsKen + Python deps; needs host network or OpenFlow connectivity to OVS
- **Dashboard container:** FastAPI + static files; PersistentVolume for `logs/`
- **Mininet:** Typically requires `--privileged` or host namespaces — challenging in standard K8s pods
- **Challenges:** OpenFlow low latency, Mininet kernel features, single-node emulation vs pod networking

---

### Q5. What Kubernetes resources would you need?

**Expected Answer:** (Theoretical)

| Resource | Purpose |
|----------|---------|
| Deployment | Dashboard API replicas |
| StatefulSet or single Pod | Controller (stateful OpenFlow state) |
| PersistentVolumeClaim | `logs/`, `logs/models/` |
| Service | ClusterIP for dashboard :8080 |
| ConfigMap | Threshold constants (optional) |

Not built — this is future architecture discussion only.

---

### Q6. How does your actual deployment compare to Kubernetes?

**Expected Answer:**

| Aspect | Our implementation | Typical K8s |
|--------|-------------------|-------------|
| Orchestration | Manual / dashboard subprocess | kube-scheduler |
| Scaling | Single VM | Horizontal pod autoscaler |
| Service discovery | localhost:6653, :8080 | DNS + Services |
| Config | Python constants + env vars | ConfigMaps/Secrets |
| Logs | CSV files on disk | Often centralized logging stack |

---

### Q7. What is your actual "orchestration" mechanism?

**Expected Answer:** `dashboard/control.py` — a Python `ControlPanel` with background threads and subprocess calls. It restarts the controller via `pgrep` + `/proc/cmdline` PID inspection, runs scenarios with sudo, archives logs, and runs metrics. This is **application-level orchestration**, not Kubernetes.

---

### Q8. Could Mininet run inside Kubernetes?

**Expected Answer:** Mininet requires Linux network namespaces and often root privileges. Running it inside standard Kubernetes pods is non-trivial and uncommon. Research SDN projects typically use bare-metal VMs or privileged bare-metal nodes. Our choice of Ubuntu VM avoids this complexity.

---

## DevOps / Cloud Boundary

### Q9. Is this a cloud-native application?

**Expected Answer:** No. It is a lab-native SDN prototype. No cloud provider integration, no Terraform, no K8s, no managed databases.

---

### Q10. What would you say if asked "Explain your K8s cluster setup"?

**Expected Answer:** "We do not use Kubernetes. Our deployment is a single Ubuntu VM running OsKen controller, FastAPI dashboard, and Mininet scenarios as native processes. Orchestration for demos is handled by the Phase 8 Master Control panel. Kubernetes is listed in future scope for potential analytics microservices but is outside current implementation."

---

## Short Answers (memorise)

| Question | One-line answer |
|----------|-----------------|
| K8s used? | **No** |
| Docker used? | **No** |
| How deployed? | Ubuntu VM, native processes |
| Orchestration? | `control.py` Master Control |
| Why no K8s? | Lab prototype; Mininet+OpenFlow on single VM |
| Future K8s? | Possible for dashboard/analytics; not Mininet controller |
