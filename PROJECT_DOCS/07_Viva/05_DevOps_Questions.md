# DevOps Questions

Each entry: **Question** → **Expected Answer**

**Note:** Full CI/CD and container DevOps are **not implemented**. Answers describe actual VM deployment and lab operations.

---

## Deployment

### Q1. How is the project deployed?

**Expected Answer:** On Ubuntu 22.04 LTS VM at `~/intellishield-sdn/`. Three main processes: (1) `osken-manager controller/flow_monitor.py` — controller; (2) `python3 dashboard/api.py` — dashboard on :8080; (3) `sudo python3 -m traffic_generator.traffic_scheduler --scenario N` — on-demand experiments. Open vSwitch runs as system service.

---

### Q2. What are the system dependencies?

**Expected Answer:**

```bash
# apt: mininet, openvswitch-switch, python3-os-ken, hping3, iperf
# pip: numpy, scikit-learn, fastapi, uvicorn
```

Documented in `initial_setup_done.md` and `04_Implementation/10_Deployment.md`.

---

### Q3. How do you sync code from dev machine to VM?

**Expected Answer:** git pull, scp, or rsync from macOS dev host to VM. After sync, restart controller and dashboard to load Python changes. No automated pipeline in repository.

---

## Dashboard & Operations

### Q4. What is Master Control?

**Expected Answer:** Phase 8 feature in `dashboard/control.py`. Background job runner from browser: archive logs, restart/stop controller, run scenarios S1–S5, batch eval S3+S4+S5, compute metrics, retrain ML. Uses subprocess + threading; not Jenkins or GitHub Actions.

---

### Q5. How does controller restart work from UI?

**Expected Answer:** `ControlPanel._controller_pids()` finds osken-manager via pgrep and `/proc/pid/cmdline` (avoids pkill self-match bug). SIGTERM then SIGKILL if needed. Starts detached `osken-manager` logging to `/tmp/controller.log`. 20-second warmup before success reported.

---

### Q6. How are scenarios run with sudo from dashboard?

**Expected Answer:** Either passwordless sudoers entry for `traffic_scheduler` only, or `INTELLISHIELD_SUDO_PASS` environment variable with `sudo -S`. Scenario lock prevents concurrent runs.

---

## Testing & Quality

### Q7. What testing strategy do you use?

**Expected Answer:** Layered: py_compile static checks, `verify_phase7.py` for RL, ADWIN/HDBSCAN self-tests, scenario-based acceptance (S1–S5), and `compute_metrics.py` regression on latencies. No pytest CI in repository — manual VM validation.

---

### Q8. Is there CI/CD?

**Expected Answer:** No GitHub Actions, Jenkins, or GitLab CI in the repo. Testing is manual on Ubuntu VM. Future work includes pytest and CI smoke tests — documented but not implemented.

---

### Q9. How do you ensure reproducible experiments?

**Expected Answer:** Archive logs before each run (`logs/archive/<timestamp>/`), restart controller for clean state, run predefined scenarios with fixed durations, compute metrics with windowed join. Master Control batch button automates this sequence.

---

## Monitoring & Logs (Ops)

### Q10. How do you monitor the system in production-like terms?

**Expected Answer:** No Prometheus/Grafana. Monitoring is: CSV log append rates, dashboard `/api/status` phase health, controller console banners, and `/tmp/controller.log` for restart debugging.

---

### Q11. How do you handle log rotation?

**Expected Answer:** Manual archival via Master Control or `mv logs/*.csv logs/archive/`. No logrotate configuration in repo. Long runs require operator to archive to prevent disk growth.

---

### Q12. What ports must be open?

**Expected Answer:** 6653 (OpenFlow controller), 8080 (dashboard HTTP), 22 (SSH admin). Mininet uses virtual interfaces — no extra host ports.

---

## Security (Ops)

### Q13. Is the dashboard secured?

**Expected Answer:** No authentication, no TLS. HTTP on 0.0.0.0:8080 with CORS allow all. Suitable for isolated lab VM only. Documented limitation.

---

### Q14. How do you manage secrets?

**Expected Answer:** Optional `INTELLISHIELD_SUDO_PASS` in environment — not ideal for production. No vault or K8s secrets. Sudoers file for passwordless scenario command is preferred for demos.

---

## Containers & Cloud (honest)

### Q15. Docker or Kubernetes in DevOps pipeline?

**Expected Answer:** Neither. No Dockerfile, no K8s manifests, no Helm. Deployment is bare VM processes.

---

### Q16. Infrastructure as Code?

**Expected Answer:** No Terraform, Ansible, or CloudFormation in repository. VM setup is manual per `initial_setup_done.md`.

---

## Troubleshooting

### Q17. Controller won't start — what do you check?

**Expected Answer:** `/tmp/controller.log`, `python3 -m py_compile controller/flow_monitor.py`, OsKen installed, port 6653 not in use, import errors for numpy/sklearn.

---

### Q18. Scenario fails from UI?

**Expected Answer:** Sudo permissions, Mininet cleanup (`mn -c`), another scenario running, hping3 installed, check job log tail in Master Control.

---

### Q19. Metrics show null latencies?

**Expected Answer:** Archive logs first, ensure `scenario_logs.csv` has ATTACK_START/STOP, run `compute_metrics.py` after scenario completes, check CSV header fallback if logs archived mid-write.

---

## DevOps Summary Table

| Topic | Implemented? | How |
|-------|--------------|-----|
| Deployment | Yes | Ubuntu VM manual |
| CI/CD | No | — |
| Docker/K8s | No | — |
| Orchestration | Partial | Master Control panel |
| Monitoring | Partial | Dashboard + CSV |
| IaC | No | — |
| Automated tests | Partial | verify_phase7, scenarios |
