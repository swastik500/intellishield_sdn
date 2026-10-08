# Database Questions

Each entry: **Question** → **Expected Answer**

**Important:** IntelliShield does **not use** a relational or NoSQL database server. Persistence is **file-based**.

---

## Direct Questions

### Q1. Which database did you use?

**Expected Answer:** We do not use PostgreSQL, MySQL, SQLite, MongoDB, or Redis. All persistence is file-based under `logs/`: CSV for time-series events, JSON for session summaries, and pickle for ML models and PPO weights.

---

### Q2. Why no database?

**Expected Answer:** For a research prototype, file-based logs are simpler, portable, and auditable. Examiners and reviewers can open CSV in Excel or pandas. No database server to install or maintain on the VM. Dashboard tail-reads CSV directly. Trade-off: no SQL queries or concurrent write safety at scale.

---

### Q3. How is data stored?

**Expected Answer:**

| Format | Examples | Written by |
|--------|----------|------------|
| CSV | `entropy_logs.csv`, `ml_predictions.csv`, `mitigation_actions.csv` | Controller phases |
| JSON | `entropy_baselines.json`, `metrics_report.json`, `mitigation_summary.json` | Loggers, metrics script |
| Pickle | `logs/models/*.pkl`, `ppo_weights.pkl` | ML trainer, PPO agent |

---

## CSV Schema Questions

### Q4. What tables equivalent exist in CSV?

**Expected Answer:** Each CSV is like a table:

- `flow_stats.csv` — per-flow telemetry
- `entropy_logs.csv` — per-cycle entropy
- `ml_predictions.csv` — per-cycle ML output
- `mitigation_actions.csv` — block/unblock events
- `scenario_logs.csv` — experiment ground truth
- `rl_decisions.csv` — RL threshold history
- `drift_alerts.csv`, `cluster_labels.csv` — Phase 6

Full schemas in `07_Database.md` under Implementation docs.

---

### Q5. How does the dashboard read data without a database?

**Expected Answer:** `read_csv_tail(path, n)` opens CSV, parses with `csv.DictReader`, returns last N rows. `/api/summary` aggregates counts from multiple files. No ORM, no connection pool — simple file I/O every 5 seconds.

---

### Q6. How are experiments isolated?

**Expected Answer:** `ControlPanel.archive_logs()` moves active CSVs to `logs/archive/YYYYMMDD_HHMMSS/`. New experiment writes fresh files. Prevents cross-run metric contamination (e.g., absurd latencies from old rows).

---

## Data Integrity

### Q7. How do you handle concurrent writes?

**Expected Answer:** Single controller process appends to CSV — no concurrent writers assumed. Dashboard is read-only on logs. If dashboard archives while controller writes, header corruption can occur — mitigated by `_KNOWN_HEADERS` fallback in `compute_metrics.py`.

---

### Q8. What is the timestamp format?

**Expected Answer:** `YYYY-MM-DD HH:%M:%S` — VM local time via `datetime.now()`. Used as join key in metrics script with 60-second grace window after attack stop.

---

### Q9. How are ML models stored?

**Expected Answer:** Python `pickle` in `logs/models/isolation_forest.pkl`, `decision_tree.pkl`, `scaler.pkl`. PPO weights in `logs/ppo_weights.pkl`. Loaded on controller startup; not portable across major sklearn versions without retrain.

---

## Comparison Questions

### Q10. CSV vs database — advantages and disadvantages?

**Expected Answer:**

| CSV files | Database |
|-----------|----------|
| ✅ Simple, human-readable | ✅ Concurrent queries |
| ✅ Easy archive/share | ✅ Indexing, joins |
| ✅ No server needed | ✅ ACID transactions |
| ❌ No indexing | ❌ Setup complexity |
| ❌ Full scan for queries | ❌ Overkill for lab |

Our scale (thousands of rows) suits CSV. Production would use InfluxDB or TimescaleDB — future scope.

---

### Q11. Could you use SQLite?

**Expected Answer:** Possible but not implemented. Would add schema migration and query layer without clear benefit for demo scale. CSV matches IEEE artifact sharing conventions.

---

### Q12. What is `entropy_baselines.json`?

**Expected Answer:** Rolling statistics per switch per entropy dimension (mean, std, min, max, sample count). Updated by `update_baseline()` in entropy_logger. Used for adaptive context; ADWIN uses separate sliding windows.

---

### Q13. What is `metrics_report.json`?

**Expected Answer:** Output of `compute_metrics.py` — per-scenario entropy/ML/mitigation latencies and false-positive block counts. Consumed by dashboard `/api/metrics`.

---

## ER / Data Model

### Q14. What are the main entities?

**Expected Answer:** Switch (DPID), FlowStat, EntropyMetric, MLPrediction, MitigationAction, ScenarioEvent, AttackWindow (derived), RLDecision. Relationships joined by switch_id and timestamp in Python — not foreign keys in SQL.

---

### Q15. How does metrics script join data?

**Expected Answer:** Parses `scenario_logs.csv` for attack windows → filters `detection_alerts.csv`, `ml_predictions.csv`, `mitigation_actions.csv` for first matching row where timestamp ∈ [attack_start, attack_stop + 60s grace].

---

## If Examiner Asks "Database" Generically

### Q16. Explain your data persistence layer.

**Expected Answer:** "We use a log-centric persistence layer — append-only CSV files for telemetry and events, JSON for summaries, pickle for trained models. The dashboard and metrics script read these files directly. We intentionally avoided a database server to keep the prototype portable and reproducible for academic evaluation."

---

## Quick Reference

| Question | Answer |
|----------|--------|
| SQL database? | **No** |
| Where is data? | `logs/*.csv`, `*.json`, `*.pkl` |
| Dashboard reads? | CSV tail via Python |
| Models stored? | pickle in `logs/models/` |
| Experiment archive? | `logs/archive/<timestamp>/` |
| Future DB? | InfluxDB/Grafana — not implemented |
