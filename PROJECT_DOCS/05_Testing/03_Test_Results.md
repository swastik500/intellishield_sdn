# Test Results

## 1. Summary

| Category | Tests executed | Result | Evidence source |
|----------|----------------|--------|-----------------|
| Static compile (Phases 1–7) | All `.py` modules | ✅ PASS | `IMPLEMENTED/`, `PROJECT_ANALYSIS.md`, VM compile |
| Entropy math unit tests | 3 | ✅ PASS | H(0.5,0.5)=1.0; 4-flow NORMAL=0.984 |
| ML synthetic sanity | 6 samples | ✅ PASS | 3 NORMAL + 3 ATTACK correct |
| ADWIN self-test | 1 stream | ✅ PASS | Drift detected at attack onset |
| HDBSCAN self-test | 50 vectors | ✅ PASS | NORMAL + ATTACK clusters |
| Phase 7 verification | 40+ checks | ✅ PASS (VM) | `verify_phase7.py` |
| VM full-stack experiments | Jun 24–25 + post-fix runs | ✅ PASS | `logs/` on VM (192.168.64.5) |
| Dashboard + Master Control | API + jobs | ✅ PASS | `IMPLEMENTED/PHASE8.md` |
| Metrics pipeline | Post windowing fix | ✅ PASS | Finite latencies after archive-first workflow |

**Overall verdict:** All eight phases are **implemented and validated** on the Ubuntu VM. macOS dev host supports static analysis; runtime tests require the VM.

---

## 2. Static Verification Results

### 2.1 Compile and import (VM — Jun 2026)

| Check | Result |
|-------|--------|
| `python3 -m py_compile` all phase modules | ✅ PASS |
| `import numpy, sklearn, os_ken, mininet` | ✅ PASS |
| Import `entropy_engine`, `ml_models`, `mitigation`, `advanced_analytics`, `rl_engine` | ✅ PASS |
| `controller/flow_monitor.py` size and path | ✅ 56 KB at `controller/flow_monitor.py` |

### 2.2 Code review verification (`PROJECT_ANALYSIS.md`)

| Phase | Methods / features claimed | Verified |
|-------|---------------------------|----------|
| Phase 1 | 14 controller features | ✅ All present |
| Phase 2 | 4 entropy modules + hook | ✅ All present |
| Phase 3 | 7 traffic modules; 5 scenarios | ✅ All present |
| Shannon math | H([0.5,0.5]), H([1.0]) | ✅ PASS |
| ARP/LLDP separation | packet_in vs stats filter | ✅ PASS |
| Safety subnet guard | External IP rejection | ✅ PASS |

---

## 3. Phase-by-Phase Test Results

### Phase 1 — Flow Statistics

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P1-01 | ✅ PASS | Controller starts on VM |
| TC-P1-02 | ✅ PASS | `pingall` 0% loss after ARP fix |
| TC-P1-03 | ✅ PASS | Stats every 5 s |
| TC-P1-04 | ✅ PASS | ~5,600+ rows in VM `flow_stats.csv` |
| TC-P1-06 | ✅ PASS | ARP broadcasts forwarded correctly |

### Phase 2 — Entropy Detection

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P2-01 | ✅ PASS | H = 1.0000 |
| TC-P2-02 | ✅ PASS | H = 0.0000 |
| TC-P2-03 | ✅ PASS | score = 0.9839, status NORMAL |
| TC-P2-04 | ✅ PASS | SRC_MAC_ENTROPY_COLLAPSE on SYN flood |
| TC-P2-05 | ✅ PASS | ~4,862 entropy rows on VM (historical) |

**Sample alert (repository logs):**

| timestamp | alert_type | entropy_value |
|-----------|------------|---------------|
| 2026-07-01 12:29:36 | SRC_MAC_ENTROPY_COLLAPSE | 0.0 |
| 2026-07-01 12:29:36 | DST_MAC_ENTROPY_COLLAPSE | 0.0 |

### Phase 3 — Traffic Generation

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P3-01 – TC-P3-05 | ✅ PASS | All 5 scenarios execute on VM |
| TC-P3-06 | ✅ PASS | External IP blocked |
| TC-P3-09 | ✅ PASS | S1 corrected to `PROFILE_NORMAL_LIGHT` (ICMP-only) |

### Phase 4 — ML Detection

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P4-01 | ✅ PASS | Models trained and saved |
| TC-P4-02 | ✅ PASS | NORMAL 77.5–79.6% confidence |
| TC-P4-03 | ✅ PASS | ATTACK 85.1–85.2% confidence |
| TC-P4-04 | ✅ PASS | SYN_FLOOD hint on live S2 |
| TC-P4-05 | ✅ PASS | NORMAL on S1 after baseline fix |
| TC-P4-09 | ✅ PASS | Quiet baseline no longer misclassified as ATTACK |

**Synthetic training results (VM):**

```
IsolationForest : 300 normal samples, contamination 10%  → TRAINED
DecisionTree    : 500 samples, test accuracy 100%       → TRAINED
Top feature     : entropy_score (importance = 1.0)
```

### Phase 5 — Mitigation

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P5-01 | ✅ PASS | BLOCK rows in VM `mitigation_actions.csv` |
| TC-P5-02 | ✅ PASS | Priority 200 DROP rules observed |
| TC-P5-03 | ✅ PASS | Auto-expiry via hard_timeout |
| TC-P5-07 | ✅ PASS | FLOW_PAIR surgical blocks used |
| TC-P5-08 | ✅ PASS | Entropy dual-trigger path implemented |

### Phase 6 — Advanced Analytics

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P6-01 | ✅ PASS | ADWIN drift at sample ~19–70 in self-test |
| TC-P6-02 | ✅ PASS | 3 clusters: 1 NORMAL, 2 ATTACK |
| TC-P6-03 | ✅ PASS | `drift_alerts.csv` populated on VM |

**HDBSCAN self-test summary:**

| Cluster | Label | Size | μ pkt/s | μ entropy |
|---------|-------|------|---------|-----------|
| 0 | NORMAL | 30 | 202.4 | 0.843 |
| 1 | ATTACK | 12 | 92,361 | 0.054 |
| 2 | ATTACK | 8 | 89,346 | 0.042 |

### Phase 7 — Reinforcement Learning

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P7-01 | ✅ PASS (VM) | `verify_phase7.py` — all checks |
| TC-P7-05 | ✅ PASS | Weight save/load identical output |
| TC-P7-06 | ✅ PASS | Normal reward > 0; attack reward ≥ +10 |
| TC-P7-07 | ✅ PASS | `rl_decisions.csv` on VM |

**`verify_phase7.py` test groups:**

| # | Test group | Checks | Result |
|---|------------|--------|--------|
| 1 | `_Linear` layer | 4 | ✅ PASS |
| 2 | `_ActorCritic` | 4 | ✅ PASS |
| 3 | GAE returns | 3 | ✅ PASS |
| 4 | PPO clipping | 2 | ✅ PASS |
| 5 | PPOAgent 60-cycle | 4 | ✅ PASS |
| 6 | ThresholdAdapter | 6 | ✅ PASS |
| 7 | SDNEnvironment | 3 | ✅ PASS |
| 8 | RLLogger | 2 | ✅ PASS |
| 9 | Weight persistence | 1 | ✅ PASS |
| 10 | Integration smoke | 4 | ✅ PASS |

*Note: macOS dev host lacks numpy; run on VM for local execution.*

### Phase 8 — Dashboard

| Test ID | Result | Notes |
|---------|--------|-------|
| TC-P8-01 | ✅ PASS | FastAPI on :8080 |
| TC-P8-02 – TC-P8-04 | ✅ PASS | All read endpoints return JSON |
| TC-P8-05 | ✅ PASS | Python PID-based restart (pkill self-match fixed) |
| TC-P8-06 – TC-P8-08 | ✅ PASS | Scenarios + batch + metrics from UI |

---

## 4. Integration Test Results

| Test ID | Result | Evidence |
|---------|--------|----------|
| TC-INT-01 | ✅ PASS | S2: entropy ALERT → ML ATTACK → BLOCK chain observed |
| TC-INT-02 | ✅ PASS | S1: ML NORMAL after light-profile fix |
| TC-INT-03 | ✅ PASS | Warm-up defers ML/mitigation; ADWIN still active |
| TC-INT-04 | ✅ PASS | Attack streak confirmation prevents single-cycle blocks |
| TC-INT-05 | ✅ PASS | Archive-first workflow prevents metric bleed |
| TC-INT-06 | ✅ PASS | Known-header fallback in `compute_metrics.py` |

### Bugs found and fixed during testing

| Bug | Impact | Fix | Retest |
|-----|--------|-----|--------|
| Duplicate entropy hook | Double window fill / inflated logs | Removed duplicate call | ✅ PASS |
| Warm-up early return | Skipped ADWIN during warm-up | `in_warmup` flag | ✅ PASS |
| RL conf not wired to mitigation | Static 60% gate | `set_threshold_adapter()` | ✅ PASS |
| S1 used heavy iperf profile | False ATTACK on baseline | `PROFILE_NORMAL_LIGHT` | ✅ PASS |
| Metrics cross-run bleed | Absurd latencies (100k+ s) | In-window + grace matching | ✅ PASS |
| S4 missing ATTACK_STOP | None metrics for burst | `_SCENARIO_END` closes window | ✅ PASS |
| Controller restart pkill self-match | UI restart failed | Python PID inspection | ✅ PASS |

---

## 5. VM Log Evidence (Historical Runs)

Full-stack experiments on VM (`192.168.64.5`, Jun 24–25, 2026):

| Log file | Approx. rows | Indicates |
|----------|-------------|-----------|
| `flow_stats.csv` | 5,600+ | Phase 1 telemetry active |
| `entropy_logs.csv` | 4,862 | Phase 2 continuous analysis |
| `ml_predictions.csv` | 2,433 | Phase 4 predictions post warm-up |
| `ml_features.csv` | 3,400+ | Feature vectors captured |
| `mitigation_actions.csv` | multiple BLOCK events | Phase 5 mitigation fired |
| `rl_decisions.csv` | per-cycle entries | Phase 7 online learning |
| `drift_alerts.csv` | drift events | Phase 6 ADWIN active |
| `scenario_logs.csv` | lifecycle events | Phase 3 ground truth |

---

## 6. Metrics Test Results

After metrics script fixes and archive-first workflow:

| Metric | Typical range (S2 SYN) | Status |
|--------|------------------------|--------|
| Entropy detection latency | 5–15 s | ✅ Finite |
| ML detection latency | 5–20 s | ✅ Finite |
| Mitigation latency | ≤ ML latency + 5 s | ✅ Finite |
| False-positive blocks (S1) | 0 | ✅ Target met |

**Prior failure (resolved):** Cross-run matching produced `ML ATTACK lat.: 187087.75s` and `False-positive blocks: 55` — fixed by `_first_in_window` with grace period and mandatory log archival.

---

## 7. Test Gaps and Outstanding Items

| Item | Status | Notes |
|------|--------|-------|
| Automated CI pipeline | Not implemented | Manual VM validation |
| Formal pytest suite (Phases 1–6) | Partial | Self-tests + verify_phase7 only |
| Multi-switch topology tests | Out of scope | Single-switch Mininet |
| Hardware performance benchmarks | Out of scope | Emulation only |
| Long-duration soak test (24 h) | Not run | Recommended for production claims |

---

## 8. Sign-Off Checklist

- [x] All phase modules compile and import on VM
- [x] Mininet connectivity verified (`pingall` 0% loss)
- [x] Scenarios S1–S5 execute with logged ground truth
- [x] Detection pipeline produces entropy + ML alerts on attacks
- [x] Mitigation installs OpenFlow blocks on confirmed attacks
- [x] S1 baseline does not produce false ATTACK or false blocks
- [x] `compute_metrics.py` produces finite per-scenario latencies
- [x] Dashboard serves live data and Master Control jobs
- [x] Phase 7 unit verification suite passes on VM

**Testing status: suitable for academic demonstration, viva, and IEEE prototype paper** with limitations documented in `06_Results/04_Limitations.md`.
