# R8 Alerting Q&A — Release 1.0

Related: [../../02_Novelties/07_R8_Alerting.md](../../02_Novelties/07_R8_Alerting.md) · [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md) · [../../04_Implementation/06_APIs.md](../../04_Implementation/06_APIs.md) · [R7_QNA.md](06_R7_QNA.md) · [FOUNDATION_QNA.md](01_Foundation_QNA.md) · `GLOSSARY.md`

R8 turns verification outcomes into **persisted security alerts** with severity, deduplication, and rate limiting. Package: `alerting/`.

**Release 1.0 scope:** JSONL persistence + dashboard poll. External Slack/email/PagerDuty: **Not implemented**. Dashboard HTTP auth: **Not implemented**.

> **PROJECT_DOCS copy** — adapted from `R8_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

### Q1. What is R8 in one sentence?

**Purpose:** Alert manager that converts `VerificationResult` into typed `AlertEvent` records, applies dedup/rate-limit policy, persists to JSONL, and optionally dispatches local adapters.

**Reason:** Operators need durable, queryable security notifications decoupled from raw verification traces and legacy entropy CSV alerts.

**Implementation:** `AlertManager.process_verification()` in `alerting/manager.py`.

**Runtime:** Hooked from controller after R7 each poll cycle (via `alerting/runtime.py`).

**Limits:** Does not authorize mitigation — observability only.

**Related:** [R8_ALERTING.md](../../02_Novelties/07_R8_Alerting.md)

---

### Q2. Why alerting after verification (R7) instead of directly from ML?

**Purpose:** Alert on **actionable, policy-approved** security state — default VERIFIED only.

**Reason:** ML/entropy fires frequently during warm-up, low confidence, and PENDING streaks — alerting there would desensitize operators.

**Implementation:** `AlertFactory.should_create()` gates on `VerificationStatus`.

**Runtime:** Empty security alerts common until first VERIFIED cycle.

**Related:** [R7_QNA.md](06_R7_QNA.md)

---

### Q3. What modules comprise the R8 package?

| Module | Role |
|--------|------|
| `manager.py` | Orchestration, policy order |
| `config.py` | Policy knobs |
| `severity.py` | Severity mapping |
| `dedup.py` | Dedup keys / window |
| `rate_limit.py` | Per-key rate limit |
| `persistence.py` | JSONL store + history reader |
| `runtime.py` | Controller hook |
| `factory.py` | AlertEvent construction |
| `adapters/` | Notification adapter protocol |
| `metrics.py` | Counters |

**Related:** `PROJECT_STRUCTURE.md`

---

### Q4. What tests cover R8?

| File | Focus |
|------|-------|
| `tests/test_alerting_core_r81.py` | Core |
| `tests/test_alerting_policy_r82.py` | Policy |
| `tests/test_alerting_runtime_r83.py` | Runtime |
| `tests/test_alerting_dashboard_r84.py` | API |
| `tests/test_alerting_hardening_r85.py` | Isolation |
| `tests/test_alerting_perf_r85.py` | Latency |

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

## Alert Lifecycle

### Q5. What is the full alert lifecycle pipeline?

```
VerificationResult
      ↓
 eligibility policy (default: VERIFIED only)
      ↓
 build AlertEvent + severity (factory)
      ↓
 dedup check ──hit──► DUPLICATE (not persisted)
      ↓ miss
 rate limit ──exceed──► RATE_LIMITED (not persisted)
      ↓
 persist JSONL (logs/alerts.jsonl)
      ↓
 dispatch adapters (local hooks)
      ↓
 Dashboard GET /api/security-alerts*
```

**Purpose:** Deterministic, auditable ordering documented in manager.

**Implementation:** `_apply_policy_and_emit()` — dedup → rate limit → persist → dispatch.

**Runtime:** Duplicates/rate-limited alerts **not persisted** (simple auditable policy).

**Related:** `alerting/manager.py` docstring

---

### Q6. What is `AlertDisposition`?

**Purpose:** Machine-readable outcome of one `process_verification` / `process_alert` call.

**Values:** `NEW`, `SKIPPED`, `DISABLED`, `DUPLICATE`, `RATE_LIMITED`, `ERROR`.

**Reason:** Controller metrics and tests assert policy behavior without parsing logs.

**Implementation:** Enum in `manager.py`; returned in `AlertProcessResult`.

**Runtime:** Only `NEW` with `persisted=True` adds JSONL line.

**Related:** `tests/test_alerting_policy_r82.py`

---

### Q7. When is an alert SKIPPED vs DISABLED?

| Disposition | Cause |
|-------------|-------|
| **DISABLED** | `AlertingConfig.enabled=False` |
| **SKIPPED** | Factory returned None (`should_create` false), null input, or policy filter |

**Purpose:** Distinguish global off switch from per-status filtering.

**Runtime:** SKIPPED increments `alerts_skipped` metric.

**Related:** `AlertManager.process_verification()`

---

### Q8. Default — which verification statuses create alerts?

| Status | Default alert? |
|--------|----------------|
| **VERIFIED** | **Yes** |
| **PENDING** | No (`alert_on_pending=False`) |
| **INELIGIBLE** | No (`alert_on_ineligible=False`) |
| **REJECTED** | No (`alert_on_rejected=False`) |

**Purpose:** Production default = actionable verified events only.

**Implementation:** `AlertingConfig` defaults in `alerting/config.py`.

**Runtime:** Enable `alert_on_pending` for debugging emerging attacks — increases noise.

**Related:** [R7_QNA.md](06_R7_QNA.md) Q11

---

### Q9. What is `AlertFactory.should_create()` logic?

**Purpose:** Central eligibility before building DTO.

**Implementation:** VERIFIED always true; other statuses consult config booleans.

**Reason:** Keeps manager thin — factory owns status→alert decision.

**Runtime:** Returns false → SKIPPED disposition, no persist.

**Related:** `alerting/factory.py`

---

### Q10. How is `AlertEvent` built from verification?

**Purpose:** Map R7 result + optional context → Foundation DTO.

**Fields set:** `alert_id`, `timestamp`, `severity`, `alert_type`, `title`, `message`, `event_id`, `source`, `dedup_key`, `evidence`, optional RCA/mitigation refs.

**Implementation:** `AlertFactory.from_verification(result, context)`.

**Runtime:** Severity assigned via injectable `SeverityPolicy` before dedup.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q16

---

## Severity

### Q11. How is severity assigned?

**Purpose:** Deterministic operator prioritization from available evidence.

**Implementation:** `DefaultSeverityPolicy.assign(SeverityEvidence)` in `alerting/severity.py`.

**Runtime:** Confidence treated as unit [0,1]; missing/invalid → 0.0.

**Limits:** Future R4/R5/R2 fields in `SeverityEvidence` ignored until policies extended.

**Related:** `alerting/severity.py`

---

### Q12. What are default confidence severity thresholds?

| Level | Rule (VERIFIED + mitigation_eligible) |
|-------|----------------------------------------|
| **CRITICAL** | confidence ≥ **0.90** OR attack_hint in {SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, VOLUMETRIC_FLOOD} |
| **HIGH** | other eligible VERIFIED |
| **MEDIUM** | VERIFIED but not eligible |
| **MEDIUM** | PENDING |
| **LOW** | INELIGIBLE |
| **INFO** | REJECTED |

**Purpose:** Map numeric confidence to `Severity` enum for dashboard badges.

**Config defaults:** `severity_critical_confidence=0.90`, `severity_high_confidence=0.75` (HIGH floor reserved).

**Related:** [R8_ALERTING.md](../../02_Novelties/07_R8_Alerting.md)

---

### Q13. Why CRITICAL for flood hints even below 0.90 confidence?

**Purpose:** Reflect high operational impact of volumetric/targeted flood classes.

**Reason:** Hint encodes attack semantics from explanation path — confidence alone may lag on burst S4.

**Implementation:** `_CRITICAL_HINTS` frozenset in severity module.

**Runtime:** SYN_FLOOD at 0.80 confidence → CRITICAL not HIGH.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.2 burst scenarios

---

### Q14. What if confidence arrives as 0–100 instead of unit?

**Purpose:** Defensive normalization at severity layer.

**Implementation:** `_safe_unit()` — values >1.0 and ≤100.0 divided by 100.

**Reason:** Double defense alongside R7 normalization — alerts must not mis-severity on scale bugs.

**Runtime:** NaN/inf → 0.0.

**Related:** `alerting/severity.py`

---

### Q15. Can severity policy be swapped for tests?

**Yes** — inject custom `SeverityPolicy` into `AlertFactory`.

**Purpose:** Test matrix without changing `AlertEvent` schema.

**Implementation:** Protocol `SeverityPolicy` with `assign(evidence)`.

**Runtime:** Default is `DefaultSeverityPolicy` with config thresholds.

**Related:** `tests/test_alerting_policy_r82.py`

---

## Deduplication

### Q16. What is alert deduplication?

**Purpose:** Suppress repeat alerts for the same logical incident within a time window.

**Reason:** VERIFIED may fire every poll cycle (~5s) while attack persists — without dedup, JSONL floods.

**Implementation:** `BoundedDeduplicator` in `alerting/dedup.py`.

**Default window:** **60 seconds**.

**Related:** `GLOSSARY.md` — **Deduplication (R8)**

---

### Q17. How is the dedup key constructed?

**Purpose:** Stable key across cycles for same attacker/victim/hint.

**Implementation:** `build_dedup_key()` — pipe-joined:
`alert_type | source | attacker_mac | victim_mac | attack_hint`

**Reason:** Fixed-order string — no dict ordering ambiguity.

**Runtime:** Stored on `AlertEvent.dedup_key`.

**Related:** `alerting/factory.py`

---

### Q18. What happens on duplicate within window?

**Purpose:** Auditable suppression without duplicate JSONL lines.

**Behavior:** First sighting → not duplicate, proceed to rate limit/persist. Repeat within 60s → `DUPLICATE` disposition, **not persisted**.

**Implementation:** `deduplicator.observe(key)` returns `DedupDecision`.

**Metrics:** `alerts_deduplicated` incremented.

**Related:** `alerting/manager.py`

---

### Q19. What happens after dedup window expires?

**Purpose:** New incident episode or continued attack after gap → new alert line.

**Behavior:** Key treated as fresh; suppression counter reset for that key.

**Implementation:** `_expire()` on monotonic clock in deduplicator.

**Runtime:** 61s apart same attacker → two JSONL records.

**Related:** `tests/test_alerting_policy_r82.py`

---

### Q20. What is `dedup_max_keys` default?

**256** — bounded cardinality with FIFO eviction of oldest key.

**Purpose:** Prevent unbounded memory growth under spoofed MAC storms.

**Implementation:** OrderedDict eviction in `BoundedDeduplicator`.

**Runtime:** Lab scale sufficient; production would need external store (**Not implemented**).

**Related:** `AlertingConfig`

---

### Q21. Can dedup be disabled?

**Yes** — `AlertingConfig.dedup_enabled=False`.

**Purpose:** Debugging / measuring raw VERIFIED rate.

**Limits:** JSONL grows quickly — not recommended for long demos.

**Related:** `alerting/config.py`

---

## Rate Limiting

### Q22. What is rate limiting in R8?

**Purpose:** Cap alerts per dedup key per sliding window — second line of defense after dedup.

**Default:** **30 alerts per 60 seconds** per key.

**Reason:** Dedup collapses identical keys; rate limit catches near-unique key storms.

**Implementation:** `BoundedRateLimiter` sliding window (not token bucket).

**Related:** `alerting/rate_limit.py`

---

### Q23. Dedup vs rate limit — which runs first?

**Dedup first**, then rate limit.

**Purpose:** Documented policy order in manager — storms collapse to DUPLICATE before consuming rate budget.

**Implementation:** `_apply_policy_and_emit()` step order.

**Runtime:** Rate limit only sees first-in-window alerts for a key.

**Related:** Q5 lifecycle

---

### Q24. What happens when rate limit exceeded?

**Disposition:** `RATE_LIMITED` — alert **not persisted**, metric `alerts_rate_limited` incremented.

**Purpose:** Protect disk, dashboard API, and future notification channels.

**Runtime:** Returns reason string with count/limit for logs.

**Related:** `alerting/manager.py`

---

### Q25. What is `rate_limit_max_keys`?

**Default 256** — same bounded cardinality pattern as dedup.

**Purpose:** Global storm protection — attackers cannot exhaust memory via unique identities.

**Implementation:** FIFO eviction of idle keys in limiter.

**Related:** `BoundedRateLimiter` docstring

---

### Q26. Can rate limit be disabled?

**Yes** — `rate_limit_enabled=False`.

**Purpose:** Test environments only.

**Related:** `AlertingConfig`

---

## Persistence

### Q27. Where are R8 alerts persisted?

**File:** `logs/alerts.jsonl` (`DEFAULT_ALERTS_FILENAME`).

**Purpose:** Append-only lab storage aligned with other JSONL planes.

**Implementation:** `JsonlAlertStore` in `alerting/persistence.py`.

**Runtime:** Thread-safe append with lock; failures logged, non-fatal.

**Related:** [R8_ALERTING.md](../../02_Novelties/07_R8_Alerting.md)

---

### Q28. How does persistence serialize alerts?

**Purpose:** Use Foundation contracts for stable schema.

**Implementation:** `to_dict(alert)` → `json.dumps` + newline.

**Read path:** `from_dict(..., AlertEvent)` on tail scan.

**Limits:** `MAX_SCAN_LINES=5000` for stats/history reads — bounded dashboard cost.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q23

---

### Q29. What evidence scrubbing applies before persist?

**Purpose:** Prevent accidental secret leakage in evidence dicts.

**Denied key substrings:** `password`, `token`, `secret`, `api_key`, `private_key`, `credential`, `authorization`.

**Implementation:** `AlertingConfig.evidence_denied_keys` — factory scrubs on build.

**Runtime:** Defense in depth for lab logs that may be bundled (P0.5).

**Related:** `alerting/config.py`

---

### Q30. What is `NullAlertStore`?

**Purpose:** No-op store for tests or alerting-disabled paths.

**Behavior:** `append()` returns True without I/O.

**Runtime:** Manager still runs dedup/rate limit when store null.

**Related:** `alerting/persistence.py`

---

### Q31. Does R8 modify legacy CSV alert files?

**No.**

**Purpose:** R8 is additive JSONL — legacy entropy `detection_alerts.csv` untouched.

**Dashboard:** `/api/alerts` (legacy) vs `/api/security-alerts` (R8).

**Related:** [API_REFERENCE.md](../../04_Implementation/06_APIs.md)

---

## Dashboard & API

### Q32. What dashboard endpoints expose R8 alerts?

| Endpoint | Purpose |
|----------|---------|
| `GET /api/security-alerts` | Recent AlertEvent history (newest first) |
| `GET /api/security-alerts/stats` | Counts / aggregates |

**Query params:** `limit` (0–500), `severity`, `alert_type`, `since`, `until`.

**Purpose:** Live lab UI poll — see `dashboard/static/index.html`.

**Related:** `dashboard/api.py`

---

### Q33. Example curl commands

```bash
curl -s 'http://127.0.0.1:8080/api/security-alerts?limit=10' | python3 -m json.tool
curl -s 'http://127.0.0.1:8080/api/security-alerts/stats' | python3 -m json.tool
```

**Purpose:** Quick operator verification after attack scenario.

**Expectation:** Empty lists if controller never reached VERIFIED (common without lab ops profile).

**Related:** [R8_ALERTING.md](../../02_Novelties/07_R8_Alerting.md)

---

### Q34. Is there HTTP authentication on security alert APIs?

**Not implemented** in Release 1.0.

**Purpose:** Lab prototype on localhost :8080.

**Reason:** Auth listed as out of scope in release docs.

**Runtime:** Do not expose dashboard to untrusted networks without reverse proxy auth.

**Related:** `GLOSSARY.md` — **Dashboard**

---

### Q35. How does UI distinguish R8 vs legacy alerts?

**R8 panel:** fetches `/api/security-alerts?limit=15`.

**Legacy panel:** `/api/alerts` from entropy CSV.

**Purpose:** Avoid conflating Phase 2 entropy alerts with unified R8 security alerts.

**Related:** `dashboard/static/index.html`

---

### Q36. What does stats endpoint return?

**Purpose:** Bounded aggregates over recent JSONL tail.

**Typical fields:** total counts, severity breakdown, exists/empty flags.

**Implementation:** `alert_history_stats()` with scan bound.

**Runtime:** On read failure returns safe empty structure with error type.

**Related:** `dashboard/api.py` `get_security_alert_stats`

---

## Notification & Future Integration

### Q37. Are Slack/email notifications implemented?

**Not implemented** / **Out of current project scope**.

**Purpose:** Release 1.0 notification = JSONL + dashboard poll.

**Implementation hook:** `NotificationAdapter` protocol in `alerting/adapters/`; `dispatch_enabled` in config.

**Runtime:** `_dispatch()` calls registered adapters — default list empty.

**Related:** [R8_ALERTING.md](../../02_Novelties/07_R8_Alerting.md)

---

### Q38. What is `dispatch_enabled`?

**Default True** — manager attempts adapter dispatch after persist.

**Purpose:** Local hook point for future Slack/webhook adapters without changing manager order.

**Runtime:** With zero adapters, dispatch is no-op success.

**Related:** `AlertingConfig`

---

### Q39. How would a Slack adapter be added (future)?

**Steps (design):**
1. Implement `NotificationAdapter` subclass
2. Register via `AlertManager.add_adapter()`
3. Keep secrets in env — not in JSONL evidence
4. Respect dedup/rate limit — only NEW persisted alerts dispatch

**Purpose:** Extension path for MCA “future work” slide.

**Limits:** Not present in repo — describe as roadmap only.

**Related:** `alerting/adapters/base.py`

---

### Q40. Does R8 block or allow mitigation?

**Neither** — observability only.

**Purpose:** Fail-isolation — alerting errors must not affect OpenFlow loop.

**Implementation:** Broad try/except in `process_verification`; ERROR disposition.

**Runtime:** Mitigation already decided by R7 before R8 invoked.

**Related:** [R7_QNA.md](06_R7_QNA.md)

---

## Performance & Concurrency

### Q41. Is alerting on the controller hot path?

**Invoked each cycle but designed lightweight** — factory + in-memory dedup/limit + append JSONL.

**Purpose:** Sub-millisecond policy in perf tests.

**Implementation:** `tests/test_alerting_perf_r85.py`.

**Runtime:** Dominated by verification + ML — not R8.

**Related:** `RUNTIME_FLOW.md`

---

### Q42. Why threading locks in dedup/rate limit?

**Purpose:** Dashboard/API may read JSONL while controller appends; dedup state may be shared if manager singleton.

**Implementation:** `threading.Lock` in bounded structures.

**Runtime:** OsKen cooperative model still benefits from defensive locking for API thread.

**Related:** `alerting/dedup.py`

---

### Q43. What are R8 metrics counters?

**Examples:** `alerts_received`, `alerts_created`, `alerts_skipped`, `alerts_deduplicated`, `alerts_rate_limited`, `manager_failures`.

**Purpose:** Lightweight introspection without Prometheus (**Not implemented**).

**Implementation:** `AlertMetrics` in `alerting/metrics.py`.

**Related:** `alerting/manager.py`

---

## Examples & Troubleshooting

### Q44. Why zero security alerts after 30-minute lab run?

**Likely causes:**
1. Never reached VERIFIED (confidence gate — try `INTELLISHIELD_OPS_PROFILE=lab`)
2. Alerting disabled in config
3. All alerts deduplicated/rate-limited (check metrics/logs)
4. Wrong API endpoint (`/api/alerts` vs `/api/security-alerts`)

**Related:** `TROUBLESHOOTING.md`, [R7_QNA.md](06_R7_QNA.md) Q34

---

### Q45. Live lab observation (reference)

**Documented run (`20260728T181121Z`):** **5** R8 alerts observed when VERIFIED cycles occurred.

**Purpose:** Proof that pipeline works when gates pass — not a guaranteed count per scenario.

**Related:** [R8_ALERTING.md](../../02_Novelties/07_R8_Alerting.md)

---

### Q46. Example alert types mapped from verification

| Condition | `AlertType` |
|-----------|-------------|
| `mitigation_eligible=True` | **MITIGATION** |
| VERIFIED/PENDING/INELIGIBLE (non-eligible) | **DETECTION** |
| Other | **SYSTEM** |

**Purpose:** Dashboard filtering by type.

**Implementation:** `map_alert_type()` in factory.

**Related:** `alerting/factory.py`

---

### Q47. How to enable PENDING alerts for debugging?

**Set** `AlertingConfig(alert_on_pending=True)` in runtime wiring or test fixture.

**Purpose:** Observe emerging attacks before streak confirmation.

**Trade-off:** Noise during borderline fusion cycles.

**Related:** Q8

---

## Cross-Plane & Design

### Q48. How does R8 relate to R5 RCA?

**Purpose:** Optional cross-link via `rca_report_id` on `AlertEvent`.

**Implementation:** `AlertFactoryContext.rca_report_id` when RCA runs same cycle.

**Runtime:** RCA JSONL separate — `GET /api/root-cause-reports`.

**Related:** [R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md)

---

### Q49. How does R8 relate to Foundation `AlertEvent`?

**Purpose:** R8 is first consumer/producer of unified alert DTO.

**Reason:** Foundation defined schema; R8 implements lifecycle.

**Serialization:** Roundtrip via `shared_contracts/serialize.py`.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md)

---

### Q50. R8 vs R7 duplicate prevention — who owns what?

| Concern | Owner |
|---------|-------|
| Re-block same attacker OpenFlow | Mitigation blocklist |
| Re-alert same incident | R8 dedup |
| Re-verify same cycle | N/A — one verify per poll |

**Purpose:** Clear responsibility boundaries for viva.

**Related:** [R7_QNA.md](06_R7_QNA.md) Q25

---

## Configuration Summary

### Q51. Default `AlertingConfig` quick reference

| Knob | Default |
|------|---------|
| `enabled` | True |
| `alert_on_pending` | False |
| `alert_on_ineligible` | False |
| `alert_on_rejected` | False |
| `severity_critical_confidence` | 0.90 |
| `severity_high_confidence` | 0.75 |
| `dedup_window_sec` | 60.0 |
| `dedup_max_keys` | 256 |
| `rate_limit_per_window` | 30 |
| `rate_limit_window_sec` | 60.0 |
| `rate_limit_max_keys` | 256 |
| `dispatch_enabled` | True |
| `default_source` | `"verification"` |

**Related:** `alerting/config.py`, [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md)

---

*Minimum 35 questions covered (51 provided). For verification gates see [R7_QNA.md](06_R7_QNA.md). For evaluation artifacts see [P0_QNA.md](02_P0_QNA.md).*
