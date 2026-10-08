# IntelliShield SDN Release 1.0 — Deep Q&A

**Scope:** Cross-cutting questions for viva, handover, and onboarding.  
**Constraint:** Facts reflect the **current repository only**. Unimplemented items are stated explicitly.  
**Related:** [README.md](README.md) · `GLOSSARY.md` · `../../../RUNTIME_FLOW.md`

> **PROJECT_DOCS copy** — adapted from `QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## General

### G-01. What is IntelliShield SDN Release 1.0?

**Definition:** A monolithic Python research stack for collaborative DDoS detection and mitigation on a Mininet/OsKen SDN laboratory.

**Purpose:** Deliver a laboratory-complete pipeline from traffic sensing through detection, correlation, fusion, verification, mitigation, RCA, and alerting with live evidence.

**Reason:** MCA/IEEE research requires an end-to-end demonstrable system—not isolated detector scripts—with reproducible acceptance artifacts.

**Implementation summary:** Single OpenFlow application (`controller/flow_monitor.py`) orchestrates optional planes (R4–R8), entropy/ML detectors, mitigation, and a FastAPI dashboard on port 8080.

**Runtime behaviour:** Controller polls switch stats ~every 5 s; planes append CSV/JSONL logs; dashboard reads logs for API/UI.

**Advantages:** One VM deploy; clear requirement mapping; documented acceptance run `20260728T181121Z`.

**Limitations:** Internet-edge production is **not claimed**; lab production-demo readiness ~92/100.

**Related modules:** `controller/`, `entropy_engine/`, `ml_models/`, `correlation/`, `fusion/`, `verification/`, `mitigation/`, `rca/`, `alerting/`, `dashboard/`.

**Related documents:** `../../../RELEASE_1.0.md`, [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md), [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Best practices:** Start onboarding at `GLOSSARY.md` → this file → requirement-specific QnA (R4–R8).

**Future improvements:** Formal CI coverage gate; external alert channels (**Not implemented**).

---

### G-02. Which requirements are in scope for Release 1.0?

**Definition:** The accepted Definition of Done (DoD) for the release artifact.

**Purpose:** Prevent viva/handover confusion about what is delivered versus deferred.

**Reason:** Historical roadmap docs (`PROJECT_STATE.json`) may be stale; Release 1.0 suite is canonical.

**Implementation summary:** Foundation, P0.1–P0.6, R4, R5, R6, R7, R8 are **COMPLETE (lab live)**. R2 is **Not implemented**. R3 live twin fidelity is **out of Release 1.0 DoD**. R1/R9 are **out of current project scope**.

**Runtime behaviour:** Only implemented planes execute; missing planes degrade gracefully via fail-isolation.

**Advantages:** Explicit scope boundary supports honest research claims.

**Limitations:** Twin code under `twin/` exists but is not acceptance-gated for R1.0.

**Related modules:** All R4–R8 packages; `shared_contracts/`; `twin/` (deferred).

**Related documents:** `../../../RELEASE_1.0.md`, [README.md](README.md)

**Best practices:** Cite Release 1.0 suite—not older gap-analysis rows—for acceptance status.

**Future improvements:** Dedicated R3 acceptance manual when twin fidelity enters DoD.

---

### G-03. What problem does IntelliShield solve in the lab?

**Definition:** Online DDoS detection and verified mitigation on a software-defined network with explainable, auditable decisions.

**Purpose:** Bridge the gap between single-detector prototypes and a multi-stage collaborative defense pipeline.

**Reason:** DDoS defense requires sensing, corroboration, gating before actuation, and operator-facing explanation—not a lone ML score.

**Implementation summary:** Entropy + ML detect; R4 correlates; R6 fuses; R7 verifies; mitigation installs OpenFlow DROP; R5 explains; R8 alerts.

**Runtime behaviour:** Attack scenarios S2–S5 trigger fusion ATTACK decisions; R7 VERIFIED cycles authorize blocks when confidence gate passes.

**Advantages:** Full evidence chain in JSONL logs for thesis evaluation.

**Limitations:** Mininet emulation ≠ datacenter traffic realism.

**Related modules:** `traffic_generator/`, `controller/flow_monitor.py`, R4–R8 packages.

**Related documents:** `../../../RUNTIME_FLOW.md`, [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Best practices:** Always pair detection metrics with verification and mitigation outcomes.

**Future improvements:** R3 digital twin for pre-deployment simulation (**out of R1.0 DoD**).

---

### G-04. Who is the intended audience for this knowledge base?

**Definition:** Stakeholders consuming `` without tribal knowledge.

**Purpose:** Support developer onboarding, MCA viva, IEEE paper consistency, and operator handover.

**Reason:** Engineering docs under `` describe *how*; KB answers *why* and cross-cutting *what if*.

**Implementation summary:** README indexes FAQ, QNA, requirement QnA files, design/architecture decisions, glossary.

**Runtime behaviour:** N/A (documentation artifact).

**Advantages:** Reduces single-person dependency for project explanation.

**Limitations:** Does not replace install scripts or full API schema dumps.

**Related modules:** N/A

**Related documents:** [README.md](README.md), `DESIGN_DECISIONS.md`, `ARCHITECTURE_DECISIONS.md`

**Best practices:** Viva prep: GLOSSARY → ARCHITECTURE_DECISIONS → requirement QnA → RUNTIME_FLOW.

**Future improvements:** KNOWLEDGE_BASE_SUMMARY generation report (**referenced in README**).

---

### G-05. What is the difference between "lab production-demo" and "internet-edge production"?

**Definition:** Two distinct readiness claims used in Release 1.0 documentation.

**Purpose:** Prevent over-claiming deployment maturity in viva or papers.

**Reason:** The stack is research-validated on Ubuntu VM + Mininet, not hardened for public internet edges.

**Implementation summary:** Lab readiness ~92/100 with `INTELLISHIELD_OPS_PROFILE=lab`; research prototype readiness ~94/100. No dashboard auth, no external alert dispatch, pickle model trust model.

**Runtime behaviour:** Lab profile freezes RL confidence gate at 60% for reproducible demos.

**Advantages:** Honest scoping strengthens academic credibility.

**Limitations:** Operators must not assume enterprise SLA or multi-tenant security.

**Related modules:** `shared_contracts/ops_profile.py`, `dashboard/api.py`, `alerting/`

**Related documents:** `../../../RELEASE_1.0.md`, [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md)

**Best practices:** Use "lab production-demo" in presentations; reserve "production" for ops profile naming only.

**Future improvements:** Sudoers-based dashboard control instead of `INTELLISHIELD_SUDO_PASS`.

---

### G-06. Why is Redis/Postgres not used?

**Definition:** Architectural choice to avoid external datastore dependencies.

**Purpose:** Simplify lab deployment and experiment reproducibility.

**Reason:** Append-only JSONL and CSV artifacts suffice for thesis-scale telemetry without DB ops overhead.

**Implementation summary:** R4–R8 persist to `logs/*.jsonl`; flow/entropy/ML to CSV. Dashboard reads bounded file tails.

**Runtime behaviour:** Each cycle appends one JSONL line per plane; no pub/sub or cache layer.

**Advantages:** Grep-able logs; easy experiment bundles; zero infra beyond VM disk.

**Limitations:** Large files need archival; no cross-run query engine without external tools.

**Related modules:** `correlation/persistence.py`, `fusion/persistence.py`, `verification/trace.py`, `alerting/persistence.py`

**Related documents:** `ARCHITECTURE_DECISIONS.md`, [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md)

**Best practices:** Archive `logs/live_vm_*` after acceptance runs; use `evaluation/experiment_bundle.py` for packaging.

**Future improvements:** Optional SQLite for dashboard queries (**Not implemented**).

---

### G-07. What is the canonical documentation location?

**Definition:** The authoritative Markdown suite for Release 1.0 handover.

**Purpose:** Avoid confusion from historical docs under `*.md`, `IMPLEMENTED/`, `PROJECT_DOCS/`.

**Reason:** Documentation-only pass centralized 18 engineering docs under ``.

**Implementation summary:** KB is additive at ``; does not replace engineering suite.

**Runtime behaviour:** N/A

**Advantages:** Single navigation path for new developers.

**Limitations:** ~70% consolidation of older materials—not all rewritten.

**Related modules:** N/A

**Related documents:** `../../../DOCUMENTATION_SUMMARY.md`, `../../../README.md`

**Best practices:** Link to `../../../` for ops detail; KB for *why* questions.

**Future improvements:** Deprecation banners on stale roadmap files.

---

### G-08. What acceptance evidence exists for Release 1.0?

**Definition:** Recorded test and live-run results supporting the release gate.

**Purpose:** Defensible claims in viva and IEEE submissions.

**Reason:** Research prototypes require both automated tests and live Mininet validation.

**Implementation summary:** Scoped pytest **491 passed**; `verify_phase7` **60/61** (script drift on conf default); live S1–S5 **PASS** run `20260728T181121Z` with R7 VERIFIED 6, SUCCESS blocks 4, R8 alerts 5, R5 RCA 6.

**Runtime behaviour:** Artifacts under `logs/live_vm_20260728T181121Z/`.

**Advantages:** Quantitative, reproducible acceptance numbers.

**Limitations:** One primary live reference run documented; occasional duplicate `fusion_id` lines.

**Related modules:** `tests/`, `traffic_generator/`, `scripts/compute_metrics.py`

**Related documents:** `../../../RELEASE_1.0.md`, [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md)

**Best practices:** Re-run `--all` scenarios with `INTELLISHIELD_OPS_PROFILE=lab` before demos.

**Future improvements:** Align `verify_phase7.py` with ops profile default 0.60.

---

### G-09. What is P0 hardening and why does it precede R4–R8?

**Definition:** P0.1–P0.6 fixes for RL observation scale, scenario semantics, experiment windows, mitigation strategy, bundles, and IEEE metrics.

**Purpose:** Ensure evaluation truthfulness before building collaborative planes on top.

**Reason:** Silent metric/RL bugs invalidate research conclusions even if R4–R8 logic is correct.

**Implementation summary:** Fixes in `rl_engine/`, `traffic_generator/`, `evaluation/`, `mitigation/`, `scripts/compute_metrics.py` with dedicated pytest modules.

**Runtime behaviour:** All P0 behaviors active in default controller/mitigation/RL/eval paths.

**Advantages:** Stable ground-truth joins for S1–S5 evaluation windows.

**Limitations:** P0 does not add new detection planes—only hardens existing paths.

**Related modules:** `rl_engine/rl_env.py`, `evaluation/experiment_windows.py`, `mitigation/mitigation_engine.py`

**Related documents:** [P0_QNA.md](02_P0_QNA.md), [../../02_Novelties/02_P0_Hardening.md](../../02_Novelties/02_P0_Hardening.md)

**Best practices:** Run P0 test modules after any RL or scenario timing change.

**Future improvements:** Automate experiment bundle on every live run.

---

### G-10. How does IntelliShield relate to the nine-requirement roadmap?

**Definition:** Mapping between master roadmap IDs (R1–R9, Foundation, P0) and Release 1.0 delivery.

**Purpose:** Answer "where is R2?" or "is R3 done?" without ambiguity.

**Reason:** Roadmap breadth exceeds Release 1.0 DoD; explicit status prevents invented features.

**Implementation summary:** Delivered: Foundation, P0, R4–R8. Deferred/out: R2 (**Not implemented**), R3 live fidelity (**out of DoD**), R1/R9 (**out of scope**).

**Runtime behaviour:** Reserved enum types for R2 exist in `shared_contracts` but no SSL detector runs.

**Advantages:** Contracts reserve extension hooks without false implementation claims.

**Limitations:** Interviewers may ask about R2/R3—must answer honestly.

**Related modules:** `shared_contracts/enums.py` (DetectorType placeholders), `twin/`

**Related documents:** [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md), `../../../RELEASE_1.0.md`

**Best practices:** Use RESEARCH_JUSTIFICATION for novelty scoped to delivered requirements.

**Future improvements:** R2 SSL collaborative detector implementation.

---

## Architecture

### A-01. What is the high-level system architecture?

**Definition:** A layered monolith: Mininet fabric → OsKen controller → detection/collaboration planes → logs → FastAPI dashboard.

**Purpose:** Provide a teachable, deployable SDN security stack on one Ubuntu VM.

**Reason:** Microservices add ops burden inappropriate for MCA lab constraints.

**Implementation summary:**

```
┌──────────────────────────────────────────────────────────────┐
│                     Ubuntu Lab VM                            │
│  ┌────────────┐   OF1.3:6653   ┌─────────────┐               │
│  │  Mininet   │◄──────────────►│ flow_monitor│               │
│  │  h1..h5+s1 │                │  (OsKen)    │               │
│  └─────┬──────┘                └──────┬──────┘               │
│        │ traffic_scheduler            │ entropy│ML│R4│R6│R7 │
│        │                              ▼                      │
│        │                         logs/*.csv|jsonl            │
│        └────────────────────► dashboard/api :8080            │
└──────────────────────────────────────────────────────────────┘
```

**Runtime behaviour:** Single controller process on port 6653; dashboard separate on 8080.

**Advantages:** Matches teaching lab simplicity; one sync target Mac→VM.

**Limitations:** Not horizontally scaled; single point of failure for control plane.

**Related modules:** `controller/flow_monitor.py`, `dashboard/api.py`, `traffic_generator/`

**Related documents:** [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md), `ARCHITECTURE_DECISIONS.md`

**Best practices:** Ensure only one controller binds 6653 before live runs.

**Future improvements:** Optional controller HA (**Not implemented**).

---

### A-02. Why is the controller the orchestrator rather than a distributed mesh?

**Definition:** `controller/flow_monitor.py` owns OpenFlow I/O and invokes optional planes each poll cycle.

**Purpose:** Centralize SDN event loop and stage ordering (R4 → R6 → R7 → mitigate → R5/R8).

**Reason:** OsKen application model naturally hosts orchestration; planes are libraries not separate services.

**Implementation summary:** Optional imports with runtime guards; `safe_*` wrappers for fail-isolation.

**Runtime behaviour:** Missing plane → degraded path (e.g., legacy `handle_alert` without R7).

**Advantages:** Deterministic pipeline order; easy step-through debugging.

**Limitations:** Controller memory/CPU bounds all planes; no independent scaling.

**Related modules:** `controller/flow_monitor.py`, `correlation/runtime.py`, `fusion/runtime.py`, `verification/runtime.py`

**Related documents:** `../../../RUNTIME_FLOW.md`, `DESIGN_DECISIONS.md`

**Best practices:** Never block OpenFlow handler on slow plane logic—keep cycle work lightweight.

**Future improvements:** Async plane dispatch with backpressure (**Not implemented**).

---

### A-03. What does "shared_contracts as leaf" mean architecturally?

**Definition:** `shared_contracts/` must not import controller, ML, mitigation, or other application packages.

**Purpose:** Provide typed DTOs and enums without circular dependencies.

**Reason:** Multiple planes serialize to JSONL; one vocabulary prevents schema drift.

**Implementation summary:** `enums.py`, `models.py`, `serialize.py`, `ops_profile.py`; `schema_version = "1.0"`.

**Runtime behaviour:** Planes import contracts; controller never imported by contracts.

**Advantages:** Dashboard, RCA, and engines share `VerificationResult`, `FusedDecision`, etc.

**Limitations:** Passive data shapes—not an event bus or validation framework at runtime.

**Related modules:** `shared_contracts/` (all modules)

**Related documents:** [FOUNDATION_QNA.md](01_Foundation_QNA.md), [../../02_Novelties/01_Foundation.md](../../02_Novelties/01_Foundation.md)

**Best practices:** Add new cross-plane fields to contracts before persisting to JSONL.

**Future improvements:** JSON Schema export from dataclasses (**Not implemented**).

---

### A-04. How do detection, collaboration, gate, and actuation layers relate?

**Definition:** Layered responsibility split per Release 1.0 architecture table.

**Purpose:** Separate concerns: sense → detect → correlate → fuse → verify → act → explain → notify.

**Reason:** Each layer maps to a research requirement with independent testability.

**Implementation summary:**

```
entropy_engine ──┐
ml_models ───────┼──► correlation (R4 advisory)
                 │         │
                 └────────► fusion (R6 authoritative score)
                               │
                               ▼
                        verification (R7 gate)
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         mitigation          rca/xai (R5)   alerting (R8)
```

**Runtime behaviour:** R4 never alone authorizes DROP; R7 must VERIFIED for mitigation when enabled.

**Advantages:** Clear viva narrative: evidence before action.

**Limitations:** Layer boundaries are logical—same Python process.

**Related modules:** All plane packages listed above.

**Related documents:** [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md), [R4_QNA.md](04_R4_QNA.md), [R6_QNA.md](05_R6_QNA.md), [R7_QNA.md](06_R7_QNA.md)

**Best practices:** Document which layer owns a decision in RCA `contributing_signals`.

**Future improvements:** Formal layer interface protocols.

---

### A-05. Why is R4 advisory-only while R6 is authoritative for fusion?

**Definition:** R4 produces co-occurrence scores; R6 produces fused ATTACK/SUSPICIOUS/NORMAL decisions for R7.

**Purpose:** Prevent correlation alone from triggering false mitigations.

**Reason:** Correlation boosts evidence but lacks verification stages; premature DROP is worse than delayed DROP.

**Implementation summary:** R4 → `correlation_results.jsonl`; R6 consumes detector + optional R4 support → `fused_decisions.jsonl`.

**Runtime behaviour:** High R4 score without R6 ATTACK + R7 VERIFIED → no DROP.

**Advantages:** Fail-safe against single-signal correlation spikes.

**Limitations:** Operators must understand two-stage collaboration model.

**Related modules:** `correlation/engine.py`, `fusion/engine.py`, `fusion/evidence.py`

**Related documents:** [R4_QNA.md](04_R4_QNA.md), [R6_QNA.md](05_R6_QNA.md), [../../02_Novelties/03_R4_Correlation.md](../../02_Novelties/03_R4_Correlation.md)

**Best practices:** Never wire R4 output directly to mitigation dispatch.

**Future improvements:** Configurable R4 weight caps in fusion registry.

---

### A-06. What is the dependency flow between packages?

**Definition:** Allowed import direction: contracts ← planes ← controller; dashboard → logs only.

**Purpose:** Enforce acyclic module graph.

**Reason:** Circular imports break optional-plane loading and testing.

**Implementation summary:**

```
shared_contracts  ◄──  correlation / fusion / verification / alerting / rca / xai
controller        ──►  all of the above (optional)
dashboard         ──►  logs + evaluation helpers (not OF control)
```

**Forbidden:** `shared_contracts` importing `controller`, `ml_models`, `mitigation`.

**Runtime behaviour:** Violations would surface at import time during development.

**Advantages:** Clean pytest isolation per package.

**Limitations:** No compile-time enforcement beyond tests and discipline.

**Related modules:** Entire repo package tree.

**Related documents:** `../../../PROJECT_STRUCTURE.md`, `ARCHITECTURE_DECISIONS.md`

**Best practices:** Run `tests/test_shared_contracts_foundation.py` after contract changes.

**Future improvements:** Import-linter in CI (**Not implemented**).

---

### A-07. How does fail-isolation work at the architecture level?

**Definition:** Each optional plane wraps errors so OpenFlow polling continues.

**Purpose:** Control-plane continuity outweighs perfect telemetry.

**Reason:** Lab demos and live runs must survive one broken plane.

**Implementation summary:** `safe_correlate_cycle`, fusion disable via env, R7 errors → INELIGIBLE, R5/R8 isolated on verified callback.

**Runtime behaviour:**

| Plane | Failure behaviour |
|-------|-------------------|
| R4 | Logged; advisory skipped |
| R6 | Legacy dual-path if disabled/missing |
| R7 | INELIGIBLE or legacy `handle_alert` |
| R5/R8 | One may fail without blocking mitigation |

**Advantages:** Resilient live demonstrations.

**Limitations:** Silent degradation unless operator reads logs.

**Related modules:** `correlation/runtime.py`, `fusion/runtime.py`, `verification/runtime.py`, `rca/runtime.py`, `alerting/runtime.py`

**Related documents:** [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md), `../../../TROUBLESHOOTING.md`

**Best practices:** Monitor JSONL file growth each scenario—stalled files indicate plane failure.

**Future improvements:** Health endpoint exposing plane status (**partial via dashboard**).

---

### A-08. What artifacts connect planes to the dashboard?

**Definition:** CSV and JSONL log files under `logs/` consumed by FastAPI routes.

**Purpose:** Decouple observation from control plane.

**Reason:** Dashboard must not import OsKen or install flows.

**Implementation summary:**

| Artifact | Writer | Consumer |
|----------|--------|----------|
| `flow_stats.csv` | controller | dashboard, ML |
| `correlation_results.jsonl` | R4 | dashboard, R5/R8 refs |
| `fused_decisions.jsonl` | R6 | R7, dashboard |
| `verification_trace.jsonl` | R7 | metrics, audits |
| `root_cause_reports.jsonl` | R5 | dashboard |
| `alerts.jsonl` | R8 | dashboard |

**Runtime behaviour:** Dashboard bounded reads; live tail for demos.

**Advantages:** Simple integration tests via TestClient + fixture logs.

**Limitations:** No real-time WebSocket push (**Not implemented** as primary model).

**Related modules:** `dashboard/api.py`, plane persistence modules.

**Related documents:** [../../04_Implementation/06_APIs.md](../../04_Implementation/06_APIs.md), `../../../RUNTIME_FLOW.md`

**Best practices:** Rotate/archive large JSONL before long `--all` runs.

**Future improvements:** SSE or WebSocket log streaming.

---

### A-09. Why FastAPI for the dashboard instead of embedding in the controller?

**Definition:** Separate `dashboard/api.py` HTTP service on port 8080.

**Purpose:** Observation layer independent of OpenFlow event loop.

**Reason:** Blocking HTTP in OsKen handler would stall stats polling.

**Implementation summary:** Sync FastAPI; OpenAPI at `/docs`; TestClient tests with `httpx`.

**Runtime behaviour:** Two processes: `osken-manager controller/flow_monitor.py` + `python3 dashboard/api.py`.

**Advantages:** Easy API testing; automatic schema docs.

**Limitations:** No built-in HTTP authentication (**Not implemented**).

**Related modules:** `dashboard/api.py`, `dashboard/readers.py`

**Related documents:** `ARCHITECTURE_DECISIONS.md`, [../../04_Implementation/06_APIs.md](../../04_Implementation/06_APIs.md)

**Best practices:** Do not expose dashboard :8080 to untrusted networks.

**Future improvements:** OAuth2 or API key gate.

---

### A-10. What extension points exist without breaking the leaf contract?

**Definition:** Registry and adapter hooks for new detectors, alert channels, and reserved detector types.

**Purpose:** Future R2 SSL or additional sensors without rewiring core pipeline.

**Reason:** Research roadmap extends beyond Release 1.0 DoD.

**Implementation summary:** `fusion/registry.py`, `fusion/adapters.py`, `alerting/adapters/`; `DetectorType` enum reserves SSL (**R2 Not implemented**).

**Runtime behaviour:** New adapter registers with fusion; R4 builds signals from categories.

**Advantages:** Additive extension without monolithic edits.

**Limitations:** Twin live DoD (**out of R1.0**); R2 has types only.

**Related modules:** `fusion/registry.py`, `alerting/adapters/`, `shared_contracts/enums.py`

**Related documents:** `../../../DEVELOPER_GUIDE.md`, [FUTURE section in ../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md)

**Best practices:** Implement contract DTOs first; add pytest before controller wiring.

**Future improvements:** R2 SSL detector; R3 twin live fidelity acceptance.

---

## Runtime

### RT-01. What is the end-to-end runtime pipeline order?

**Definition:** Ordered stages from traffic injection to dashboard observation per poll cycle (~5 s).

**Purpose:** Single reference path for operators and viva explanation.

**Reason:** Stage order encodes safety policy: fuse before verify, verify before DROP, explain/alert after verify.

**Implementation summary:**

```
Traffic Generator → Flow Monitor → Feature Extraction
      → Entropy + ML Detection → R4 (JSONL) → R6 (JSONL)
      → R7 (JSONL) → [VERIFIED] → Mitigation (DROP)
      → R5 RCA + R8 Alerts → Dashboard
```

**Runtime behaviour:** INELIGIBLE/PENDING → no DROP; monitoring continues.

**Advantages:** Documented in RUNTIME_FLOW with live reference metrics.

**Limitations:** Legacy path skips R6/R7 when disabled/missing.

**Related modules:** `controller/flow_monitor.py`, all R4–R8 runtime modules.

**Related documents:** `../../../RUNTIME_FLOW.md`

**Best practices:** Trace one attack cycle through all JSONL files for debugging.

**Future improvements:** Unified cycle correlation ID across all artifacts.

---

### RT-02. What happens during a single OsKen poll cycle?

**Definition:** One iteration of stats request/reply and downstream plane invocation.

**Purpose:** Explain timing and warm-up behaviour.

**Reason:** DDoS detection is windowed; decisions accumulate across cycles.

**Implementation summary:** Controller requests flow/port stats → builds features → runs detectors → R4 → R6 (if enabled) → R7 → optional mitigation → R5/R8 on verified callback.

**Runtime behaviour:** Monitor interval ~**5 seconds**; warm-up **3** cycles; attack confirm **2** consecutive attack-like cycles.

**Advantages:** Predictable demo timing for scenario narration.

**Limitations:** 5 s granularity misses sub-second bursts without additional sampling.

**Related modules:** `controller/flow_monitor.py`, `verification/confirmation_state.py`

**Related documents:** `../../../RUNTIME_FLOW.md`, [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md)

**Best practices:** Wait for warm-up completion before scoring detection latency.

**Future improvements:** Configurable poll interval via env (**partially in constants**).

---

### RT-03. How does R6 owning the cycle prevent double verification?

**Definition:** When `INTELLISHIELD_R6_FUSION=1`, duplicate ML→R7 dispatch is suppressed.

**Purpose:** Avoid two verification traces and conflicting mitigation triggers for one cycle.

**Reason:** Legacy path ran entropy and ML each toward R7 independently.

**Implementation summary:** Fusion aggregates detector opinions → single `FusedDecision` → R7 adapter.

**Runtime behaviour:** R6 disabled (`=0`) → legacy dual-path entropy/ML → R7/mitigation.

**Advantages:** One authoritative fused confidence for R7 confidence gate.

**Limitations:** Misconfigured disable may resurrect duplicate paths.

**Related modules:** `fusion/runtime.py`, `fusion/r7_adapter.py`, `controller/flow_monitor.py`

**Related documents:** [R6_QNA.md](05_R6_QNA.md), [../../02_Novelties/04_R6_Collaborative_Detection.md](../../02_Novelties/04_R6_Collaborative_Detection.md)

**Best practices:** Keep R6 enabled for Release 1.0 demos unless testing legacy parity.

**Future improvements:** Explicit cycle ownership flag in verification trace.

---

### RT-04. What are R7 verification stages and terminal statuses?

**Definition:** Ordered gate from warm-up through attacker identification to VERIFIED/INELIGIBLE/PENDING.

**Purpose:** Mitigation safety gate—detection ≠ authorization.

**Reason:** False positives must not install DROP rules without corroboration and confidence.

**Implementation summary:**

```
WARMUP → DETECTION_EVIDENCE → ATTACK_CONFIRMATION
  → CONFIDENCE_GATE → ATTACKER_IDENTIFY → AUTO_MITIGATE_POLICY
  → VERIFIED | PENDING | INELIGIBLE | REJECTED
```

**Runtime behaviour:** Exceptions fail-closed to **INELIGIBLE**; `mitigation_eligible=True` only on VERIFIED under policy.

**Advantages:** Auditable JSONL trace per stage in `verification_trace.jsonl`.

**Limitations:** Many cycles INELIGIBLE by design when confidence gate fails.

**Related modules:** `verification/engine.py`, `verification/stages.py`, `verification/trace.py`

**Related documents:** [R7_QNA.md](06_R7_QNA.md), [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md)

**Best practices:** Interpret INELIGIBLE as safety success, not necessarily system failure.

**Future improvements:** Dashboard stage breakdown widget.

---

### RT-05. When does mitigation install OpenFlow DROP rules?

**Definition:** Actuation via `mitigation/` after R7 VERIFIED (or legacy `handle_alert` when R7 missing).

**Purpose:** Block attacker flow pairs or source MAC with timeout.

**Reason:** Verified eligibility aligns blocks with policy and confidence.

**Implementation summary:** FLOW_PAIR or SRC_MAC DROP; `mitigation_actions.csv`; skip if already blocked; expire on flow removed.

**Runtime behaviour:** P0.4 strategy selection from attack hints; RL threshold adapter injects confidence bounds.

**Advantages:** Idempotent block attempts; unblock on flow expiry.

**Limitations:** OpenFlow rules are lab-scale—not hardware ACL tables.

**Related modules:** `mitigation/mitigation_engine.py`, `rl_engine/`, `verification/runtime.py`

**Related documents:** `../../../RUNTIME_FLOW.md`, [P0_QNA.md](02_P0_QNA.md)

**Best practices:** Confirm SUCCESS entries in `mitigation_actions.csv` after live runs.

**Future improvements:** Rate-limited block list sync to hardware offload (**Not implemented**).

---

### RT-06. Why do R5 and R8 run after verification, not after raw detection?

**Definition:** R5 RCA and R8 alerts attach to **verified** events via `safe_enrich_verified_event` and `safe_emit_verification_alert`.

**Purpose:** Explain and notify only authorized outcomes—align alerts with policy.

**Reason:** Alerting on every ML spike would flood operators; RCA needs stable evidence chain.

**Implementation summary:** R5 → `root_cause_reports.jsonl`; R8 → `alerts.jsonl` with severity, dedup, optional RCA refs.

**Runtime behaviour:** R5 error logged—alert may still emit; R8 error logged—mitigation already independent.

**Advantages:** Fail-isolated post-verify enrichment.

**Limitations:** No alert on PENDING/INELIGIBLE by default (`alerting/config.py`).

**Related modules:** `rca/runtime.py`, `xai/`, `alerting/runtime.py`

**Related documents:** [R5_QNA.md](07_R5_XAI_QNA.md), [R8_QNA.md](08_R8_QNA.md), [../../02_Novelties/06_R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md)

**Best practices:** Cross-reference R8 `rca_report_id` with R5 JSONL for viva walkthrough.

**Future improvements:** External Slack/email dispatch (**Not implemented**).

---

### RT-07. What is the happy-path ASCII sequence for an attack cycle?

**Definition:** Temporal interaction between scheduler, switch, controller, planes, and dashboard.

**Purpose:** Viva-ready narrative of live SYN flood mitigation.

**Reason:** Sequence diagrams clarify concurrency vs pipeline order.

**Implementation summary:**

```
Scheduler    Switch/OVS      Controller       R6/R7/Mitig      Logs/Dash
   │             │               │                 │               │
   │ launch SYN  │               │                 │               │
   │────────────►│               │                 │               │
   │             │ stats reply   │                 │               │
   │             │──────────────►│                 │               │
   │             │               │ fuse ATTACK   │               │
   │             │               │──────────────►│               │
   │             │               │ verify VERIFIED               │
   │             │               │──────────────►│               │
   │             │               │ install DROP  │               │
   │             │◄──────────────│◄──────────────│               │
   │             │               │ RCA + alert   │──────────────►│
   │             │               │               │               │ GET /api/*
```

**Runtime behaviour:** Matches live run `20260728T181121Z` outcomes.

**Advantages:** Handover artifact for non-developer stakeholders.

**Limitations:** Simplified—does not show warm-up cycles or INELIGIBLE retries.

**Related modules:** Full stack.

**Related documents:** `../../../RUNTIME_FLOW.md`

**Best practices:** Replay S2 scenario while tailing JSONL files in parallel terminals.

**Future improvements:** Automated sequence capture in experiment bundle.

---

### RT-08. How do traffic scenarios S1–S5 drive runtime behaviour?

**Definition:** Lab ground-truth scenarios from `traffic_generator/traffic_scheduler.py`.

**Purpose:** Reproducible normal and attack traffic for evaluation.

**Reason:** Metrics require labeled attack windows (P0.3 experiment windows).

**Implementation summary:** S1 normal · S2 SYN · S3 UDP · S4 burst · S5 mixed; logs to `scenario_logs.csv`, `attack_logs.csv`.

**Runtime behaviour:** `--scenario N` or `--all`; START/ATTACK_*/END timestamps define ground truth.

**Advantages:** Standard benchmark suite for acceptance and papers.

**Limitations:** Requires sudo/Mininet; Mac dev typically syncs to Ubuntu VM.

**Related modules:** `traffic_generator/traffic_scheduler.py`, `traffic_generator/attack_scenarios.py`

**Related documents:** [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md), `../../../RUNTIME_FLOW.md`

**Best practices:** Run S1 first to establish false-positive baseline before attack scenarios.

**Future improvements:** Containerized traffic gen without sudo (**Not implemented**).

---

### RT-09. How does INTELLISHIELD_OPS_PROFILE affect runtime gating?

**Definition:** Lab vs production ops profile controlling RL confidence gate behaviour.

**Purpose:** Separate reproducible demos from adaptive RL bounds.

**Reason:** Frozen gate stabilizes viva demos; production profile allows RL adaptation within clamps.

**Implementation summary:** `lab`/`demo`/`dev` → freeze at **60%**; `production` (default) → adaptive **55–75%** with default 0.60.

**Runtime behaviour:** `shared_contracts/ops_profile.py` read by RL/mitigation; evidence from live run with `lab` profile.

**Advantages:** One env var toggles demo vs adaptive behaviour.

**Limitations:** "Production" profile ≠ internet-edge product; naming is ops-oriented.

**Related modules:** `shared_contracts/ops_profile.py`, `rl_engine/`, `mitigation/`

**Related documents:** [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md), `GLOSSARY.md`

**Best practices:** Export `INTELLISHIELD_OPS_PROFILE=lab` before acceptance live runs.

**Future improvements:** Align `verify_phase7.py` assertion with profile default.

---

### RT-10. What happens when a plane fails at runtime?

**Definition:** Degraded-mode behaviour preserving OpenFlow polling.

**Purpose:** Operational resilience during partial outages.

**Reason:** Research demos must not crash controller on one ImportError.

**Implementation summary:**

| Failure | Behaviour |
|---------|-----------|
| Entropy/ML missing | Plane disabled |
| R6 disabled | Legacy paths |
| R7 missing | Legacy `handle_alert` |
| R7 INELIGIBLE | No DROP; continue |
| R5/R8 error | Logged; peer may succeed |

**Runtime behaviour:** OpenFlow continuity; fail-open control, fail-closed mitigation.

**Advantages:** Matches architecture fail-isolation table.

**Limitations:** Operator must detect degradation via logs—not always dashboard-visible.

**Related modules:** All `safe_*` runtime wrappers.

**Related documents:** `../../../TROUBLESHOOTING.md`, `../../../RUNTIME_FLOW.md`

**Best practices:** Check controller stderr after deploy for import warnings.

**Future improvements:** Explicit `/api/health/planes` status matrix.

---

## Testing

### T-01. What is the Release 1.0 testing strategy?

**Definition:** Layered testing: unit, integration, hardening, synthetic performance, live Mininet acceptance, RL smoke.

**Purpose:** Functional coverage for Foundation, P0, R4–R8 without claiming formal line-coverage CI gate.

**Reason:** Research prototype prioritizes requirement-scoped tests over percentage metrics.

**Implementation summary:** ~48 test modules, ~600 test functions; acceptance audit **491 passed**.

**Runtime behaviour:** pytest on dev Mac/VM; live `--all` on Ubuntu VM with controller + dashboard up.

**Advantages:** Each requirement maps to named test files.

**Limitations:** Formal coverage % **Not implemented** as enforced CI gate.

**Related modules:** `tests/test_*.py`, `verify_phase7.py`

**Related documents:** [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md), `../../../RELEASE_1.0.md`

**Best practices:** Run scoped suites before full `pytest tests/` during iteration.

**Future improvements:** Enforced coverage threshold in CI.

---

### T-02. Which pytest modules cover Foundation and P0?

**Definition:** Contract leaf tests and P0.1–P0.6 hardening regressions.

**Purpose:** Guard dependency rules and evaluation truthfulness before R4–R8 changes.

**Reason:** Foundation/P0 bugs invalidate all downstream metrics.

**Implementation summary:** `test_shared_contracts_foundation.py`; `test_rl_observation_p01.py` … `test_ieee_metrics_p06.py`.

**Runtime behaviour:** Fast unit tests; no Mininet required.

**Advantages:** Quick pre-commit signal.

**Limitations:** Do not substitute for live S1–S5 runs.

**Related modules:** `shared_contracts/`, `rl_engine/`, `evaluation/`, `mitigation/`

**Related documents:** [FOUNDATION_QNA.md](01_Foundation_QNA.md), [P0_QNA.md](02_P0_QNA.md), [../../02_Novelties/02_P0_Hardening.md](../../02_Novelties/02_P0_Hardening.md)

**Best practices:** Run Foundation tests after any `models.py` or enum change.

**Future improvements:** Property-based tests for serialize round-trips.

---

### T-03. How are R4–R8 planes tested in isolation?

**Definition:** Engine, adapter, runtime, dashboard, and perf tests per requirement ID.

**Purpose:** Fail-isolation and logic correctness without full live stack.

**Reason:** Live Mininet runs are slow and environment-dependent.

**Implementation summary:** Examples: `test_correlation_*.py`, `test_fusion_*.py`, `test_verification_*.py`, `test_rca_*.py`, `test_alerting_*.py`, `test_*_hardening_*.py`, `test_*_perf_*.py`.

**Runtime behaviour:** Synthetic fixtures simulate cycle signals and fused decisions.

**Advantages:** Regression catch before VM sync.

**Limitations:** Synthetic paths may miss OVS timing quirks.

**Related modules:** Each plane's `engine.py`, `runtime.py`

**Related documents:** [R4_QNA.md](04_R4_QNA.md) through [R8_QNA.md](08_R8_QNA.md)

**Best practices:** Pair engine tests with runtime hook tests for controller wiring.

**Future improvements:** Record/replay OF stats fixtures from live runs.

---

### T-04. What are live acceptance criteria for S1–S5?

**Definition:** Manual Mininet validation with ground-truth scenario logs and JSONL growth.

**Purpose:** Thesis-grade evidence that pipeline works on real OpenFlow path.

**Reason:** Unit tests cannot fully substitute for OsKen + OVS integration.

**Implementation summary:** Reference PASS run `20260728T181121Z`: R7 VERIFIED 6, blocks 4, alerts 5, RCA 6.

**Runtime behaviour:** `sudo python3 -m traffic_generator.traffic_scheduler --all` with controller and dashboard running.

**Advantages:** Quantitative acceptance numbers for viva.

**Limitations:** Environment-specific; requires VM sync from Mac.

**Related modules:** `traffic_generator/`, `controller/`, all R4–R8 persistence

**Related documents:** [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md), `../../../RELEASE_1.0.md`

**Best practices:** Archive `logs/live_vm_*` directory after each acceptance attempt.

**Future improvements:** Scripted live acceptance with pass/fail JSON report.

---

### T-05. What is verify_phase7 and why might it show 60/61?

**Definition:** RL smoke script checking Phase 7 integration constants.

**Purpose:** Catch RL/mitigation integration regressions.

**Reason:** Historical assertion expects conf **0.80**; runtime ops default is **0.60**—documented script drift.

**Implementation summary:** `verify_phase7.py` at repo root; known issue in RELEASE_1.0.md.

**Runtime behaviour:** One check may fail on init conf mismatch—not necessarily runtime bug.

**Advantages:** Fast RL path sanity check.

**Limitations:** Must interpret failure in context of ops profile.

**Related modules:** `rl_engine/`, `shared_contracts/ops_profile.py`

**Related documents:** `../../../RELEASE_1.0.md`, `../../../TROUBLESHOOTING.md`

**Best practices:** Treat 60/61 as known drift until script aligned with profile.

**Future improvements:** Update verify_phase7 to read ops_profile dynamically.

---

### T-06. How are dashboard APIs tested?

**Definition:** FastAPI TestClient integration tests with fixture log files.

**Purpose:** Ensure `/api/*` routes parse JSONL/CSV correctly.

**Reason:** Dashboard is primary operator observation surface.

**Implementation summary:** `tests/test_*_dashboard_*.py`; requires `httpx` on VM.

**Runtime behaviour:** No live controller needed—reads staged logs.

**Advantages:** CI-friendly API regression tests.

**Limitations:** Does not test Web UI rendering.

**Related modules:** `dashboard/api.py`

**Related documents:** [../../04_Implementation/06_APIs.md](../../04_Implementation/06_APIs.md), [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md)

**Best practices:** Install `httpx` on VM before full suite.

**Future improvements:** Playwright E2E for UI (**Not implemented**).

---

### T-07. What performance tests exist and what do they measure?

**Definition:** Synthetic latency benchmarks for R4–R8 plane operations.

**Purpose:** Support IEEE performance subsection with median/P95 numbers.

**Reason:** Live Mininet timing is noisy; offline benches stabilize comparisons.

**Implementation summary:** `tests/test_*_perf_*.py`; artifacts `logs/r*latency*.json`, `logs/r*perf*.json`.

**Runtime behaviour:** Median R4 ~0.11 ms, R6 ~0.04 ms, R7 ~0.02 ms, R5 ~0.32 ms, R8 ~0.09 ms (Release 1.0 summary).

**Advantages:** Reproducible micro-benchmarks.

**Limitations:** Not end-to-end wall-clock including 5 s poll interval.

**Related modules:** Plane engines under test.

**Related documents:** `../../../RELEASE_1.0.md`

**Best practices:** Regenerate perf JSON after algorithm changes.

**Future improvements:** End-to-end latency harness with injected OF stats.

---

### T-08. How should twin tests be interpreted given R3 is out of DoD?

**Definition:** Tests under `twin/` may exist but are outside Release 1.0 acceptance gate.

**Purpose:** Prevent counting twin failures as Release 1.0 regressions.

**Reason:** R3 live fidelity explicitly **out of Release 1.0 DoD**; code present for future work.

**Implementation summary:** TESTING_GUIDE notes twin tests in full tree (~600 functions includes twin).

**Runtime behaviour:** ImportError twin on old VM → sync issue; not R1.0 blocker.

**Advantages:** Clear scope for viva "what we accept."

**Limitations:** Full `pytest tests/` may include non-DoD modules.

**Related modules:** `twin/`

**Related documents:** [README.md](README.md), [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md)

**Best practices:** Run Release 1.0 scoped suite for acceptance sign-off.

**Future improvements:** pytest markers `@pytest.mark.release1` for DoD subset.

---

## Design

### D-01. What is the core design philosophy of Release 1.0?

**Definition:** Five principles: evidence before action, fail-isolated planes, advisory vs authoritative separation, contracts as leaf, lab vs production ops profiles.

**Purpose:** Unify architectural and policy decisions for handover.

**Reason:** Without explicit philosophy, teams revert to "block on any alert."

**Implementation summary:** Encoded in controller wiring, R4 advisory role, R7 gate, `ops_profile.py`.

**Runtime behaviour:** DROP only after R7 VERIFIED when R7 available; R4 never alone triggers mitigation.

**Advantages:** Coherent viva narrative.

**Limitations:** Philosophy adds latency vs naive immediate block.

**Related modules:** Controller + all planes.

**Related documents:** `DESIGN_DECISIONS.md`, [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md)

**Best practices:** Teach philosophy before module deep-dives in onboarding.

**Future improvements:** ADR index linking decisions to commits.

---

### D-02. Why JSONL instead of a relational database for R4–R8?

**Definition:** Append-only newline-delimited JSON records per plane.

**Purpose:** Audit trail without DB operations in lab VM.

**Reason:** Experiment bundles, grep, and thesis artifacts favor files over SQL setup.

**Implementation summary:** `correlation_results.jsonl`, `fused_decisions.jsonl`, `verification_trace.jsonl`, `root_cause_reports.jsonl`, `alerts.jsonl`.

**Runtime behaviour:** One record per cycle/event appended; dashboard reads tail.

**Advantages:** Zero Redis/Postgres dependency (**Not implemented**).

**Limitations:** Idempotency hygiene needed—occasional duplicate `fusion_id` lines.

**Related modules:** Plane persistence modules.

**Related documents:** `ARCHITECTURE_DECISIONS.md`

**Best practices:** Use `serialize.py` for consistent JSON encoding.

**Future improvements:** Compaction job for duplicate fusion IDs.

---

### D-03. Why is detection≠mitigation encoded as R7 rather than controller if-statements?

**Definition:** Dedicated verification engine with staged policy and trace records.

**Purpose:** Research contribution: explicit multi-stage gate with auditable outcomes.

**Reason:** Ad-hoc controller thresholds are harder to test, document, and cite.

**Implementation summary:** Package `verification/` with engine, stages, confirmation state, legacy parity module.

**Runtime behaviour:** INELIGIBLE/PENDING/VERIFIED statuses drive mitigation eligibility.

**Advantages:** Requirement R7 maps 1:1 to package and tests.

**Limitations:** More moving parts than minimal SDN apps.

**Related modules:** `verification/`

**Related documents:** [R7_QNA.md](06_R7_QNA.md), [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md)

**Best practices:** Never bypass R7 in production-demo configs without documenting risk.

**Future improvements:** Configurable stage ordering for experiments.

---

### D-04. How does R6 fusion calibrate confidence for R7?

**Definition:** Signed score S ∈ [-1,1], decision enum, reliability × health weights, calibrated confidence.

**Purpose:** Single authoritative opinion replacing naive OR/AND of detectors.

**Reason:** Detectors disagree; fusion paper claim requires principled aggregation.

**Implementation summary:** `FusionEngine.fuse()` in `fusion/engine.py`; thresholds attack 0.55, suspicious 0.20, freshness 30 s.

**Runtime behaviour:** ATTACK decisions feed R7 adapter with normalized confidence.

**Advantages:** Disagreement and uncertainty captured in fused record.

**Limitations:** Weights require tuning for new detectors.

**Related modules:** `fusion/engine.py`, `fusion/normalize.py`, `fusion/r7_adapter.py`

**Related documents:** [R6_QNA.md](05_R6_QNA.md), [../../02_Novelties/04_R6_Collaborative_Detection.md](../../02_Novelties/04_R6_Collaborative_Detection.md)

**Best practices:** Register new detectors in `fusion/registry.py` with role metadata.

**Future improvements:** Online weight learning (**Not implemented**).

---

### D-05. What is R4's scoring model design?

**Definition:** Cross-layer co-occurrence score combining signal categories in a time window.

**Purpose:** Advisory evidence that independent categories agree on same entity.

**Reason:** Single-detector papers miss structural agreement across planes.

**Implementation summary:** Score = S · T · D · A · P clamped [0,1]; `window_duration_sec` 30; categories in `correlation/categories.py`.

**Runtime behaviour:** `safe_correlate_cycle` each controller cycle; errors logged not raised.

**Advantages:** Structured input to R6 and dashboard.

**Limitations:** Advisory only—by design cannot authorize DROP.

**Related modules:** `correlation/engine.py`, `correlation/adapters.py`

**Related documents:** [R4_QNA.md](04_R4_QNA.md), [../../02_Novelties/03_R4_Correlation.md](../../02_Novelties/03_R4_Correlation.md)

**Best practices:** Validate signal inventory when adding new detection CSV columns.

**Future improvements:** Dynamic window sizing by traffic rate.

---

### D-06. How is XAI integrated with R5 RCA?

**Definition:** Post-verify enrichment producing structured root cause reports with contributing signals.

**Purpose:** Operator and viva trust via evidence chains—not black-box alerts.

**Reason:** Alerting without explanation fails academic and operational scrutiny.

**Implementation summary:** `safe_enrich_verified_event` → `root_cause_reports.jsonl`; XAI package supports feature attribution context.

**Runtime behaviour:** Fail-isolated from R8; runs after VERIFIED.

**Advantages:** R8 may reference `rca_report_id`.

**Limitations:** Explanation depth bounded by available cycle evidence.

**Related modules:** `rca/`, `xai/`

**Related documents:** [R5_QNA.md](07_R5_XAI_QNA.md), [../../02_Novelties/06_R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md)

**Best practices:** Include contributing_signals in viva demo JSONL walkthrough.

**Future improvements:** SHAP/LIME on live feature vectors at verify time.

---

### D-07. What alert policy does R8 enforce?

**Definition:** Severity, deduplication, rate windows, VERIFIED-only default emission.

**Purpose:** Prevent notification floods; align alerts to authorized events.

**Reason:** Raw detection alerts would duplicate INELIGIBLE noise.

**Implementation summary:** Dedup/rate windows 60 s; no alert on PENDING/INELIGIBLE by default; `alerts.jsonl` persistence.

**Runtime behaviour:** `safe_emit_verification_alert` on verified callback.

**Advantages:** Policy-as-code in `alerting/config.py`.

**Limitations:** External channels (email/Slack) **Not implemented**—JSONL only.

**Related modules:** `alerting/engine.py`, `alerting/persistence.py`

**Related documents:** [R8_QNA.md](08_R8_QNA.md), [../../02_Novelties/07_R8_Alerting.md](../../02_Novelties/07_R8_Alerting.md)

**Best practices:** Tune dedup windows when running rapid `--all` scenarios.

**Future improvements:** Pluggable `alerting/adapters/` for SMTP/webhook.

---

### D-08. Why pickle for ML models in a security project?

**Definition:** Local trusted-lab model artifacts (Isolation Forest + Decision Tree) loaded via pickle.

**Purpose:** Fast demo startup without training pipeline on every run.

**Reason:** Lab trust model assumes local file integrity; not internet-facing model serving.

**Implementation summary:** Artifacts under `logs/models` or configured paths; 15-D feature vector from `ml_models/feature_builder.py`.

**Runtime behaviour:** Optional `INTELLISHIELD_AUTO_TRAIN_SYNTHETIC=1` for demos.

**Advantages:** Simple lab workflow.

**Limitations:** Pickle trust risk if models sourced externally—documented security summary.

**Related modules:** `ml_models/`, `controller/flow_monitor.py`

**Related documents:** `../../../RELEASE_1.0.md`, `DESIGN_DECISIONS.md`

**Best practices:** Treat model files as trusted lab artifacts only.

**Future improvements:** ONNX or sklearn JSON export with signature verification.

---

## Performance

### P-01. What are the documented synthetic plane latencies?

**Definition:** Offline median/P95 micro-benchmarks for R4–R8 engines.

**Purpose:** IEEE-friendly performance subsection without claiming datacenter scale.

**Reason:** Plane logic must be fast relative to 5 s poll interval.

**Implementation summary:** R4 ~0.11/0.13 ms, R6 ~0.04 ms, R7 ~0.02 ms, R5 ~0.32/0.48 ms, R8 ~0.09/0.25 ms (Release 1.0).

**Runtime behaviour:** Artifacts in `logs/r*latency*.json`, `logs/r*perf*.json`.

**Advantages:** Sub-millisecond planes leave headroom for OsKen loop.

**Limitations:** Excludes network I/O, Mininet, and ML inference variance.

**Related modules:** Plane engines; perf test modules.

**Related documents:** `../../../RELEASE_1.0.md`

**Best practices:** Cite synthetic numbers separately from live wall-clock detection delay.

**Future improvements:** Unified perf regression dashboard.

---

### P-02. How does the 5-second poll interval bound detection latency?

**Definition:** Controller monitor interval between OpenFlow stats polls.

**Purpose:** Trade temporal resolution for lab CPU stability.

**Reason:** Sub-second polling increases OsKen load without thesis requirement.

**Implementation summary:** Constant in controller; features built per batch.

**Runtime behaviour:** Worst-case detection delay includes warm-up (3) + confirm (2) cycles ≈ tens of seconds.

**Advantages:** Predictable resource usage on VM.

**Limitations:** S4 burst may partially occur between polls.

**Related modules:** `controller/flow_monitor.py`

**Related documents:** `../../../RUNTIME_FLOW.md`

**Best practices:** Report detection latency as cycles × interval in papers.

**Future improvements:** Adaptive poll rate under attack (**Not implemented**).

---

### P-03. Does the stack meet real-time constraints for lab DDoS?

**Definition:** Whether verify→mitigate completes within acceptable lab window.

**Purpose:** Answer viva "is it real-time enough?"

**Reason:** Research claim is online pipeline, not carrier-grade line rate.

**Implementation summary:** Live reference: 4 SUCCESS blocks from 6 VERIFIED on acceptance run.

**Runtime behaviour:** Plane CPU ≪ poll period; bottleneck is cycle accumulation not engine ms.

**Advantages:** Demonstrated live blocking under scenarios S2–S5.

**Limitations:** Not benchmarked at 10G+ rates.

**Related modules:** Full pipeline.

**Related documents:** `../../../RELEASE_1.0.md`

**Best practices:** Scope claims to Mininet lab topology h1–h5.

**Future improvements:** Stress harness with higher host count.

---

### P-04. How does JSONL append performance scale?

**Definition:** Cost of per-cycle append to log files.

**Purpose:** Understand disk I/O as traffic duration grows.

**Reason:** Long `--all` runs accumulate thousands of lines.

**Implementation summary:** R8 persist median ~0.09 ms; dashboard uses bounded reads.

**Runtime behaviour:** Large files may slow dashboard tail—archive recommended.

**Advantages:** No DB connection pool or lock contention.

**Limitations:** Manual archival under `logs/archive/` needed.

**Related modules:** Persistence modules; `dashboard/readers.py`

**Related documents:** `ARCHITECTURE_DECISIONS.md`

**Best practices:** Rotate logs before multi-hour experiments.

**Future improvements:** Log rotation daemon (**Not implemented**).

---

### P-05. What is the ML inference cost per cycle?

**Definition:** CPU time for 15-D feature vector through Isolation Forest + Decision Tree.

**Purpose:** Ensure ML path fits within poll budget alongside R4–R8.

**Reason:** ML is one of two primary detectors feeding fusion.

**Implementation summary:** Pickle load once at startup; per-cycle predict in controller cycle.

**Runtime behaviour:** Warm-up skips ML/mitigation until cycles complete.

**Advantages:** Pre-trained models avoid training latency during demo.

**Limitations:** Pickle load time on cold start; not GPU accelerated.

**Related modules:** `ml_models/`, `ml_models/feature_builder.py`

**Related documents:** `../../../RUNTIME_FLOW.md`

**Best practices:** Pre-warm controller before timed demo.

**Future improvements:** Batch inference across buffered flows.

---

### P-06. Are there known metrics double-count issues?

**Definition:** Technical debt in metrics window naming causing some report double-counts.

**Purpose:** Honest performance/evaluation reporting.

**Reason:** Listed in RELEASE_1.0 technical debt.

**Implementation summary:** `scripts/compute_metrics.py` + P0.3 experiment windows—some reports affected.

**Runtime behaviour:** Does not block mitigation; affects evaluation CSV interpretation.

**Advantages:** Documented—not hidden.

**Limitations:** Papers must verify metric scripts used.

**Related modules:** `evaluation/`, `scripts/compute_metrics.py`

**Related documents:** `../../../RELEASE_1.0.md`, [P0_QNA.md](02_P0_QNA.md)

**Best practices:** Cross-check IEEE metrics with ground-truth windows manually once.

**Future improvements:** Unify window naming in metrics pipeline.

---

### P-07. How does entropy detection compare to ML in runtime cost?

**Definition:** Relative CPU for entropy windows vs ML inference each cycle.

**Purpose:** Justify dual-detector design cost.

**Reason:** Fusion requires multiple opinions—cost must stay bounded.

**Implementation summary:** `entropy_engine/` computes windowed entropy on flow batches.

**Runtime behaviour:** Both paths run before R4; outputs to CSV logs.

**Advantages:** Entropy provides fast baseline signal complementary to ML.

**Limitations:** Entropy alone insufficient for verified mitigation path.

**Related modules:** `entropy_engine/`, `ml_models/`

**Related documents:** `../../../RUNTIME_FLOW.md`

**Best practices:** Profile with plane disabled flags when isolating bottlenecks.

**Future improvements:** Shared feature cache between entropy and ML builders.

---

## Research

### R-01. What is the scoped research novelty of Release 1.0?

**Definition:** Laboratory-complete collaborative pipeline—not "another Isolation Forest on flows."

**Purpose:** Defensible IEEE/MCA contribution statement.

**Reason:** Reviewers distinguish integrated systems from single-algorithm tweaks.

**Implementation summary:** Sense → detect → R4 correlate → R6 fuse → R7 verify → mitigate → R5 explain → R8 alert on shared contracts after P0 fixes, with live Mininet evidence.

**Runtime behaviour:** Demonstrated on acceptance run under lab ops profile.

**Advantages:** End-to-end evidence chain rare in student SDN projects.

**Limitations:** Scoped to controlled lab—not internet-edge production claim.

**Related modules:** Full R4–R8 stack.

**Related documents:** [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md), `../../../RELEASE_1.0.md`

**Best practices:** Lead papers with pipeline novelty; cite ML as component not headline.

**Future improvements:** Comparative baseline against single-detector-only mode.

---

### R-02. Why was Foundation research-necessary?

**Definition:** Typed evidence vocabulary across planes.

**Purpose:** Reproducible logs/APIs for cross-layer RCA and dashboard joins.

**Reason:** Multi-module SDN stacks often suffer stringly-typed JSON drift.

**Implementation summary:** `shared_contracts` with schema_version 1.0 DTOs for all R4–R8 records.

**Runtime behaviour:** JSONL round-trip via `serialize.py`.

**Advantages:** Citable contract layer in methodology section.

**Limitations:** Passive contracts—not an event-sourced research framework.

**Related modules:** `shared_contracts/`

**Related documents:** [FOUNDATION_QNA.md](01_Foundation_QNA.md), [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Best practices:** Reference Foundation as enabling reproducibility.

**Future improvements:** Publish contract schema as supplementary material.

---

### R-03. What research gap does R4 address?

**Definition:** Cross-layer co-occurrence beyond independent detector fires.

**Purpose:** Structured advisory signal for fusion and RCA.

**Reason:** Single-detector papers ignore agreement structure across categories.

**Implementation summary:** Correlation engine with weighted categories and 30 s window.

**Runtime behaviour:** Advisory JSONL each cycle; may boost R6 evidence.

**Advantages:** Distinct requirement with dedicated QnA (≥80 questions in R4_QNA.md).

**Limitations:** Advisory-only by safety design.

**Related modules:** `correlation/`

**Related documents:** [R4_QNA.md](04_R4_QNA.md), [../../02_Novelties/03_R4_Correlation.md](../../02_Novelties/03_R4_Correlation.md)

**Best practices:** Compare runs with R4 disabled to quantify fusion impact.

**Future improvements:** Publish correlation score distribution plots from live runs.

---

### R-04. What research gap does R6 address?

**Definition:** Principled multi-detector fusion with reliability and health—not naive voting.

**Purpose:** Handle detector disagreement in collaborative SDN security.

**Reason:** OR/AND/majority ignore detector quality and freshness.

**Implementation summary:** Signed score fusion with calibrated confidence for R7.

**Runtime behaviour:** Owns cycle when enabled; single fused decision per poll.

**Advantages:** Core differentiator vs entropy-only or ML-only baselines.

**Limitations:** Weight tuning is lab-specific.

**Related modules:** `fusion/`

**Related documents:** [R6_QNA.md](05_R6_QNA.md), [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Best practices:** Document `INTELLISHIELD_R6_FUSION=0` ablation runs for papers.

**Future improvements:** Learned fusion weights from labeled scenarios.

---

### R-05. What research gap does R7 address?

**Definition:** Explicit verification gate between detection and actuation.

**Purpose:** Reduce false mitigation in SDN reactive defense.

**Reason:** Detection≠authorization is under-emphasized in naive SDN demos.

**Implementation summary:** Multi-stage engine with warm-up, streak confirm, confidence gate, attacker ID.

**Runtime behaviour:** Many INELIGIBLE cycles are intentional safety outcomes.

**Advantages:** Trace JSONL supports qualitative security analysis in thesis.

**Limitations:** Adds latency vs immediate block.

**Related modules:** `verification/`

**Related documents:** [R7_QNA.md](06_R7_QNA.md), [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md)

**Best practices:** Report VERIFIED vs INELIGIBLE ratios—not just block count.

**Future improvements:** Formal verification stage policy language.

---

### R-06. Why is R5 positioned after mitigation in the research narrative?

**Definition:** XAI/RCA explains **authorized** defensive actions, not raw anomalies.

**Purpose:** Align explanation with operator-trustworthy events.

**Reason:** Explaining every false ML positive dilutes RCA value.

**Implementation summary:** Post-verify `RootCauseReport` with contributing_signals.

**Runtime behaviour:** 6 RCA reports on reference live run vs 6 VERIFIED.

**Advantages:** Clean causal story for viva: verify → block → explain → alert.

**Limitations:** RCA depth limited by cycle evidence snapshot.

**Related modules:** `rca/`, `xai/`

**Related documents:** [R5_QNA.md](07_R5_XAI_QNA.md), [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Best practices:** Show one full JSONL chain from fusion through RCA in presentation.

**Future improvements:** Counterfactual "what if not blocked" analysis.

---

### R-07. What is the role of live Mininet evidence in research claims?

**Definition:** S1–S5 scenarios on Ubuntu VM with archived artifacts.

**Purpose:** Empirical validation beyond unit tests.

**Reason:** SDN security claims require OpenFlow path proof.

**Implementation summary:** Run `20260728T181121Z` archived under `logs/live_vm_20260728T181121Z/`.

**Runtime behaviour:** Ground truth from scenario/attack CSV timestamps.

**Advantages:** Quantitative acceptance table in RELEASE_1.0.md.

**Limitations:** Emulation realism bounded—state explicitly in papers.

**Related modules:** `traffic_generator/`, Mininet topology

**Related documents:** [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md)

**Best practices:** Archive logs with run id timestamp for reproducibility.

**Future improvements:** Public dataset export of anonymized JSONL traces.

---

### R-08. How should R2 and R3 be discussed in research writing?

**Definition:** Honest status for deferred requirements.

**Purpose:** Avoid reviewer accusations of over-claiming.

**Reason:** R2 SSL zero-day **Not implemented**; R3 twin live fidelity **out of R1.0 DoD**.

**Implementation summary:** Reserved `DetectorType` enums; `twin/` code exists without acceptance gate.

**Runtime behaviour:** Neither R2 nor R3 participates in Release 1.0 acceptance pipeline.

**Advantages:** Future work section writes itself with integrity.

**Limitations:** Reviewers may ask about twin—answer with DoD boundary.

**Related modules:** `shared_contracts/enums.py`, `twin/`

**Related documents:** [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md), `../../../RELEASE_1.0.md`

**Best practices:** One paragraph "Future Work" citing R2/R3 explicitly.

**Future improvements:** R2 implementation; R3 live fidelity acceptance criteria.

---

## Deployment

### DEP-01. What is the standard lab deployment topology?

**Definition:** Ubuntu VM running Mininet, OsKen controller, traffic scheduler, and FastAPI dashboard.

**Purpose:** Repeatable demo and acceptance environment.

**Reason:** OpenFlow and OVS require Linux; Mac is typical dev sync source.

**Implementation summary:** Topology h1–h5 + s1; controller :6653; dashboard :8080; repo on VM at `~/intellishield-sdn`.

**Runtime behaviour:** Three-terminal workflow: controller, dashboard, scheduler.

**Advantages:** Documented operator commands in RELEASE_1.0.md.

**Limitations:** Manual process management—no Kubernetes (**Not implemented**).

**Related modules:** All runtime packages.

**Related documents:** `../../../RELEASE_1.0.md`, [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md)

**Best practices:** Sync Mac → VM before live runs; single controller on 6653.

**Future improvements:** systemd unit files for controller and dashboard.

---

### DEP-02. What environment variables must operators set?

**Definition:** Primary runtime configuration via env—not central YAML.

**Purpose:** Lab vs production ops behaviour without config files.

**Reason:** Central YAML/TOML config service **Not implemented**.

**Implementation summary:**

| Variable | Effect |
|----------|--------|
| `INTELLISHIELD_OPS_PROFILE=lab` | Freeze conf gate 60% |
| `INTELLISHIELD_R6_FUSION=0` | Disable fusion |
| `PYTHONPATH` | Repo root on VM |
| `INTELLISHIELD_SUDO_PASS` | Dashboard scenario sudo (lab risk) |

**Runtime behaviour:** Read at process start; changes require restart.

**Advantages:** Simple export in shell before demo.

**Limitations:** No hot reload of thresholds.

**Related modules:** `shared_contracts/ops_profile.py`, plane config modules.

**Related documents:** [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md), `../../../TROUBLESHOOTING.md`

**Best practices:** Document env in run script snippet for viva reproducibility.

**Future improvements:** `.env` loader with validation (**`.env.example` exists**).

---

### DEP-03. What are the operator startup commands for Release 1.0?

**Definition:** Canonical three-command lab bring-up from RELEASE_1.0.md.

**Purpose:** Handover checklist for demos.

**Reason:** Order matters—controller before traffic.

**Implementation summary:**

```bash
export INTELLISHIELD_OPS_PROFILE=lab
osken-manager controller/flow_monitor.py
python3 dashboard/api.py
sudo python3 -m traffic_generator.traffic_scheduler --all
```

**Runtime behaviour:** Scheduler requires sudo; dashboard optional but recommended for observation.

**Advantages:** Copy-paste ready for operators.

**Limitations:** Assumes venv/deps pre-installed on VM.

**Related modules:** `controller/`, `dashboard/`, `traffic_generator/`

**Related documents:** `../../../RELEASE_1.0.md`, `../../../DEVELOPER_GUIDE.md`

**Best practices:** Verify controller connected before launching `--all`.

**Future improvements:** Single `make demo` orchestrator script.

---

### DEP-04. What dependencies are required on the lab VM?

**Definition:** Python packages, OsKen, Mininet, OVS, pytest stack for validation.

**Purpose:** Avoid ImportError during live acceptance.

**Reason:** Dashboard tests need `httpx`; controller needs `python3-os-ken`.

**Implementation summary:** `pip install pytest httpx fastapi`; `PYTHONPATH=$HOME/intellishield-sdn`.

**Runtime behaviour:** Full pytest first import may be slow on VM.

**Advantages:** Documented in TESTING_GUIDE and DEVELOPER_GUIDE.

**Limitations:** Root `requirements.txt` lockfile may be absent.

**Related modules:** N/A (infra)

**Related documents:** [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md), root `README.md`

**Best practices:** Maintain VM venv separate from system Python.

**Future improvements:** Committed lockfile with install script.

---

### DEP-05. What security considerations apply at deployment?

**Definition:** Lab security posture—not enterprise hardening.

**Purpose:** Honest risk disclosure for handover.

**Reason:** Dashboard lacks auth; sudo password env is lab convenience.

**Implementation summary:** Plane fail-isolation present; no `shell=True` in core planes; pickle trust model; optional `INTELLISHIELD_SUDO_PASS`.

**Runtime behaviour:** Do not expose :8080 or :6653 to untrusted networks.

**Advantages:** Documented in RELEASE_1.0 security summary.

**Limitations:** Internet-edge production **not claimed**.

**Related modules:** `dashboard/api.py`, `ml_models/`

**Related documents:** `../../../RELEASE_1.0.md`, `../../../TROUBLESHOOTING.md`

**Best practices:** Prefer sudoers over password env for dashboard control.

**Future improvements:** Dashboard authentication layer.

---

### DEP-06. How should logs be managed post-deployment?

**Definition:** CSV/JSONL artifact lifecycle on VM disk.

**Purpose:** Prevent disk fill and dashboard slowdown.

**Reason:** JSONL append grows unbounded without rotation.

**Implementation summary:** Primary paths under `logs/`; archive to `logs/archive/` or `logs/live_vm_*` for acceptance.

**Runtime behaviour:** Dashboard bounded reads; very large files degrade tail performance.

**Advantages:** Experiment bundles (P0.5) package artifacts for papers.

**Limitations:** No automated rotation daemon (**Not implemented**).

**Related modules:** `evaluation/experiment_bundle.py`, plane persistence

**Related documents:** [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md), [P0_QNA.md](02_P0_QNA.md)

**Best practices:** Archive after each `--all` acceptance run with timestamp.

**Future improvements:** Logrotate config snippet in repo.

---

### DEP-07. Can Redis or Postgres be deployed alongside IntelliShield?

**Definition:** External datastore integration status.

**Purpose:** Answer infrastructure questions honestly.

**Reason:** Architecture explicitly rejected Redis/Postgres for Release 1.0.

**Implementation summary:** **Not implemented**—all R4–R8 state in JSONL/CSV files.

**Runtime behaviour:** No code paths expect Redis/Postgres URLs.

**Advantages:** Zero additional service deployment.

**Limitations:** No distributed cache or SQL analytics without custom tooling.

**Related modules:** N/A

**Related documents:** `ARCHITECTURE_DECISIONS.md`, `GLOSSARY.md`

**Best practices:** Do not introduce Redis without architectural ADR—breaks leaf simplicity.

**Future improvements:** Optional read replica via SQLite for dashboard only.

---

## Maintenance

### M-01. What is the recommended reading order for new maintainers?

**Definition:** Onboarding path from vocabulary to deep requirement QnA to runtime walkthrough.

**Purpose:** Reduce time-to-first-successful live run.

**Reason:** KB and release suite split *why* vs *how* deliberately.

**Implementation summary:** GLOSSARY → FAQ → ARCHITECTURE_DECISIONS → DESIGN_DECISIONS → FOUNDATION/P0 QnA → R4→R6→R7→R5→R8 QnA → this QNA → RUNTIME_FLOW.

**Runtime behaviour:** N/A

**Advantages:** Documented in [README.md](README.md).

**Limitations:** FAQ.md referenced but may need generation—use this QNA as deep alternative.

**Related modules:** N/A

**Related documents:** [README.md](README.md), `../../../RUNTIME_FLOW.md`

**Best practices:** Complete one S2 live run within first week.

**Future improvements:** Maintainer checklist issue template.

---

### M-02. What are known Release 1.0 issues to track?

**Definition:** Documented bugs and drifts—not hidden debt.

**Purpose:** Prioritize maintenance without surprise regressions.

**Reason:** RELEASE_1.0.md lists known issues explicitly.

**Implementation summary:** verify_phase7 conf drift; duplicate fusion_id lines; stale PROJECT_STATE.json; many INELIGIBLE cycles by design.

**Runtime behaviour:** Issues affect metrics/scripts more than core safety path.

**Advantages:** Transparency for handover.

**Limitations:** Requires periodic re-validation after fixes.

**Related modules:** `verify_phase7.py`, `fusion/persistence.py`

**Related documents:** `../../../RELEASE_1.0.md`, `../../../TROUBLESHOOTING.md`

**Best practices:** File fix PRs against technical debt list in RELEASE_1.0.md.

**Future improvements:** GitHub issues mirroring known issues table.

---

### M-03. How should contract schema changes be maintained?

**Definition:** Process for evolving `shared_contracts` DTOs and enums.

**Purpose:** Prevent breaking JSONL consumers (dashboard, RCA, metrics).

**Reason:** schema_version 1.0 is baseline—changes need coordinated updates.

**Implementation summary:** Update `models.py` → `serialize.py` → plane writers → dashboard readers → `test_shared_contracts_foundation.py`.

**Runtime behaviour:** Old JSONL lines may fail `from_dict` if fields removed without migration.

**Advantages:** Foundation tests catch many breaks early.

**Limitations:** No automatic JSONL migration tool (**Not implemented**).

**Related modules:** `shared_contracts/`, `dashboard/`

**Related documents:** [FOUNDATION_QNA.md](01_Foundation_QNA.md), [../../02_Novelties/01_Foundation.md](../../02_Novelties/01_Foundation.md)

**Best practices:** Bump schema_version on breaking changes; document in CHANGELOG.

**Future improvements:** Forward-compatible optional fields policy doc.

---

### M-04. How should threshold tuning be maintained safely?

**Definition:** Changing knobs in Python config modules across planes.

**Purpose:** Improve detection/mitigation balance without bypassing R7.

**Reason:** Thresholds scattered—no central YAML.

**Implementation summary:** `fusion/config.py`, `correlation/config.py`, `verification/config.py`, `alerting/config.py`, `mitigation/mitigation_engine.py`.

**Runtime behaviour:** Restart controller after changes; lab profile may freeze RL gate regardless.

**Advantages:** Code-reviewed tunables near engine logic.

**Limitations:** Easy to desync related thresholds across R6/R7.

**Related modules:** Config modules listed above.

**Related documents:** [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md)

**Best practices:** Change one plane at a time; re-run scoped pytest + one live scenario.

**Future improvements:** Central config module with validation (**Not implemented**).

---

### M-05. What regression suite should run before each demo?

**Definition:** Minimum test + live checklist.

**Purpose:** Protect demo reliability under last-minute changes.

**Reason:** 491-test full suite may be slow—scoped path balances speed and coverage.

**Implementation summary:** Foundation + affected plane tests + `verify_phase7` + S2 live spot check with JSONL growth verification.

**Runtime behaviour:** Full `--all` before major viva only.

**Advantages:** Catches wiring regressions fast.

**Limitations:** Live check requires VM availability.

**Related modules:** `tests/`, `traffic_generator/`

**Related documents:** [../../05_Testing/01_Testing_Strategy.md](../../05_Testing/01_Testing_Strategy.md)

**Best practices:** Keep archived golden JSONL snippet for diff comparison.

**Future improvements:** Demo smoke script wrapping scoped pytest + log grep assertions.

---

### M-06. How should Mac-to-VM sync be maintained?

**Definition:** Dev workflow copying repo to Ubuntu lab VM.

**Purpose:** Ensure VM runs same code as version-controlled source.

**Reason:** Live acceptance runs on VM—not Mac Mininet in typical setup.

**Implementation summary:** Documented in operator notes; `PYTHONPATH=$HOME/intellishield-sdn`.

**Runtime behaviour:** ImportError on VM often indicates incomplete sync.

**Advantages:** Mac dev with Linux runtime is common academic pattern.

**Limitations:** Manual sync error-prone before demos.

**Related modules:** N/A

**Related documents:** `../../../TROUBLESHOOTING.md`, `../../../DEVELOPER_GUIDE.md`

**Best practices:** Tag git commit used for each archived `live_vm_*` run.

**Future improvements:** rsync script or CI deploy-to-VM action.

---

### M-07. How is technical debt documented for maintainers?

**Definition:** RELEASE_1.0.md technical debt and documentation summary gaps.

**Purpose:** Prioritize post-release maintenance work.

**Reason:** Includes smoke script alignment, fusion idempotency, metrics naming, sudoers.

**Implementation summary:** Four debt items listed in release notes.

**Runtime behaviour:** Debt items do not block lab demo but affect polish.

**Advantages:** Explicit—maintainers need not archaeology git history.

**Limitations:** Not tracked as automated issues unless team adds them.

**Related modules:** `verify_phase7.py`, `fusion/`, `scripts/compute_metrics.py`

**Related documents:** `../../../RELEASE_1.0.md`, `../../../DOCUMENTATION_SUMMARY.md`

**Best practices:** Address debt items before claiming "Release 1.1."

**Future improvements:** DEBT.md with owner and target milestone.

---

## Future Work

### F-01. What is planned for R2 SSL zero-day detection?

**Definition:** Reserved collaborative SSL/TLS anomaly detector requirement.

**Purpose:** Extend detector diversity beyond entropy and ML flow features.

**Reason:** Master roadmap includes R2; Release 1.0 delivers types only.

**Implementation summary:** **Not implemented**—`DetectorType` enum placeholders in `shared_contracts`; fusion registry hook exists for future adapter.

**Runtime behaviour:** No SSL plane executes in Release 1.0 pipeline.

**Advantages:** Extension point documented without false claims.

**Limitations:** Viva must state R2 explicitly deferred.

**Related modules:** `shared_contracts/enums.py`, `fusion/registry.py`

**Related documents:** [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md), `../../../RELEASE_1.0.md`

**Best practices:** Implement contract + tests before controller wiring when starting R2.

**Future improvements:** SSL feature extractor adapter feeding R6 fusion.

---

### F-02. What is the R3 digital twin roadmap status?

**Definition:** Attack simulation/training twin under `twin/` package.

**Purpose:** Pre-deployment simulation and training fidelity beyond Mininet scenarios.

**Reason:** R3 live fidelity explicitly **out of Release 1.0 DoD** despite existing code.

**Implementation summary:** Twin tests may exist in full tree; not acceptance-gated for R1.0.

**Runtime behaviour:** Twin does not participate in standard `--all` acceptance pipeline.

**Advantages:** Code scaffold reduces greenfield work for R3 phase.

**Limitations:** No Release 1.0 manual or live acceptance evidence as DoD requirement.

**Related modules:** `twin/`

**Related documents:** `../../../DOCUMENTATION_SUMMARY.md`, historical `R3_*.md`

**Best practices:** Treat twin as research future work in papers—not current contribution.

**Future improvements:** R3 live Mininet validation checklist execution and DoD inclusion.

---

### F-03. Will external alert channels be added?

**Definition:** Email, Slack, webhook dispatch beyond `alerts.jsonl`.

**Purpose:** Operator notification outside dashboard UI.

**Reason:** R8 completes policy and persistence; dispatch adapters deferred.

**Implementation summary:** **Not implemented**—`alerting/adapters/` extension point documented.

**Runtime behaviour:** Alerts observable via dashboard `/api` and JSONL tail only.

**Advantages:** JSONL sufficient for lab and thesis evidence.

**Limitations:** No mobile push or SOC integration.

**Related modules:** `alerting/adapters/`

**Related documents:** [R8_QNA.md](08_R8_QNA.md), [../../02_Novelties/07_R8_Alerting.md](../../02_Novelties/07_R8_Alerting.md)

**Best practices:** Keep VERIFIED-only policy when adding channels.

**Future improvements:** SMTP and Slack webhook adapters with secret env vars.

---

### F-04. Will dashboard authentication be implemented?

**Definition:** HTTP auth for FastAPI dashboard and control endpoints.

**Purpose:** Secure observation and scenario trigger APIs.

**Reason:** Lab demo prioritizes accessibility; auth **Not implemented**.

**Implementation summary:** Dashboard open on :8080; optional sudo via password env for scenarios.

**Runtime behaviour:** Any client on network can reach API if port exposed.

**Advantages:** Zero auth friction for viva demos on isolated VM.

**Limitations:** Unacceptable for any shared network deployment.

**Related modules:** `dashboard/api.py`

**Related documents:** `ARCHITECTURE_DECISIONS.md`, [../../04_Implementation/06_APIs.md](../../04_Implementation/06_APIs.md)

**Best practices:** Bind dashboard to localhost or VM-internal network only until auth exists.

**Future improvements:** API key or OAuth2 middleware.

---

### F-05. Will a central configuration service replace scattered Python configs?

**Definition:** Unified YAML/TOML config with hot reload.

**Purpose:** Operator-friendly tuning without code edits.

**Reason:** Release 1.0 uses env vars + per-package Python config modules.

**Implementation summary:** Central YAML/TOML config service **Not implemented**.

**Runtime behaviour:** Threshold changes require code/module edits and process restart.

**Advantages:** Current approach is grep-friendly and test-stable.

**Limitations:** Higher ops burden for non-developer tuners.

**Related modules:** All `*/config.py` files.

**Related documents:** [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md)

**Best practices:** If adding YAML, validate against contracts at startup.

**Future improvements:** Single `config.yaml` with schema validation.

---

### F-06. Will Redis or Postgres be introduced for scale?

**Definition:** External datastore for logs, dedup, or dashboard queries.

**Purpose:** Multi-instance or high-volume telemetry scenarios.

**Reason:** Release 1.0 explicitly chose JSONL/CSV simplicity.

**Implementation summary:** **Not implemented**—no Redis/Postgres dependencies or connection code.

**Runtime behaviour:** File-based persistence only.

**Advantages:** Maintains lab deploy simplicity documented in ARCHITECTURE_DECISIONS.

**Limitations:** Manual analytics on large JSONL files.

**Related modules:** Plane persistence modules.

**Related documents:** `ARCHITECTURE_DECISIONS.md`, `GLOSSARY.md`

**Best practices:** Consider SQLite before full Postgres for read-heavy dashboard if needed.

**Future improvements:** Optional Postgres writer mirroring JSONL append stream.

---

### F-07. What fusion persistence improvements are planned?

**Definition:** Idempotency hygiene for `fused_decisions.jsonl`.

**Purpose:** Eliminate occasional duplicate `fusion_id` lines for same event/timestamp.

**Reason:** Listed in Release 1.0 known issues and technical debt.

**Implementation summary:** Current append model may double-write under edge paths.

**Runtime behaviour:** Dashboard may show duplicates—metrics scripts should dedupe carefully.

**Advantages:** Issue is documented—not silent corruption.

**Limitations:** Complicates automated log diff tooling until fixed.

**Related modules:** `fusion/persistence.py`, `fusion/runtime.py`

**Related documents:** `../../../RELEASE_1.0.md`

**Best practices:** Dedupe by fusion_id in offline analysis scripts until fix ships.

**Future improvements:** Idempotent upsert key or write-ahead guard per cycle.

---

### F-08. What is the path toward internet-edge production readiness?

**Definition:** Hardening beyond ~92/100 lab production-demo score.

**Purpose:** Clarify gap between research prototype and enterprise deployment.

**Reason:** Release 1.0 explicitly does **not** claim internet-edge production.

**Implementation summary:** Would require auth, external alert dispatch, model signing, sudoers, HA controller, formal CI coverage, possibly R2/R3 maturity.

**Runtime behaviour:** Current stack optimized for Mininet evidence and thesis evaluation.

**Advantages:** Clear roadmap narrative for viva "what next."

**Limitations:** Significant engineering beyond MCA scope.

**Related modules:** Entire stack.

**Related documents:** `../../../RELEASE_1.0.md`, [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Best practices:** Position Release 1.0 as research-complete, ops-demo-ready, not carrier-grade.

**Future improvements:** Release 1.1+ milestone doc with prioritized hardening backlog.

---

## Document index

| Section | Prefix | Count |
|---------|--------|------:|
| General | G- | 10 |
| Architecture | A- | 10 |
| Runtime | RT- | 10 |
| Testing | T- | 8 |
| Design | D- | 8 |
| Performance | P- | 7 |
| Research | R- | 8 |
| Deployment | DEP- | 7 |
| Maintenance | M- | 7 |
| Future Work | F- | 8 |
| **Total** | | **83** |

**Sibling KB documents:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) · [P0_QNA.md](02_P0_QNA.md) · [R4_QNA.md](04_R4_QNA.md) · [R5_QNA.md](07_R5_XAI_QNA.md) · [R6_QNA.md](05_R6_QNA.md) · [R7_QNA.md](06_R7_QNA.md) · [R8_QNA.md](08_R8_QNA.md) · `GLOSSARY.md` · `DESIGN_DECISIONS.md` · `ARCHITECTURE_DECISIONS.md` · [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md)

**Engineering walkthrough:** `../../../RUNTIME_FLOW.md` · [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md) · `../../../RELEASE_1.0.md`

*Generated for IntelliShield SDN Release 1.0 handover and viva preparation. Facts reflect repository state only; unimplemented features are labeled explicitly.*
