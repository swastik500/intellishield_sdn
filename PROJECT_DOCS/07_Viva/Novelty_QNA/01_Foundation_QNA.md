# Foundation Q&A — Shared Contracts (Release 1.0)

Related: [../../02_Novelties/01_Foundation.md](../../02_Novelties/01_Foundation.md) · [../../03_System_Design/01_Overall_Architecture.md](../../03_System_Design/01_Overall_Architecture.md) · [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md) · `GLOSSARY.md` · [P0_QNA.md](02_P0_QNA.md)

Answers reflect **current repository code** under `shared_contracts/`. Unimplemented requirements (R2 SSL detector, R3 live twin DoD) are noted explicitly.

> **PROJECT_DOCS copy** — adapted from `FOUNDATION_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview & Purpose

### Q1. What is the Foundation layer in IntelliShield Release 1.0?

**Purpose:** Provide a dependency-leaf typed contract layer so R4–R8 (and twin scaffolding) share enums, DTOs, serialization, and ops policy without importing the controller or detectors.

**Reason:** Without shared contracts, each plane invents ad-hoc dict shapes → fragile dashboard/RCA linking, inconsistent enums, and silent schema drift across JSONL logs.

**Implementation:** Package `shared_contracts/` with modules `enums.py`, `models.py`, `serialize.py`, `timeutil.py`, `ops_profile.py`, and public exports in `__init__.py`.

**Runtime:** Planes import types for JSONL records and API projections. The controller uses `get_ops_policy()` indirectly via RL/mitigation for confidence bounds.

**Limits:** Infrastructure only — detectors may still return plain dicts at boundaries; adoption is incremental.

**Related:** [FOUNDATION.md](../../02_Novelties/01_Foundation.md), `tests/test_shared_contracts_foundation.py`

---

### Q2. Why was Foundation built before R4–R8 instead of inline types per plane?

**Purpose:** Establish a single vocabulary before correlation, fusion, verification, alerting, and RCA were wired together.

**Reason:** Research prototypes often accumulate “stringly typed” logs. A shared contract layer makes cross-plane evidence chains (R5) and dashboard joins predictable.

**Implementation:** Master roadmap phase “FOUNDATION” completed with `schema_version = "1.0"` on all DTOs.

**Runtime:** R4 writes `CorrelationResult`, R6 writes `FusedDecision`, R7 writes `VerificationResult`, R8 writes `AlertEvent` — all round-trippable through `serialize.py`.

**Limits:** No event bus; contracts are passive data shapes, not a messaging framework.

**Related:** [ARCHITECTURE.md](../../03_System_Design/01_Overall_Architecture.md), [R7_QNA.md](06_R7_QNA.md), [R8_QNA.md](08_R8_QNA.md)

---

### Q3. What problem does Foundation solve that CSV logs alone cannot?

**Purpose:** Typed, validated interchange between Python modules and JSONL persistence.

**Reason:** CSV schemas are flat and phase-specific (`entropy_logs.csv`, `ml_predictions.csv`). Cross-layer RCA needs structured nested evidence with stable enum values.

**Implementation:** Frozen dataclasses in `models.py` with explicit fields (e.g., `VerificationStageResult`, `contributing_signals` on `RootCauseReport`).

**Runtime:** Planes append JSONL; dashboard/API reads via `from_dict`/`from_json`.

**Limits:** Legacy CSV formats are **not** replaced by Foundation; they coexist for backward compatibility.

**Related:** `RUNTIME_FLOW.md`

---

## Package Structure & Dependency Rules

### Q4. Why is the package named `shared_contracts` and not `common`?

**Purpose:** Make import purpose obvious in a multi-package SDN codebase.

**Reason:** `common/` is too generic (collision risk). `intellishield_events/` implies an event bus. `shared_contracts` matches snake_case siblings (`entropy_engine`, `ml_models`).

**Implementation:** Top-level package with explicit docstring dependency rules in `__init__.py`.

**Runtime:** `from shared_contracts import VerificationResult, VerificationStatus` — no controller import side effects.

**Limits:** Name does not imply runtime enforcement; discipline is documented + tested.

**Related:** `FOUNDATION_SHARED_CONTRACTS.md` (design note)

---

### Q5. What does “dependency LEAF” mean for Foundation?

**Purpose:** Keep contracts importable from anywhere without circular imports.

**Reason:** Controller imports verification; verification must not import controller. Leaf placement breaks cycles.

**Implementation:** `shared_contracts` imports **stdlib only** (plus internal submodules). Must NOT import: `controller`, `ml_models`, `mitigation`, `dashboard`, `evaluation`, `traffic_generator`, `rl_engine`, `entropy_engine`, `advanced_analytics`.

**Runtime:** Safe to import at module load in OsKen greenlets without triggering model load or network I/O.

**Limits:** Ops profile reads `INTELLISHIELD_OPS_PROFILE` from env — minimal, intentional exception for policy resolution.

**Related:** `DEVELOPER_GUIDE.md`

---

### Q6. Can Foundation import mitigation or fusion code?

**No** — that would invert the graph and create circular dependencies.

**Purpose:** Preserve acyclic architecture.

**Reason:** Mitigation and fusion depend on contract types, not vice versa.

**Implementation:** Enforcement is convention + code review; `__init__.py` documents the rule.

**Runtime:** If a contract needs mitigation constants, higher layers inject values (e.g., `VerificationConfig` imports legacy constants from mitigation — acceptable because verification is **above** contracts, not inside them).

**Limits:** `verification/config.py` importing `MIN_CONFIDENCE_TO_BLOCK` is verification-layer alignment, not Foundation importing mitigation.

**Related:** [R7_QNA.md](06_R7_QNA.md) Q on config alignment

---

### Q7. What modules exist under `shared_contracts/` and what does each do?

| Module | Role |
|--------|------|
| `enums.py` | Shared enumerations (`DetectorType`, `VerificationStatus`, `Severity`, …) |
| `models.py` | Frozen DTO dataclasses with validation in `__post_init__` |
| `serialize.py` | JSON-safe `to_dict` / `from_dict` / `to_json` / `from_json` |
| `timeutil.py` | UTC-aware timestamps, ISO-8601 `Z` formatting, legacy parse helpers |
| `ops_profile.py` | Lab vs production RL confidence gate policy |
| `__init__.py` | Curated public API surface |

**Related:** [FOUNDATION.md](../../02_Novelties/01_Foundation.md)

---

## Enums

### Q8. Why use enums instead of raw strings for detector and verification status?

**Purpose:** Prevent typos and enable exhaustive handling in fusion/verification.

**Reason:** `"ATTACK"` vs `"attack"` vs `"Attack"` caused silent gate failures in early prototypes.

**Implementation:** `str, Enum` subclasses (e.g., `VerificationStatus.PENDING`, `DetectionDecision.ATTACK`).

**Runtime:** Serialized as string values in JSONL; deserialized back to enum instances via `serialize.py` registry.

**Limits:** Legacy CSV may still use free-form strings; adapters normalize at boundaries.

**Related:** `GLOSSARY.md`

---

### Q9. What enums are defined in Release 1.0 Foundation?

Representative set:

- **Detection plane:** `DetectorType`, `DetectorHealth`, `DetectionDecision`
- **Security outcomes:** `Severity`, `VerificationStatus`, `AlertType`
- **Model lifecycle (future R1/R9):** `ModelStatus`, `CandidateStatus`, `ValidationStatus`
- **Twin scaffolding (R3 code present; live DoD out of R1.0):** `TwinRunPurpose`, `TwinRunStatus`, `TwinLabelSource`, `TwinOutcomeCode`

**Related:** `shared_contracts/enums.py`

---

### Q10. What is `DetectorType.SSL` if R2 is not implemented?

**Purpose:** Reserve enum value for future SSL/zero-day detector integration.

**Reason:** Adding enum members later is easier than renaming persisted JSONL records.

**Implementation:** Enum exists; no live SSL detector adapter in Release 1.0.

**Runtime:** Unused in production paths — **R2 Not implemented**.

**Limits:** Do not assume SSL evidence in fusion weights or verification stages.

**Related:** [README.md](README.md) status table

---

### Q11. How does `DetectionDecision` align with legacy ML/entropy log statuses?

**Purpose:** Bridge old string statuses to typed decisions.

**Reason:** Entropy uses `ALERT`; ML uses `ATTACK`/`SUSPICIOUS`/`NORMAL`.

**Implementation:** Enum string values match existing log vocabulary; helper `parse_detection_decision()` accepts aliases.

**Runtime:** Fusion adapters map heterogeneous detector outputs into `DetectionDecision`.

**Limits:** Unknown strings may map to `UNKNOWN` or `NONE` depending on caller.

**Related:** [R6_COLLABORATIVE_DETECTION.md](../../02_Novelties/04_R6_Collaborative_Detection.md)

---

### Q12. What are the four `VerificationStatus` values and when is each used?

| Status | Meaning |
|--------|---------|
| `PENDING` | Attack streak incomplete (`attack_confirm`) |
| `INELIGIBLE` | Warm-up, low confidence, no attacker, policy exclude, or fail-closed error |
| `VERIFIED` | `mitigation_eligible=True` under current policy |
| `REJECTED` | No actionable detection evidence this cycle |

**Related:** [R7_QNA.md](06_R7_QNA.md), [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md)

---

## DTOs (Models)

### Q13. What is a DTO in this codebase?

**Purpose:** Immutable data transfer object describing one record exchanged between planes.

**Reason:** Dataclasses give IDE autocomplete, field validation, and stable JSON shape.

**Implementation:** `@dataclass(frozen=True)` in `models.py` with `schema_version: str = SCHEMA_VERSION`.

**Runtime:** Written to JSONL, returned from engines, projected to dashboard API.

**Limits:** DTOs never hold live OpenFlow handles, model objects, or sockets.

**Related:** `GLOSSARY.md` — **DTO**

---

### Q14. Which DTOs are actively used in Release 1.0 runtime?

| DTO | Primary consumer |
|-----|------------------|
| `DetectorResult`, `DetectionEvent` | Detector adapters, fusion input |
| `CorrelationResult` | R4 correlation engine |
| `FusedDecision` | R6 fusion → R7 input |
| `VerificationResult`, `VerificationStageResult` | R7 → mitigation / R8 |
| `RootCauseReport` | R5 RCA |
| `AlertEvent` | R8 alerting + dashboard |
| Twin DTOs | R3 package — **live fidelity out of R1.0 DoD** |

**Related:** `RUNTIME_FLOW.md`

---

### Q15. What fields does `VerificationResult` carry?

**Purpose:** Single record describing one verification cycle outcome.

**Key fields:** `verification_id`, `timestamp`, `event_id`, `status`, `confidence` (unit 0–1), `stages[]`, `attacker_mac`, `victim_mac`, `mitigation_eligible`, `reason`, `schema_version`.

**Reason:** R8 severity, R5 RCA, and dashboard need structured stage-level audit trail.

**Implementation:** Built by `VerificationEngine.verify()` in `verification/engine.py`.

**Runtime:** Persisted to `logs/verification_trace.jsonl` via `verification/trace.py`.

**Related:** [R7_QNA.md](06_R7_QNA.md)

---

### Q16. What fields does `AlertEvent` carry?

**Purpose:** Unified security alert for R8 persistence and dashboard.

**Key fields:** `alert_id`, `timestamp`, `severity`, `alert_type`, `title`, `message`, `event_id`, `source`, `rca_report_id`, `mitigation_ref`, `mitigation_status`, `dedup_key`, `evidence`, `schema_version`.

**Reason:** Decouple alert presentation from raw verification dicts; support dedup keys and future RCA links.

**Implementation:** Created by `alerting/factory.py` from `VerificationResult`.

**Runtime:** Appended to `logs/alerts.jsonl`.

**Related:** [R8_QNA.md](08_R8_QNA.md)

---

### Q17. Why are all contract dataclasses frozen?

**Purpose:** Immutability after construction — safe to pass across OsKen greenlets and cache keys.

**Reason:** Mutable shared state caused streak/confusion bugs in early controller code.

**Implementation:** `frozen=True`; updates create new instances (or new records per cycle).

**Runtime:** Serialization treats them as value objects.

**Limits:** Large nested `evidence` dicts are still mutable if callers retain references — prefer copying at boundaries.

**Related:** `verification/engine.py` docstring on concurrency

---

### Q18. What validation happens in model `__post_init__`?

**Purpose:** Reject impossible field values at construction time.

**Examples:** Confidence outside [0,1] where applicable; empty required IDs; invalid enum combinations.

**Reason:** Fail early in tests rather than corrupt JSONL.

**Implementation:** Per-model checks in `models.py`.

**Runtime:** Adapters also sanitize NaN/inf confidence before DTO construction (fusion tests cover this).

**Limits:** Not all legacy dict inputs are validated — only typed construction paths.

**Related:** `tests/test_shared_contracts_foundation.py`

---

## Schema Versioning

### Q19. What is `SCHEMA_VERSION` and where is it defined?

**Purpose:** Explicit contract version stamp on every DTO.

**Reason:** Enables future readers to branch on schema evolution without guessing from field presence.

**Implementation:** Constant `SCHEMA_VERSION = "1.0"` in `models.py`; each dataclass has `schema_version: str = SCHEMA_VERSION`.

**Runtime:** Included in JSONL records and trace output.

**Limits:** Release 1.0 has **no migration registry** — version is documentary + forward-compatible hook.

**Related:** [FOUNDATION.md](../../02_Novelties/01_Foundation.md)

---

### Q20. How should we evolve schema from 1.0 to 1.1?

**Purpose:** Safe additive evolution without breaking lab reproducibility.

**Recommended approach:**
1. Bump `SCHEMA_VERSION` on changed DTOs only.
2. Add optional fields with defaults — never remove/rename in-place without migration.
3. Update `serialize.py` registries if new types added.
4. Extend `tests/test_shared_contracts_foundation.py` roundtrips.

**Reason:** JSONL logs from paper experiments must remain parseable.

**Runtime:** `from_dict` ignores unknown keys if implementation allows; enum registry must know new types.

**Limits:** No automatic migrator in Release 1.0.

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q21. Does every JSONL line include `schema_version`?

**Purpose:** Per-record versioning for mixed-era log files.

**Implementation:** DTO serialization includes `schema_version`; trace writer in `verification/trace.py` copies it explicitly.

**Runtime:** Dashboard readers may ignore version today; evaluation scripts should log warnings on mismatch.

**Limits:** Legacy CSV files do not carry `schema_version`.

**Related:** `verification/trace.py`, `alerting/persistence.py`

---

## Serialization

### Q22. Why not use Python `pickle` for contract persistence?

**Purpose:** Safe, language-agnostic, auditable logs.

**Reason:** Pickle is executable, opaque, and unsuitable for IEEE artifact bundles.

**Implementation:** `serialize.py` — explicit JSON encoding with `_type` discriminator on dataclasses.

**Runtime:** `to_json(obj)` produces sorted-key JSON strings for deterministic diffs in tests.

**Limits:** Only registered types in `_MODEL_BY_NAME` / `_ENUM_BY_NAME` deserialize automatically.

**Related:** `shared_contracts/serialize.py` module docstring

---

### Q23. How does `to_dict` / `from_dict` work?

**Purpose:** Round-trip contracts without pickle or dynamic import from payload.

**Implementation:**
- Enums → string value
- `datetime` → ISO-8601 UTC with `Z` via `format_ts`
- Dataclasses → dict with `_type` key for disambiguation
- Nested lists/dicts handled recursively

**Runtime:** `alerting/persistence.py` uses `to_dict` before JSONL append; reads use `from_dict(..., AlertEvent)`.

**Limits:** `from_dict` without `cls` requires `_type` in payload; unknown types raise explicit errors.

**Related:** `tests/test_shared_contracts_foundation.py`

---

### Q24. What is forbidden in serialized payloads?

**Forbidden:** pickle, live ML models, controller/OpenFlow objects, `eval`, dynamic class import from untrusted payload.

**Purpose:** Security and reproducibility for lab artifacts.

**Reason:** JSONL may be shared in papers/supplements.

**Implementation:** Serialize only registered contract fields and plain JSON types in `evidence` dicts.

**Runtime:** R8 scrubs sensitive keys (`password`, `token`, `secret`, …) from evidence before persist.

**Related:** [R8_QNA.md](08_R8_QNA.md), `AlertingConfig.evidence_denied_keys`

---

### Q25. How are timestamps serialized?

**Purpose:** Consistent UTC semantics across planes.

**Implementation:** Internal fields use timezone-aware UTC (`timeutil.utc_now()`); serialized as `YYYY-MM-DDTHH:MM:SSZ`.

**Reason:** Avoid local-time ambiguity in multi-machine lab setups.

**Runtime:** Legacy CSV `YYYY-MM-DD HH:MM:SS` unchanged; `parse_ts` / `format_ts` bridge adopters.

**Limits:** P0.3 experiment windows still parse legacy CSV format for ground truth.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.3

---

## Ops Profile

### Q26. What is `ops_profile.py` and why is it in Foundation?

**Purpose:** Separate **operational policy** (lab vs production) from algorithm code.

**Reason:** RL adapts confidence gate; demos need frozen thresholds for reproducible IEEE figures.

**Implementation:** `OpsProfile` enum (`LAB`, `PRODUCTION`), `get_ops_policy()`, env `INTELLISHIELD_OPS_PROFILE`.

**Runtime:** RL threshold adapter clamps to policy bounds before R7 confidence gate.

**Limits:** “Production” here means adaptive bounds in research — not internet-hardened production deployment.

**Related:** [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md)

---

### Q27. What are the lab vs production confidence gate bounds?

| Profile | Freeze RL gate? | Default | Min | Max |
|---------|-----------------|---------|-----|-----|
| **lab** | Yes | 60% | 60% | 60% |
| **production** | No (adaptive) | 60% | 55% | 75% |

**Purpose:** Lab freezes at 60%; production allows RL to adapt within ~55–75%.

**Implementation:** Constants in `ops_profile.py`; `MAX_RL_CONFIDENCE_GATE_PERCENT=75` referenced in docs.

**Runtime:** `export INTELLISHIELD_OPS_PROFILE=lab` before controller start for demos.

**Limits:** Gate still compared in **percent** at R7; RL internal state may use 0–1 unit.

**Related:** [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md), `tests/test_ops_confidence_calibration.py`

---

### Q28. How do I set ops profile for a viva demo?

```bash
export INTELLISHIELD_OPS_PROFILE=lab
osken-manager controller/flow_monitor.py
```

**Purpose:** Reproducible mitigation eligibility when fused confidence hovers near 60%.

**Reason:** Without lab profile, adaptive RL may raise gate above fused confidence → many INELIGIBLE cycles.

**Runtime:** Default env value is `production` if unset.

**Related:** `TROUBLESHOOTING.md`

---

## Compatibility & Adoption

### Q29. Do detectors have to return DTOs immediately?

**No** — Foundation is infrastructure; incremental adoption is intentional.

**Purpose:** Avoid big-bang refactor of entropy/ML paths.

**Reason:** `__init__.py` states detectors may continue returning plain dicts until adapters convert.

**Implementation:** Fusion/verification adapters normalize dicts → typed evidence at plane boundaries.

**Runtime:** Release 1.0 uses mixed dict + DTO internally.

**Limits:** New planes (R4–R8) should emit typed contracts at persistence boundary.

**Related:** `DEVELOPER_GUIDE.md`

---

### Q30. How does Foundation relate to legacy CSV schemas?

**Purpose:** Coexistence during migration.

**Reason:** Phase 2 entropy CSV alerts (`detection_alerts.csv`) remain for dashboard legacy endpoint `/api/alerts`.

**Implementation:** Foundation JSONL is additive (`fused_decisions.jsonl`, `verification_trace.jsonl`, `alerts.jsonl`).

**Runtime:** R8 alerts are **not** the same as legacy entropy CSV alerts.

**Limits:** Do not assume one-to-one mapping between CSV rows and `AlertEvent` records.

**Related:** [R8_QNA.md](08_R8_QNA.md)

---

### Q31. Can twin DTOs be used in Release 1.0 experiments?

**Code present:** Twin models (`TwinRun`, `TwinTopology`, …) exist in `models.py`.

**Runtime DoD:** **R3 live twin fidelity is out of Release 1.0 scope.**

**Purpose:** Scaffold future digital-twin validation without blocking R4–R8 delivery.

**Reason:** Twin enums/DTOs serialize correctly but live Mininet fidelity is not a Release 1.0 acceptance criterion.

**Related:** [README.md](README.md), `GLOSSARY.md` — **Twin (R3)**

---

## Testing

### Q32. What does `tests/test_shared_contracts_foundation.py` cover?

**Purpose:** Guard the contract layer as a dependency leaf.

**Typical coverage:**
- Enum parse roundtrips
- DTO construction validation
- `to_dict` / `from_dict` / `to_json` / `from_json` symmetry
- Timestamp formatting
- Ops profile resolution (`lab` aliases: `demo`, `dev`)
- Schema version presence

**Reason:** Regressions here cascade to all planes.

**Runtime:** Run with project pytest suite before merging contract changes.

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

### Q33. Should I add Foundation tests when adding a new enum value?

**Yes** — always extend foundation tests for new enum/DTO fields.

**Purpose:** Keep serialization registry complete.

**Implementation:** Update `_ENUM_BY_NAME` or `_MODEL_BY_NAME` in `serialize.py` + test roundtrip.

**Limits:** Do not add enum values for unimplemented detectors without documenting **Not implemented** status.

**Related:** Q10 above

---

## Common Mistakes

### Q34. What happens if I import controller from `shared_contracts`?

**Purpose:** Document anti-pattern.

**Reason:** Creates circular import risk and violates leaf rule.

**Implementation:** Not blocked by tooling — code review and architecture docs enforce.

**Runtime symptom:** ImportError or subtle initialization order bugs at OsKen startup.

**Fix:** Move shared logic into `shared_contracts` or pass values via function arguments from controller.

**Related:** Q5, Q6

---

### Q35. What if ML confidence is 0–100 but I store it as unit in `VerificationResult`?

**Purpose:** Clarify dual-scale confidence in the stack.

**Reason:** ML `predict()` returns 0–100; R7 gate compares **percent**; `VerificationResult.confidence` is **unit** 0–1.

**Implementation:** P0.1 normalizes RL observation; R7 `_parse_confidence_percent` normalizes gate input; result stores unit confidence.

**Runtime mistake:** Comparing unit confidence directly to `MIN_CONFIDENCE_TO_BLOCK` (60.0) without scaling.

**Fix:** Follow `verification/engine.py` normalization paths.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.1, [R7_QNA.md](06_R7_QNA.md)

---

### Q36. What if I add heavy dependencies to `shared_contracts`?

**Avoid** — violates leaf stdlib-only rule.

**Purpose:** Keep contracts importable in minimal test environments.

**Reason:** numpy/pandas in Foundation would drag ML into every plane import.

**Implementation:** Heavy logic stays in feature packages; only plain types in contracts.

**Runtime:** CI foundation tests run fast without GPU/model load.

**Related:** [FOUNDATION.md](../../02_Novelties/01_Foundation.md) future extensions

---

### Q37. Can I mutate `evidence` dict inside a frozen DTO?

**Technically yes** if you retain a reference to the nested dict — **don't**.

**Purpose:** Preserve value-object semantics.

**Reason:** Shared mutable evidence causes cross-plane leakage.

**Fix:** Copy dicts at adapter boundaries; treat DTOs as immutable snapshots.

**Related:** Q17

---

## Best Practices

### Q38. When adding a new plane (e.g., future R2), what Foundation steps are required?

1. Add enum values if new detector/source types needed.
2. Add or extend DTOs with `schema_version`.
3. Register types in `serialize.py`.
4. Export from `__init__.py` if public.
5. Extend `test_shared_contracts_foundation.py`.
6. Document **implemented vs not** in release docs.

**Purpose:** Consistent onboarding for new requirements.

**Related:** `DEVELOPER_GUIDE.md`

---

### Q39. Should new JSONL logs use Foundation serialization?

**Yes** for cross-plane records (fusion, verification, alerts, correlation).

**Purpose:** One parser for dashboard and evaluation.

**Implementation:** `to_dict` → `json.dumps` append line.

**Limits:** High-volume raw telemetry CSV may remain flat for pandas workflows (P0.6 metrics).

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.5 bundles

---

### Q40. How should viva answers cite Foundation design?

**Suggested framing:**
- “Foundation is the typed lingua franca between detection, fusion, verification, and alerting.”
- “Leaf dependency prevents circular imports in the OsKen controller.”
- “Schema version 1.0 enables future evolution without breaking paper artifacts.”

**Related:** [RESEARCH_JUSTIFICATION.md](../../02_Novelties/10_Research_Justification.md) (when present), `FAQ.md`

---

## Future Extensions

### Q41. Will R2 SSL detector enums be activated?

**Planned:** `DetectorType.SSL` exists.

**Release 1.0:** **R2 Not implemented** — no SSL adapter, no verification stage, no fusion weight.

**Purpose:** Placeholder for zero-day/SSL research track.

**Related:** [README.md](README.md)

---

### Q42. Will there be a schema migration tool?

**Not in Release 1.0.**

**Purpose:** Future tooling to upgrade JSONL between schema versions.

**Workaround:** Evaluation scripts branch on `schema_version` field when reading mixed logs.

**Related:** Q20

---

### Q43. Should Foundation grow an event bus?

**No** — out of scope for Release 1.0.

**Purpose:** Keep Foundation as passive contracts; orchestration stays in controller `flow_monitor.py`.

**Reason:** Event buses add operational complexity inappropriate for lab prototype.

**Related:** [ARCHITECTURE.md](../../03_System_Design/01_Overall_Architecture.md)

---

### Q44. How does Foundation support IEEE reproducibility?

**Purpose:** Typed artifacts in experiment bundles (P0.5).

**Implementation:** Bundles hash JSON/CSV including `metrics_report.json`; contracts ensure stable field names in machine-readable outputs.

**Runtime:** `evaluation/experiment_bundle.py` collects logs; DTO schema versions document contract era.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.5, [P0_QNA.md](02_P0_QNA.md) P0.6

---

## Quick Reference

### Q45. Foundation checklist for new contributors

- [ ] Read `GLOSSARY.md`
- [ ] Never import controller from `shared_contracts`
- [ ] Use enums for statuses severities and detector types
- [ ] Include `schema_version` on new DTOs
- [ ] Roundtrip test via `serialize.py`
- [ ] Set `INTELLISHIELD_OPS_PROFILE=lab` for demos
- [ ] Cross-link changes to [../../02_Novelties/01_Foundation.md](../../02_Novelties/01_Foundation.md)

**Related modules:** `shared_contracts/*`, `tests/test_shared_contracts_foundation.py`, `tests/test_ops_confidence_calibration.py`

---

*Last aligned with Release 1.0 repository state. For operational runbooks see ``../../../``.*
