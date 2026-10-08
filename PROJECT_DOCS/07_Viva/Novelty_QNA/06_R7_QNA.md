# R7 Verification Engine Q&A — Release 1.0

Related: [../../02_Novelties/05_R7_Verification.md](../../02_Novelties/05_R7_Verification.md) · `../../../RUNTIME_FLOW.md` · [../../02_Novelties/09_Ops_Calibration.md](../../02_Novelties/09_Ops_Calibration.md) · [P0_QNA.md](02_P0_QNA.md) · [R8_QNA.md](08_R8_QNA.md) · [FOUNDATION_QNA.md](01_Foundation_QNA.md)

R7 is the **mitigation safety gate**. Package: `verification/`. It decides whether a detection cycle is eligible to install OpenFlow DROP rules.

> **PROJECT_DOCS copy** — adapted from `R7_QNA.md`. Novelty manuals: [`../../02_Novelties/`](../../02_Novelties/README.md). Quick viva bank: [`../08_Novelty_Questions.md`](../08_Novelty_Questions.md).

---

## Overview

### Q1. What is R7 in one sentence?

**Purpose:** Multi-stage verification engine that converts fused/legacy predictions into a typed `VerificationResult` with explicit `mitigation_eligible` flag.

**Reason:** Direct “alert → DROP” paths cause false blocks during warm-up, single-sample noise, and low-confidence fusion outputs.

**Implementation:** `VerificationEngine.verify(VerificationInput)` in `verification/engine.py`.

**Runtime:** Called each controller poll cycle after R6 fusion (or legacy dual-path).

**Limits:** Does not install OpenFlow rules itself — actuation is mitigation engine after VERIFIED.

**Related:** [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md)

---

### Q2. Why does verification exist as a separate plane from fusion (R6)?

**Purpose:** Separation of **opinion combination** (R6) from **actuation safety** (R7).

**Reason:** Fusion may output ATTACK with moderate confidence; verification applies temporal confirmation, warm-up, identification, and policy gates before DROP.

**Implementation:** R6 → `FusedDecision`; controller builds `VerificationInput`; R7 → status.

**Runtime:** R4 correlation is advisory — does not alone authorize mitigation.

**Related:** [R6_COLLABORATIVE_DETECTION.md](../../02_Novelties/04_R6_Collaborative_Detection.md)

---

### Q3. What modules comprise the R7 package?

| Module | Role |
|--------|------|
| `engine.py` | Ordered stage pipeline |
| `config.py` | Thresholds aligned with mitigation |
| `confirmation_state.py` | Attack streak utility |
| `adapters.py` | Confidence normalization helpers |
| `runtime.py` | Controller integration hook |
| `legacy_decision.py` | Parity with pre-R7 gates |
| `trace.py` | JSONL trace persistence |
| `stages.py` | Stage name enum + order |

**Related:** `PROJECT_STRUCTURE.md`

---

### Q4. What tests cover R7?

| File | Focus |
|------|-------|
| `tests/test_verification_engine_r71.py` | Stages |
| `tests/test_verification_golden_r72.py` | Golden cases |
| `tests/test_verification_runtime_r73.py` | Runtime integration |
| `tests/test_verification_hardening_r74.py` | Fail-closed |
| `tests/test_verification_perf_r74.py` | Latency |
| `tests/test_ops_confidence_calibration.py` | Lab gate freeze |

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

## Verification Workflow & Stages

### Q5. What is the ordered stage pipeline?

```
WARMUP
  → DETECTION_EVIDENCE
  → ATTACK_CONFIRMATION
  → CONFIDENCE_GATE
  → ATTACKER_IDENTIFICATION
  → MITIGATION_ELIGIBILITY (AUTO_MITIGATE_POLICY)
  → VERIFIED | PENDING | INELIGIBLE | REJECTED
```

**Purpose:** Deterministic audit trail — each stage appends `VerificationStageResult`.

**Implementation:** `STAGE_ORDER` in `verification/stages.py`; early exit on failure with appropriate terminal status.

**Runtime:** Stages recorded in `VerificationResult.stages[]` and trace JSONL.

**Related:** `GLOSSARY.md`

---

### Q6. What are the four terminal verification statuses?

| Status | Meaning | Typical `mitigation_eligible` |
|--------|---------|--------------------------------|
| **VERIFIED** | All gates passed under policy | `True` |
| **PENDING** | Attack streak incomplete | `False` |
| **INELIGIBLE** | Evidence exists but safety gate failed | `False` |
| **REJECTED** | No actionable detection evidence | `False` |

**Purpose:** Downstream consumers (mitigation, R8, RCA) branch on status + eligibility bit.

**Implementation:** `VerificationStatus` enum in Foundation.

**Runtime:** R8 default alerts on **VERIFIED only**.

**Related:** [R8_QNA.md](08_R8_QNA.md)

---

### Q7. What is stage WARMUP for?

**Purpose:** Block mitigation during early controller cycles while stats baselines stabilize.

**Reason:** First polls after start often have incomplete flow stats → spurious ATTACK labels.

**Implementation:** Pass when `warmup_cycles_done > warmup_threshold` (default **3**).

**Failure:** INELIGIBLE, `reason=warmup_active`.

**Runtime:** Controller increments `warmup_cycles_done` per switch per poll.

**Related:** [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md)

---

### Q8. Why is warm-up threshold 3 and not 0 or 10?

**Purpose:** Balance fast demo startup vs stability.

**Reason:** With MONITOR_INTERVAL ~5s, 3 cycles ≈ 15s — enough for initial flow establishment in Mininet lab.

**Implementation:** `VerificationConfig.warmup_threshold = 3`.

**Limits:** Tunable via config injection — default chosen for lab reproducibility.

**Runtime:** Symptom “always INELIGIBLE warm-up” if threshold raised or cycles not incrementing.

**Related:** `TROUBLESHOOTING.md`

---

### Q9. What is stage DETECTION_EVIDENCE?

**Purpose:** Require prediction status in mitigation-eligible set before proceeding.

**Implementation:** Pass when `status in mitigate_on_status` (default `{"ATTACK", "SUSPICIOUS"}`).

**Failure:** **REJECTED**, `reason=no_detection_evidence`.

**Reason:** NORMAL cycles should not consume confirmation streak or identification work.

**Runtime:** Entropy-only ALERT paths may use different upstream mapping — see controller adapter.

**Related:** `verification/config.py`

---

### Q10. What is stage ATTACK_CONFIRMATION?

**Purpose:** Require consecutive ATTACK cycles before treating attack as confirmed.

**Implementation:** For `status == ATTACK`: pass when `attack_streak >= attack_confirm` (default **2**).

**Failure:** **PENDING**, `reason=attack_pending_confirmation`.

**Reason:** Single-cycle ML spike should not trigger DROP.

**Runtime:** SUSPICIOUS skips streak requirement (stage passes with `no_streak_required_for_SUSPICIOUS`).

**Related:** `verification/confirmation_state.py`

---

### Q11. Why PENDING instead of INELIGIBLE for incomplete streak?

**Purpose:** Semantic distinction — attack **seen** but **not yet confirmed**.

**Reason:** Operators/analytics can count “emerging attacks”; R8 can optionally alert on PENDING (default **off**).

**Implementation:** Terminal status PENDING with partial stage trail.

**Runtime:** Next ATTACK cycle may reach VERIFIED if confidence and identification succeed.

**Related:** [R8_QNA.md](08_R8_QNA.md) Q on `alert_on_pending`

---

### Q12. What is stage CONFIDENCE_GATE?

**Purpose:** Require prediction confidence ≥ dynamic threshold before mitigation.

**Implementation:** Compare `raw_conf` (percent) to `min_confidence_percent` (default **60.0** = `MIN_CONFIDENCE_TO_BLOCK`).

**Failure:** INELIGIBLE, `reason=confidence_below_threshold`.

**Runtime:** RL adapter may override threshold; ops profile clamps override.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q27, [P0_QNA.md](02_P0_QNA.md) P0.1

---

### Q13. How is confidence normalized at the gate?

**Purpose:** Accept heterogeneous detector scales at input; gate compares **percent**.

**Implementation:** `_parse_confidence_percent()` in engine; stores unit confidence [0,1] on result.

**Reason:** ML 0–100, fusion may emit unit — normalization prevents scale bugs.

**Runtime:** Entropy paths may set `force_entropy_confidence_floor` for static floor behavior.

**Related:** `verification/adapters.py`, `verification/engine.py`

---

### Q14. What is `MIN_CONFIDENCE_TO_BLOCK` default?

**60.0 percent** — aligned with `mitigation/mitigation_engine.py`.

**Purpose:** Single source of truth via `VerificationConfig` importing mitigation constant.

**Reason:** Avoid R7/mitigation threshold drift.

**Runtime:** Below 60% → warning/skip block in mitigation even if mistakenly VERIFIED (defense in depth).

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.4 Q27

---

### Q15. How does RL adapt the confidence gate?

**Purpose:** Learn threshold from recent attack/FP history via PPO.

**Implementation:** Controller passes `min_confidence_percent` on `VerificationInput` from RL decision.

**Runtime clamps:** `INTELLISHIELD_OPS_PROFILE=lab` freezes at 60%; production clamps 55–75%.

**Limits:** RL cannot bypass identification or warm-up — only confidence stage threshold.

**Related:** `shared_contracts/ops_profile.py`, `tests/test_ops_confidence_calibration.py`

---

### Q16. What is stage ATTACKER_IDENTIFICATION?

**Purpose:** Pick concrete `(attacker_mac, victim_mac)` pair for DROP rules.

**Implementation:** Reuses `MitigationEngine._identify_attackers` via injectable callable — **no duplicated logic**.

**Failure:** INELIGIBLE, `reason=attacker_not_identified`.

**Runtime:** Requires non-empty `flow_features` with identifiable MACs.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.4

---

### Q17. Does identification install OpenFlow rules?

**No.**

**Purpose:** R7 is pure decision — no datapath side effects.

**Implementation:** Lazy `MitigationEngine(auto_mitigate=False)` for helper methods only.

**Reason:** Verification must be replayable in tests without mock switches.

**Runtime:** Actual DROP after separate mitigation call post-VERIFIED.

**Related:** `verification/engine.py` docstring

---

### Q18. What is stage MITIGATION_ELIGIBILITY / AUTO_MITIGATE_POLICY?

**Purpose:** Final policy check — auto_mitigate enabled and status in `AUTO_MITIGATE_STATUS` (default `{"ATTACK"}`).

**Implementation:** SUSPICIOUS may pass earlier stages but fail auto-mitigate policy.

**Failure:** INELIGIBLE, policy-specific reason.

**Success:** **VERIFIED**, `mitigation_eligible=True`.

**Runtime:** Matches legacy `MitigationEngine.handle_alert` gating semantics.

**Related:** `legacy_decision.py`

---

### Q19. When is status VERIFIED exactly?

**Purpose:** Unambiguous actuation authorization.

**Condition:** All stages pass including identification; policy allows auto mitigation; result built with `mitigation_eligible=True`.

**Invariant:** `mitigation_eligible == (status == VerificationStatus.VERIFIED)` under current policy.

**Runtime:** Mitigation engine checks VERIFIED before `block_*` calls.

**Related:** Golden tests in `test_verification_golden_r72.py`

---

### Q20. When is status REJECTED vs INELIGIBLE?

| Case | Status |
|------|--------|
| NORMAL / no evidence | **REJECTED** |
| Warm-up active | **INELIGIBLE** |
| Low confidence | **INELIGIBLE** |
| No attacker MAC | **INELIGIBLE** |
| Engine exception | **INELIGIBLE** (fail-closed) |
| Streak incomplete | **PENDING** (not INELIGIBLE) |

**Purpose:** REJECTED = “nothing to verify”; INELIGIBLE = “something seen but unsafe to act”.

**Related:** `GLOSSARY.md`

---

## Eligibility & Mitigation Gate

### Q21. What does `mitigation_eligible=True` authorize?

**Purpose:** Controller may invoke mitigation engine to install DROP rules.

**Reason:** Explicit bit avoids inferring eligibility from status strings alone (edge policy cases).

**Implementation:** Set only on VERIFIED path in `_result()`.

**Runtime:** R8 may alert; blocklist manager consulted at mitigation layer.

**Limits:** Eligibility ≠ guaranteed block — blocklist/TTL/protected MACs may still skip.

**Related:** `RUNTIME_FLOW.md`

---

### Q22. Can SUSPICIOUS status ever reach VERIFIED?

**Depends on policy.**

**Purpose:** SUSPICIOUS is in `MITIGATE_ON_STATUS` but not default `AUTO_MITIGATE_STATUS`.

**Implementation:** May pass evidence + confidence + identification but fail AUTO_MITIGATE → INELIGIBLE.

**Reason:** Mid-band fusion state for analyst attention without automatic DROP.

**Runtime:** Tune `auto_mitigate_status` only with care — increases FP block risk.

**Related:** `mitigation/mitigation_engine.py`

---

### Q23. What is fail-closed behavior?

**Purpose:** Safety on unexpected errors.

**Implementation:** Any exception in `verify()` → INELIGIBLE, `reason=verification_error_fail_closed`, stage `ENGINE_ERROR`.

**Reason:** SDN security prefers missed block over erroneous mass DROP.

**Runtime:** Logged at ERROR with traceback; controller continues poll loop.

**Related:** `tests/test_verification_hardening_r74.py`

---

### Q24. Why fail-closed instead of fail-open?

**Purpose:** Align with security operations norm — “when in doubt, do not block production traffic.”

**Reason:** False block disrupts legitimate flows; false INELIGIBLE delays mitigation but preserves connectivity.

**Research note:** IEEE evaluation tracks mitigation latency — fail-closed may increase latency on bugs (visible in tests).

**Related:** `GLOSSARY.md` — **Fail-closed (R7)**

---

### Q25. How does R7 prevent duplicate mitigation?

**Purpose:** Avoid reckless re-blocks on same attacker.

**Layers:**
1. **Verification streak** — requires sustained ATTACK before VERIFIED
2. **Attacker identification** — concrete entity target
3. **Blocklist manager** — mitigation checks `should_block()` before new DROP
4. **Alert dedup** — R8 responsibility, not R7

**Implementation:** Verification itself does not dedup blocks — mitigation/blocklist does.

**Runtime:** Re-VERIFIED on same MAC may skip if block active.

**Related:** [R8_QNA.md](08_R8_QNA.md), [P0_QNA.md](02_P0_QNA.md) P0.4

---

### Q26. Why verification before mitigation (not inline in ML)?

**Purpose:** Centralize all actuation gates in one auditable pipeline.

**Reason:** ML phase predates R6/R7; retrofitting gates into each detector duplicates warm-up/streak/confidence logic.

**Implementation:** Controller orchestrates single `verify()` call per cycle.

**Viva answer:** “Verification is the contract between detection research and SDN actuation safety.”

**Related:** [ARCHITECTURE.md](../../03_System_Design/01_Overall_Architecture.md)

---

## Warm-up Deep Dive

### Q27. What input field drives warm-up?

**`VerificationInput.warmup_cycles_done`** — integer incremented by controller per switch.

**Purpose:** Decouple warm-up from wall clock — tied to poll cycles actually executed.

**Implementation:** Compared strictly: pass if `> warmup_threshold` (not `>=`).

**Runtime:** Cycle 3 with threshold 3 still fails — need cycle 4 pass.

**Related:** `verification/engine.py` stage 1 details

---

### Q28. Is warm-up per-switch or global?

**Per-switch (`dpid`)** in production controller state.

**Purpose:** Multi-switch Mininet topologies may warm at different rates.

**Implementation:** `flow_monitor` tracks warm-up counters per datapath.

**Utility:** `AttackConfirmationState` also keyed by `dpid`.

**Related:** `verification/confirmation_state.py`

---

### Q29. Can warm-up be disabled?

**Purpose:** Testing only — set `warmup_threshold=0` in injected `VerificationConfig`.

**Reason:** Production default 3 is intentional; zero threshold passes immediately when `warmup_cycles_done > 0`.

**Limits:** Not recommended for demo realism.

**Runtime:** Config validation allows `>= 0`.

**Related:** `verification/config.py`

---

## Attack Confirmation & Streak

### Q30. How is `attack_streak` updated?

**Purpose:** Count consecutive ATTACK/SUSPICIOUS (or entropy ALERT) cycles.

**Production:** Controller `flow_monitor` updates before calling `verify()` — must reflect **current** cycle increment.

**Utility:** `AttackConfirmationState.update(dpid, status)` mirrors semantics for tests.

**Rules:** ATTACK/SUSPICIOUS increment; NORMAL resets to 0.

**Related:** `confirmation_state.py` docstring

---

### Q31. Why is `attack_confirm` default 2?

**Purpose:** Two consecutive ATTACK polls ≈ 10s at 5s interval — filters single-sample noise.

**Reason:** Balances burst scenario S4 (short window) vs stability — P0.2 burst 8s may need both polls ATTACK inside burst.

**Implementation:** `VerificationConfig.attack_confirm = 2`.

**Runtime:** First ATTACK → PENDING; second consecutive → confirmation passes.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.2

---

### Q32. Does SUSPICIOUS increment the streak?

**Yes** — `AttackConfirmationState` treats SUSPICIOUS like ATTACK for increment.

**Purpose:** Mid-band fusion may escalate to ATTACK next cycle.

**Implementation:** Status uppercased; membership in `("ATTACK", "SUSPICIOUS")`.

**Limits:** AUTO_MITIGATE may still exclude SUSPICIOUS from final VERIFIED.

**Related:** Q22

---

### Q33. What happens to streak on NORMAL?

**Resets to 0.**

**Purpose:** Non-attack cycles break confirmation — attacker must sustain signal.

**Runtime:** Oscillating ATTACK/NORMAL/ATTACK requires two fresh consecutive ATTACKs.

**Related:** `confirmation_state.py`

---

## Confidence Gate & Ops Profile

### Q34. Why do many lab runs show `confidence_below_threshold`?

**Purpose:** Explain common demo symptom.

**Reason:** Fused calibrated confidence may sit at 55–59% while gate is 60%; production RL may raise gate toward 75% cap.

**Fix:** `export INTELLISHIELD_OPS_PROFILE=lab` freezes gate at 60%.

**Runtime:** Trace stage CONFIDENCE_GATE shows observed vs threshold.

**Related:** `TROUBLESHOOTING.md`

---

### Q35. What is entropy static confidence floor?

**Purpose:** Entropy-only detection path may enforce minimum confidence behavior.

**Implementation:** When `source == "entropy"` or `force_entropy_confidence_floor=True`, `_resolve_min_confidence` uses entropy-specific floor logic.

**Runtime:** Legacy dual-path compatibility during R6 migration.

**Related:** `verification/engine.py` `_resolve_min_confidence`

---

### Q36. How does INTELLISHIELD_OPS_PROFILE affect R7?

| Profile | RL gate behavior | Effect on R7 |
|---------|------------------|--------------|
| `lab` | Frozen 60% | Stable VERIFIED rate for demos |
| `production` | Adaptive 55–75% | RL may raise bar → more INELIGIBLE |

**Purpose:** Separate reproducibility from adaptive research mode.

**Implementation:** `shared_contracts/ops_profile.py`; RL clamp before passing override to verification.

**Related:** [FOUNDATION_QNA.md](01_Foundation_QNA.md) Q26–Q28

---

## False Positives & Policy

### Q37. How does R7 reduce false positive blocks?

**Mechanisms:**
1. Warm-up (transient startup noise)
2. Attack confirmation streak (single spike)
3. Confidence gate ≥ 60%
4. Attacker identification (no vague block)
5. AUTO_MITIGATE status filter
6. Fail-closed on errors

**Purpose:** Layered defense — no single knob eliminates all FPs.

**Runtime:** P0.6 metrics track FP outside attack windows separately.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.6

---

### Q38. Can R7 REJECT a true attack?

**Yes** — if upstream status never enters `mitigate_on_status` (e.g., fusion NORMAL).

**Purpose:** R7 does not re-detect — it verifies upstream opinion.

**Reason:** Detection recall is R6/detector problem; R7 recall is conditional on evidence.

**Runtime:** Improve fusion/detector, not verification thresholds alone.

**Related:** [R6_COLLABORATIVE_DETECTION.md](../../02_Novelties/04_R6_Collaborative_Detection.md)

---

### Q39. What is `legacy_decision.py` for?

**Purpose:** Parity testing against pre-R7 inline gates in controller.

**Reason:** Refactor safety during R7 introduction — golden paths must match prior behavior.

**Implementation:** Shared constants from mitigation imported into `VerificationConfig`.

**Runtime:** Production uses `VerificationEngine`; legacy module for regression comparison.

**Related:** `tests/test_verification_golden_r72.py`

---

## Runtime Integration

### Q40. What is `VerificationInput`?

**Purpose:** R7-specific per-cycle input bundle.

**Key fields:** `dpid`, `prediction`, `explanation`, `flow_features`, `warmup_cycles_done`, `attack_streak`, `event_id`, `min_confidence_percent`, `force_entropy_confidence_floor`.

**Reason:** Explicit contract decouples engine from controller internals.

**Implementation:** Dataclass in `verification/engine.py`.

**Runtime:** Built in `verification/runtime.py` / controller handler.

**Related:** `RUNTIME_FLOW.md`

---

### Q41. What is the runtime flow from fusion to mitigation?

```
Fused / legacy prediction
        ↓
VerificationEngine.verify(VerificationInput)
        ↓
   VERIFIED? ──yes──► MitigationEngine / flow_blocker
        │ no
        ▼
   persist verification trace; no DROP
        ↓
   R5 / R8 may still observe (policy-dependent)
```

**Purpose:** Single diagram for operators.

**Related:** [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md)

---

### Q42. Where are verification traces persisted?

**File:** `logs/verification_trace.jsonl` (default via `verification/trace.py`).

**Purpose:** Append-only audit for viva/debug.

**Implementation:** Bounded records — max ~24KB/line, trimmed stage details.

**Runtime:** Best-effort I/O — failures never crash controller.

**Related:** `DEFAULT_TRACE_FILENAME`

---

### Q43. What appears in a trace record?

**Fields:** `schema_version`, `verification_id`, `event_id`, `timestamp`, `status`, `mitigation_eligible`, `stages[]`, `reason`, optional MACs/confidence.

**Purpose:** Replay why a cycle was INELIGIBLE without debugger.

**Runtime:** Align with `VerificationResult` DTO shape.

**Related:** `verification_result_to_trace_record()`

---

### Q44. Is R7 on the hot path for latency?

**Yes, but designed O(stages) with no I/O inside `verify()`.

**Purpose:** Keep verification CPU-bound and fast.

**Implementation:** Perf tests in `test_verification_perf_r74.py`.

**Runtime:** Trace write is async/best-effort outside engine core.

**Limits:** Identification scans flow_features list — size bounded by switch export.

**Related:** Performance section below

---

## Examples

### Q45. Lab demo command sequence

```bash
export INTELLISHIELD_OPS_PROFILE=lab
osken-manager controller/flow_monitor.py
# In another terminal — run attack scenario
# Tail traces:
tail -f logs/verification_trace.jsonl
```

**Purpose:** Reproducible VERIFIED cycles for viva.

**Related:** [R7_VERIFICATION.md](../../02_Novelties/05_R7_Verification.md)

---

### Q46. Conceptual Python verification call

```python
result = engine.verify(VerificationInput(
    dpid=1,
    prediction={"status": "ATTACK", "confidence": 72.0, "source": "fusion"},
    explanation={"attack_type_hint": "SYN_FLOOD"},
    flow_features=[{"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}],
    warmup_cycles_done=5,
    attack_streak=2,
))
assert result.status.name == "VERIFIED"
assert result.mitigation_eligible is True
```

**Purpose:** Test fixture pattern — see golden tests for exact cases.

**Related:** `tests/test_verification_golden_r72.py`

---

### Q47. Example INELIGIBLE trace reasons

| `reason` | Stage failed |
|----------|--------------|
| `warmup_active` | WARMUP |
| `confidence_below_threshold` | CONFIDENCE_GATE |
| `attacker_not_identified` | ATTACKER_IDENTIFICATION |
| `verification_error_fail_closed` | ENGINE_ERROR |

**Purpose:** Troubleshooting map.

**Related:** `TROUBLESHOOTING.md`

---

### Q48. Example PENDING cycle

**Cycle 1:** ATTACK, streak=1 → PENDING (`attack_pending_confirmation`)

**Cycle 2:** ATTACK, streak=2, confidence OK, ID OK → VERIFIED

**Purpose:** Illustrate temporal gate for interview panel.

**Related:** Q31

---

## Performance & Concurrency

### Q49. Is R7 thread-safe?

**Designed for OsKen cooperative greenlet model — single-threaded cooperative scheduling.**

**Purpose:** No locks inside `verify()` — caller owns streak/warm-up state.

**Implementation:** Engine docstring documents concurrency assumptions.

**Runtime:** Production state on `flow_monitor`; updated before verify call.

**Limits:** Not tested for multi-threaded parallel verify on same switch.

**Related:** `verification/engine.py`

---

### Q50. What is typical verify() latency?

**Purpose:** Sub-millisecond per cycle in perf tests (feature extraction dominates elsewhere).

**Implementation:** `test_verification_perf_r74.py` asserts bounded time.

**Runtime:** Dominated by controller stats collection and ML inference — not R7 stages.

**Related:** `RUNTIME_FLOW.md`

---

### Q51. Does verification sleep or yield?

**No** — pure computation.

**Purpose:** Avoid blocking OsKen hub.

**Implementation:** No `hub.sleep` in engine.

**Related:** Engine docstring

---

## Cross-Plane Relationships

### Q52. How does R7 interact with R8 alerting?

**Purpose:** R8 consumes `VerificationResult` — default policy alerts **VERIFIED only**.

**Reason:** INELIGIBLE/PENDING would flood dashboard during warm-up and low-confidence periods.

**Implementation:** `AlertManager.process_verification(result)`.

**Runtime:** Empty `/api/security-alerts` common if never VERIFIED.

**Related:** [R8_QNA.md](08_R8_QNA.md)

---

### Q53. How does R7 interact with R5 RCA?

**Purpose:** RCA assembles evidence chain including verification stages.

**Reason:** Root cause narrative needs “why blocked” not just “ML said ATTACK”.

**Implementation:** `VerificationResult` + trace JSONL as evidence refs.

**Runtime:** RCA may run even when not VERIFIED — policy dependent.

**Related:** [R5_XAI_RCA.md](../../02_Novelties/06_R5_XAI_RCA.md)

---

### Q54. Does R4 correlation affect R7 stages directly?

**Not in Release 1.0 stage list.**

**Purpose:** Correlation is advisory input to fusion — not a separate verification stage yet.

**Implementation:** Comment in `stages.py`: future SSL/CORRELATION stages must not be added until implemented.

**Runtime:** Indirect effect via improved fusion confidence/decision.

**Related:** [R4_CORRELATION.md](../../02_Novelties/03_R4_Correlation.md)

---

### Q55. Does P0.4 strategy selection run inside R7?

**Partially** — identification stage uses `_select_block_strategy` callable for consistency.

**Purpose:** VERIFIED implies identifiable attacker **and** known strategy hint path — actual strategy used at mitigation.

**Implementation:** Injectable `StrategyFn` defaults to mitigation helper.

**Related:** [P0_QNA.md](02_P0_QNA.md) P0.4

---

## Troubleshooting

### Q56. Always INELIGIBLE — where to start?

1. Check warm-up cycles in controller logs
2. Tail `verification_trace.jsonl` for failing stage
3. Compare fused confidence vs gate (try lab profile)
4. Confirm flow_features contain attacker MAC

**Related:** `TROUBLESHOOTING.md`

---

### Q57. Never PENDING — always REJECTED?

**Likely upstream status never ATTACK/SUSPICIOUS** — check R6 fusion flag `INTELLISHIELD_R6_FUSION` and fused decision logs.

**Related:** [CONFIGURATION.md](../../02_Novelties/09_Ops_Calibration.md)

---

### Q58. VERIFIED but no DROP rule?

**Check mitigation layer:** blocklist skip, protected MAC, auto_mitigate disabled, OpenFlow errors.

**Purpose:** R7 authorizes — mitigation executes.

**Related:** `RUNTIME_FLOW.md`

---

## Future & Limits

### Q59. Will SSL/R2 add verification stages?

**Not until R2 implemented** — enum/stage placeholders exist in docs only.

**Purpose:** Avoid staging fiction in viva answers.

**Related:** [README.md](README.md)

---

### Q60. Can verification run offline on logged predictions?

**Yes** — tests replay `VerificationInput` from fixtures without Mininet.

**Purpose:** Golden regression without network emulation cost.

**Implementation:** `test_verification_golden_r72.py`, `test_verification_engine_r71.py`

**Related:** [TESTING_GUIDE.md](../../05_Testing/01_Testing_Strategy.md)

---

*Minimum 40 questions covered. For alerting on VERIFIED events see [R8_QNA.md](08_R8_QNA.md). For shared types see [FOUNDATION_QNA.md](01_Foundation_QNA.md).*
