# R7 — Multi-Stage Verification

**PROJECT_DOCS novelty copy.** Source: `R7_VERIFICATION.md`.  
Related: [04_R6_Collaborative_Detection.md](04_R6_Collaborative_Detection.md) · [09_Ops_Calibration.md](09_Ops_Calibration.md) · [../07_Viva/Novelty_QNA/06_R7_QNA.md](../07_Viva/Novelty_QNA/06_R7_QNA.md)

---

## Verification engine

R7 is the **mitigation safety gate**. It decides whether a detection cycle is eligible to install OpenFlow DROP rules. Package: `verification/`.

## Workflow

```
WARMUP → DETECTION_EVIDENCE → ATTACK_CONFIRMATION
      → CONFIDENCE_GATE → ATTACKER_IDENTIFY → AUTO_MITIGATE_POLICY
      → VERIFIED | PENDING | INELIGIBLE | REJECTED
```

| Status | Meaning |
|--------|---------|
| **PENDING** | Attack streak incomplete |
| **INELIGIBLE** | Warm-up, low confidence, no attacker, policy, or fail-closed error |
| **VERIFIED** | `mitigation_eligible=True` |
| **REJECTED** | Explicit reject paths |

Fail-safe: unexpected exceptions → **INELIGIBLE** (no DROP).

## Defaults

| Knob | Default |
|------|---------|
| Warm-up | 3 cycles |
| Attack confirm streak | 2 |
| Min confidence to block | **60%** |
| Auto mitigate | True |

RL may adapt the confidence gate; ops profile clamps it — see [09_Ops_Calibration.md](09_Ops_Calibration.md).

## Novelty angle

Separates **detect** from **authorize**. Detection-only papers skip this gate.

## Tests

`tests/test_verification_engine_r71.py` and related `test_verification_*.py`.
