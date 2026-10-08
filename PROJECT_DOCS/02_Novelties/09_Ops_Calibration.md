# Ops / Calibration Novelty

**PROJECT_DOCS novelty copy.** Source: `CONFIGURATION.md`.  
Related: [05_R7_Verification.md](05_R7_Verification.md) · [04_R6_Collaborative_Detection.md](04_R6_Collaborative_Detection.md)

---

## Problem

An adaptive RL confidence gate can climb (~92%) while fusion confidence sits near ~60%, starving R7 of **VERIFIED** outcomes (no blocks, no R5/R8).

## Novelty

| Profile | Behaviour |
|---------|-----------|
| `INTELLISHIELD_OPS_PROFILE=lab` (also `demo` / `dev`) | Freeze confidence gate at **60%** for reproducible demos |
| `production` (default if unset) | Adaptive RL gate clamped ~**55–75%** |

Code: `shared_contracts/ops_profile.py`. “Production” here means **adaptive lab/ops bounds**, not internet-edge product readiness.

## Live proof

After calibration, Mininet S1–S5 run `20260728T181121Z` produced VERIFIED blocks plus R5 RCA and R8 alerts.

```bash
export INTELLISHIELD_OPS_PROFILE=lab
export PYTHONPATH="$PWD"
osken-manager controller/flow_monitor.py
```
