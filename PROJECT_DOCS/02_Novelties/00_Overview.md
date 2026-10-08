# Release 1.0 Novelties — Overview

**Audience:** Report, viva, IEEE framing.  
**Source:** `PROJECT_STATUS_AND_NOVELTIES.md` §4 and `RESEARCH_JUSTIFICATION.md`.

These are the **research / engineering contributions beyond a single ML detector → DROP** stack. Phases 1–8 (monitor, entropy, traffic, ML, mitigation, ADWIN/HDBSCAN, PPO, dashboard) remain the baseline pipeline; the items below are the **added novelty planes**.

---

## 1. Status

| Novelty | Status | Package |
|---------|--------|---------|
| Foundation — shared contracts | COMPLETE | `shared_contracts/` |
| P0.1–P0.6 hardening | COMPLETE | evaluation, RL, mitigation, traffic |
| R4 Correlation | COMPLETE (lab live) | `correlation/` |
| R6 Collaborative fusion | COMPLETE (lab live) | `fusion/` |
| R7 Verification gate | COMPLETE (lab live) | `verification/` |
| R5 XAI + RCA | COMPLETE (lab live) | `xai/` + `rca/` |
| R8 Alerting | COMPLETE (lab live) | `alerting/` |
| Ops lab/production profile | COMPLETE (lab live) | `shared_contracts/ops_profile.py` |
| R3 Snapshot digital twin | COMPLETE (Level A — observational) | `twin/` |
| R2 SSL zero-day | Not implemented | — |
| R1 / R9 | Out of scope | — |

Live proof (calibrated): `20260728T181121Z`, `INTELLISHIELD_OPS_PROFILE=lab`.

---

## 2. One-line novelty

> Collaborative evidence pipeline: **correlate → fuse → verify → mitigate → explain → alert**, on typed shared contracts, with an ops profile — plus a **read-only snapshot twin** for experiment replay (not live OpenFlow).

---

## 3. Detail documents

| Topic | File |
|-------|------|
| Foundation | [01_Foundation.md](01_Foundation.md) |
| P0 | [02_P0_Hardening.md](02_P0_Hardening.md) |
| R4 | [03_R4_Correlation.md](03_R4_Correlation.md) |
| R6 | [04_R6_Collaborative_Detection.md](04_R6_Collaborative_Detection.md) |
| R7 | [05_R7_Verification.md](05_R7_Verification.md) |
| R5 | [06_R5_XAI_RCA.md](06_R5_XAI_RCA.md) |
| R8 | [07_R8_Alerting.md](07_R8_Alerting.md) |
| R3 | [08_R3_Digital_Twin.md](08_R3_Digital_Twin.md) |
| Ops | [09_Ops_Calibration.md](09_Ops_Calibration.md) |
| Essay | [10_Research_Justification.md](10_Research_Justification.md) |

---

## 4. What is not claimed

| Item | Stance |
|------|--------|
| Inventing Isolation Forest / Shannon entropy | No — integration is the claim |
| Internet-edge production / carrier SDN | Not claimed |
| Twin-launched Mininet / live OF replica | Not claimed |
| R2 SSL detector | Not implemented |
| Slack / email / Redis / Postgres | Not implemented |
