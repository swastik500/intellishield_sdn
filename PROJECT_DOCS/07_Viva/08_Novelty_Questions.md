# Novelty Questions (Release 1.0 planes)

Short viva drill for **Foundation, P0, R3–R8, ops profile**. Expected answers match the current repository.

**Full Q&A banks (~400+ questions):** [`Novelty_QNA/README.md`](Novelty_QNA/README.md)  
**Novelty manuals:** [`../02_Novelties/`](../02_Novelties/README.md)

---

## Foundation

**Q. Why `shared_contracts/` instead of dicts in each package?**  
**Expected:** One typed vocabulary for JSONL/API so correlation, fusion, verification, RCA, and alerts do not invent incompatible shapes. The package is a dependency leaf (no controller import).

→ Deep dive: [`Novelty_QNA/01_Foundation_QNA.md`](Novelty_QNA/01_Foundation_QNA.md)

## P0

**Q. What broke without P0.1?**  
**Expected:** ML confidence 0–100 vs RL 0–1 broke observation scale. Fix in `rl_engine/rl_env.py`.

**Q. Why FLOW_PAIR vs SRC_MAC (P0.4)?**  
**Expected:** Known victim floods use flow-pair DROP to cut collateral; volumetric/unknown victim uses source MAC.

→ Deep dive: [`Novelty_QNA/02_P0_QNA.md`](Novelty_QNA/02_P0_QNA.md)

## R4

**Q. Does correlation install OpenFlow rules?**  
**Expected:** No. Score **S·T·D·A·P** is advisory for fusion/RCA/dashboard.

→ Deep dive: [`Novelty_QNA/04_R4_QNA.md`](Novelty_QNA/04_R4_QNA.md)

## R6

**Q. How is this different from majority vote?**  
**Expected:** Weight **w = ρ × h** (reliability × health); signed score S; disagreement and uncertainty shrink overconfidence. Confidence calibration does not change the S decision rule.

→ Deep dive: [`Novelty_QNA/05_R6_QNA.md`](Novelty_QNA/05_R6_QNA.md)

## R7

**Q. Why verification if fusion already says ATTACK?**  
**Expected:** Detection ≠ authorization. Warm-up, streak, confidence, attacker identity, and policy must pass. Errors → **INELIGIBLE**, no DROP.

→ Deep dive: [`Novelty_QNA/06_R7_QNA.md`](Novelty_QNA/06_R7_QNA.md)

## R5 / R8

**Q. When do RCA and alerts fire?**  
**Expected:** After verification (typically VERIFIED). R8 defaults skip PENDING/INELIGIBLE. Email/Slack are **Not implemented**.

→ Deep dive: [`Novelty_QNA/07_R5_XAI_QNA.md`](Novelty_QNA/07_R5_XAI_QNA.md) · [`Novelty_QNA/08_R8_QNA.md`](Novelty_QNA/08_R8_QNA.md)

## Ops profile

**Q. Why `INTELLISHIELD_OPS_PROFILE=lab`?**  
**Expected:** Freezes the confidence gate at 60% so fusion ~0.6 can still VERIFIED. Unclamped RL can starve mitigation.

→ See: [`../02_Novelties/09_Ops_Calibration.md`](../02_Novelties/09_Ops_Calibration.md)

## R3

**Q. Is Mininet the digital twin?**  
**Expected:** No. `twin/` is the software model + log snapshot/replay. Twin does not launch Mininet or write OpenFlow.

**Q. Is R1/R9 done in the twin?**  
**Expected:** No. Twin only exposes validation/dataset gates. R1 AutoML and R9 adaptive learning are out of scope.

→ Deep dive: [`Novelty_QNA/03_R3_QNA.md`](Novelty_QNA/03_R3_QNA.md)

## Honesty

**Q. Production internet?**  
**Expected:** Not claimed. Lab Mininet prototype with documented live run `20260728T181121Z`.

→ Cross-cutting: [`Novelty_QNA/09_Cross_Cutting_QNA.md`](Novelty_QNA/09_Cross_Cutting_QNA.md)
