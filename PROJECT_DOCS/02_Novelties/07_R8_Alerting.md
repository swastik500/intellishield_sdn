# R8 — Policy-Aware Alerting

**PROJECT_DOCS novelty copy.** Source: `R8_ALERTING.md`.  
Related: [05_R7_Verification.md](05_R7_Verification.md) · [06_R5_XAI_RCA.md](06_R5_XAI_RCA.md) · [../07_Viva/Novelty_QNA/08_R8_QNA.md](../07_Viva/Novelty_QNA/08_R8_QNA.md)

---

## Alert manager

R8 turns verification outcomes into **persisted security alerts** with severity, deduplication, and rate limiting. Package: `alerting/`.

## Lifecycle

```
VerificationResult
      ↓
 eligibility policy (default: VERIFIED only)
      ↓
 severity → dedup → rate limit → JSONL
      ↓
 Dashboard /api/security-alerts*
```

Defaults: do **not** alert on PENDING/INELIGIBLE/REJECTED. Dedup window 60 s.

Release 1.0 notification = **JSONL + dashboard poll**. Email/Slack/PagerDuty: **Not implemented**.

Live lab (`20260728T181121Z`): **5** R8 alerts.

`GET /api/alerts` remains the **legacy entropy CSV** feed (Phase 2) — distinct from R8.

## Tests

`tests/test_alerting_core_r81.py` and related `test_alerting_*.py`.
