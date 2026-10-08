# Foundation — Shared Contracts

**PROJECT_DOCS novelty copy.** Source: `FOUNDATION.md`.  
Related: [00_Overview.md](00_Overview.md) · [10_Research_Justification.md](10_Research_Justification.md) · [../07_Viva/Novelty_QNA/01_Foundation_QNA.md](../07_Viva/Novelty_QNA/01_Foundation_QNA.md)

---

## Purpose

Provide a **dependency-leaf** typed contract layer so R4–R8 (and twin) share enums, DTOs, and serialization without importing the controller or detectors.

## Problem solved

Without shared contracts, each plane invents ad-hoc dict shapes → fragile dashboard/RCA linking and inconsistent enums.

---

## Architecture

```
shared_contracts/   (LEAF — stdlib + local only)
        ▲
        │ imports
 correlation / fusion / verification / alerting / rca / xai / twin / …
```

## Folder locations

| Path | Role |
|------|------|
| `shared_contracts/enums.py` | Detector, decision, severity, verification, twin enums |
| `shared_contracts/models.py` | DTOs |
| `shared_contracts/serialize.py` | JSON-friendly encode/decode |
| `shared_contracts/timeutil.py` | UTC helpers |
| `shared_contracts/ops_profile.py` | Lab/production ops policy |
| `shared_contracts/__init__.py` | Public exports |

## Contracts / enums (representative)

- `DetectorType`, `DetectorHealth`, `DetectionDecision`
- `Severity`, `VerificationStatus`, `AlertType`
- Twin-related types for R3 snapshot support

## Serialization & validation

- Roundtrip helpers in `serialize.py`
- Models carry `schema_version` where applicable
- Invalid confidence (NaN/inf) handled at adapters (fusion tests cover this)

## Runtime usage

Planes import types for JSONL records and API projections. Controller uses `get_ops_policy()` indirectly via RL/mitigation for confidence bounds.

## Tests

`tests/test_shared_contracts_foundation.py`

## Future extensions

- New detector enums for R2 — **Not implemented**
- Do not add heavy dependencies to this package
