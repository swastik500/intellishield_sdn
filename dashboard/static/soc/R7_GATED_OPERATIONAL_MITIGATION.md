# R7-Gated Operational Mitigation — Phase 13

**Status:** **BLOCKED** — mitigation remains **DISABLED** on the SOC Command Center path  
**Date:** 2026-09-29  
**Branch:** `feat/soc-ui-phase13-r7-mitigation`

**Phase 13 does not implement autonomous mitigation.**  
**R7 verification is a prerequisite for any future operator mitigation — and that path is NOT enabled here.**

---

## Verdict

After a full repository audit of mitigation, OpenFlow, blocklist, controller integration,
and R7 event-linkage contracts, **no existing mitigation capability can be safely connected**
to the Phase 10–12 Command/Safety infrastructure without inventing a new cross-process
control plane or weakening Phase 13 stop conditions.

| Final operational status | Value |
|--------------------------|--------|
| Controlled SOC mitigation | **BLOCKED / DISABLED** |
| Phase 12 `COMMAND_DRY_RUN` | Still the only allowlisted executable action |
| Controller-side autonomous R7→DROP | Unchanged (pre-existing; outside SOC Command Center) |
| `/api/control/*` | Remains disconnected from Command Center |

---

## Mitigation capability matrix

| Capability | Exists | Location | Side effect | Target | Reversible | R7 required today | Caller | Safe for Phase 13 |
|---|---|---|---|---|---|---|---|---|
| `MitigationEngine.handle_alert` | YES | `mitigation/mitigation_engine.py` | OpenFlow DROP + in-memory blocklist + CSV | Dominant `(src_mac,dst_mac)` from live flows | Partial (`hard_timeout`; FLOW_PAIR unblock incomplete) | YES via controller `run_verified_mitigation` | `flow_monitor` → `run_verified_mitigation` | **NO** |
| `MitigationEngine._execute_block` | YES (private) | same | Installs DROP | MAC / flow pair | Partial | Indirect | `handle_alert` | **NO** |
| `block_src_mac` | YES | `mitigation/flow_blocker.py` | `OFPFlowMod` DROP `eth_src` | Attacker MAC | YES (`unblock_src_mac` / timeout) | NO (primitive) | `_execute_block` | **NO** |
| `block_flow_pair` | YES | `flow_blocker.py` | DROP `eth_src`+`eth_dst` | Attacker→victim | Weak (no dedicated unblock) | NO (primitive) | `_execute_block` | **NO** |
| `unblock_src_mac` / `unblock_all` | YES | `flow_blocker.py` | DELETE flow(s) | MAC / switch-wide | N/A | NO | Engine manual APIs | **NO** (bulk / ungated) |
| `BlocklistManager.*` | YES | `blocklist_manager.py` | In-memory only | `(dpid, mac)` | Soft expiry | NO | Engine | **NO** |
| `log_block_action` | YES | `mitigation_logger.py` | CSV append | MAC fields | N/A | NO | Engine | **NO** alone (no `event_id`) |
| GET `/api/blocklist` | YES | `dashboard/api.py` | Read-only | Historical | N/A | NO | SOC | Observer only |
| `run_verified_mitigation` | YES | `verification/runtime.py` | May call `handle_alert` when eligible | Same as engine | Partial | YES | Controller (auto) | **NO** for Phase 13 SOC (autonomous) |
| Registry `EXECUTE_MITIGATION` | Stub | `dashboard/commands/actions.py` | Intended network mutate | EVENT | Spec: irreversible | Intended YES | Disabled | **NO today** |
| Registry `BLOCK_TARGET` / `UNBLOCK_TARGET` | Stub | `actions.py` | Intended block/unblock | ATTACKER | Spec: reversible | Intended | Disabled | **NO today** |
| `COMMAND_DRY_RUN` | YES | Phase 12 executor | None | EVENT | Yes | NO | Phase 12 allowlist | N/A (not mitigation) |
| Lab `/api/control/*` | YES | `dashboard/api.py` | Lab control | Controller/scenarios | Varies | NO | Master Control | **NO** — must stay disconnected |

### Auditability / concurrency / persistence (summary)

| Aspect | Finding |
|--------|---------|
| OpenFlow actuation | Requires live OsKen `datapath` in the **controller process** |
| SOC / FastAPI process | **No** `MitigationEngine`, **no** datapaths, **no** mitigation imports |
| Blocklist | Process-local memory — not shared with Command Center |
| Mitigation CSV | Append-only; **no `event_id` column** — not joinable to R7 |
| Command store | Durable SQLite (Phase 11) — **not wired** to mitigation state |
| Cross-process RPC for operator DROP | **Does not exist** |

---

## R7 contract (consume, do not rewrite)

### Authoritative outputs

- In-process: `VerificationEngine.verify` → `VerificationResult`
- Durable observer log: `logs/verification_trace.jsonl`
- HTTP (read-only): `GET /api/verification-traces?event_id=…`, `GET /api/verification-traces/{verification_id}`

### Fields needed for a future operator gate

| Field | Role |
|-------|------|
| `event_id` | Explicit command ↔ verification link |
| `verification_id` | Audit correlation |
| `status` | Must be `VERIFIED` |
| `mitigation_eligible` | Must be `true` |
| `timestamp` | Freshness (server UTC) |
| `attacker_mac` / `victim_mac` | Target identity |
| Trace extras `dpid` | Switch context (not first-class on `VerificationResult`) |

### Eligibility today (controller path)

Actuation requires `status=VERIFIED` **and** `mitigation_eligible=True` after stages  
`WARMUP` → `DETECTION_EVIDENCE` → `ATTACK_CONFIRMATION` → `CONFIDENCE_GATE` →  
`ATTACKER_IDENTIFICATION` → `MITIGATION_ELIGIBILITY`.

---

## Blocking gaps (stop conditions hit)

1. **`event_id` discontinuity**  
   `flow_monitor` does not pass R4/R6 `event_id` into `run_verified_mitigation`; runtime often creates a **fresh** id. R6 may put `event_id` on prediction, but it is not reliably the same id used for investigation joins. Command → event → R7 → target cannot be enforced without heuristic joins (forbidden).

2. **No SOC → OpenFlow bridge**  
   Enabling mitigation from the Command Center would require inventing a new controller actuation channel. Existing OpenFlow primitives are too broad if exposed raw. `/api/control/*` must not be used as a shortcut.

3. **Mitigation logs lack `event_id`**  
   Provenance Mitigation → Command → Event → R7 cannot be reconstructed from CSV.

4. **RBAC**  
   `EXECUTE_MITIGATION` / `BLOCK_TARGET` / `UNBLOCK_TARGET` remain in `FUTURE_PERMISSIONS` and are **never granted** to any role. Correct for Phase 13 BLOCKED.

5. **Autonomous vs operator**  
   Controller already auto-mitigates after R7. Phase 13 forbids automatic SOC mitigation and forbids treating that auto path as the Command Center executor.

6. **FLOW_PAIR rollback incomplete**  
   Surgical blocks lack a clean dedicated unblock — weakens reversibility preference.

---

## Selected Phase 13 capability

**None.**

| Field | Value |
|-------|--------|
| Operation | **NOT SELECTED** |
| Risk | N/A |
| Target | N/A |
| Reversibility | N/A |
| Permission | Mitigation permissions remain **DENIED** |
| R7 requirement | Would be mandatory; cannot be satisfied end-to-end today |

**Closest future candidate (deferred):** single allowlisted `EXECUTE_VERIFIED_MITIGATION` / `EXECUTE_MITIGATION` with  
backend-loaded R7 (`VERIFIED` + `mitigation_eligible` + MAC target), after fixing `event_id` continuity  
and adding a **narrow** controller-side operator actuation API (not `/api/control/*`, not arbitrary OpenFlow). Prefer FLOW_PAIR over SRC_MAC. Not implemented in this phase.

---

## What Phase 13 deliberately did **not** change

- Detection, R4, R6, R7 engine/stages/thresholds, R5, R8, R3
- Mitigation engine / flow_blocker / blocklist algorithms
- Controller OpenFlow install path
- Phase 12 allowlist (`COMMAND_DRY_RUN` only)
- Lab `/api/control/*` connectivity to Command Center

---

## Action registry after Phase 13

```text
COMMAND_DRY_RUN          execution_enabled = true   (Phase 12)
EXECUTE_MITIGATION       execution_enabled = false  (BLOCKED)
BLOCK_TARGET             execution_enabled = false
UNBLOCK_TARGET           execution_enabled = false
ALL_OTHER_ACTIONS        execution_enabled = false
```

No `PHASE13_ALLOWLIST` of real mitigation actions exists.

---

## API audit (unchanged)

Authentication / authorization / command / audit routes remain as in Phase 12.  
**`POST /api/operator/commands/{id}/execute`** exists for allowlisted dry-run only.

**Must not / does not exist for Phase 13 enablement:**

- `POST /api/mitigate`
- `POST /api/block`
- `POST /api/controller/execute`
- bulk mitigation
- automatic SOC mitigation
- arbitrary OpenFlow from frontend

---

## Explicit statements

**AUTONOMOUS MITIGATION: NOT IMPLEMENTED on the SOC Command Center path.**  
(Controller-side R7→`handle_alert` remains a separate, pre-existing automatic path and was not expanded.)

**R7 verification is a prerequisite for any future selected mitigation operation.**

**PHASE 13 BLOCKED — MITIGATION REMAINS DISABLED.**

---

## Prerequisites to unblock a future phase

1. Plumb stable `event_id` from detection/R4/R6 through R7 traces and mitigation logs  
2. Server-side R7 loader + freshness against **backend** timestamps (not client-supplied)  
3. Grant a narrowly scoped mitigation permission to OPERATOR/ADMIN only  
4. Narrow controller actuation contract (one validated MAC/dpid/strategy; no raw OF)  
5. Durable mitigation result keyed by `command_id` + `event_id` + `verification_id`  
6. Explicit FLOW_PAIR rollback or classify SRC_MAC timeout-only as reversible policy  
7. Comprehensive Phase 13-style tests then re-evaluate enablement
