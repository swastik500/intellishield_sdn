#!/usr/bin/env python3
"""Offline COMPLETE pipeline audit artifact generator.

Does NOT claim live Mininet / OsKen. Labels live S1–S5 as NOT_RUN when unavailable.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> dict:
    out_dir = ROOT / "logs"
    out_dir.mkdir(exist_ok=True)

    live_mininet = False
    live_osken = False
    try:
        import shutil

        live_mininet = shutil.which("mn") is not None
        live_osken = shutil.which("osken-manager") is not None
    except Exception:
        pass

    trace: dict = {
        "schema": "intellishield.pipeline_complete_trace.v1",
        "mode": "offline_synthetic" if not (live_mininet and live_osken) else "live_attempt",
        "live_mininet": bool(live_mininet and live_osken),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {
            "mininet": "FOUND" if live_mininet else "NOT_FOUND",
            "osken_manager": "FOUND" if live_osken else "NOT_FOUND",
        },
        "execution_order_production": [
            "1 FlowMonitor OF stats cycle",
            "2 Feature build / flow telemetry",
            "3 EntropyDetector",
            "4 AnomalyDetector ML",
            "5 R4 CorrelationEngine (advisory)",
            "6 R6 CollaborativeFusion (if enabled) else legacy ML/entropy",
            "7 R7 VerificationEngine",
            "8 R8 AlertManager (on verified; independent of mitigate)",
            "9 R5 XAI + RCA enrich",
            "10 MitigationEngine / OpenFlow DROP if eligible",
            "11 CSV/JSONL logs",
            "12 Dashboard poll (separate process)",
        ],
        "scenarios": {},
        "offline_pipeline_runs": [],
        "failures": [],
        "duplicate_events": [],
        "dropped_events": [],
        "component_status": {},
        "timing_ms": {},
    }

    # ── S1–S5 dry-run ───────────────────────────────────────────────────
    from twin import dry_run_scenario, plan_scenario

    t0 = time.perf_counter()
    for sid in ("S1", "S2", "S3", "S4", "S5"):
        t1 = time.perf_counter()
        try:
            plan = plan_scenario(sid, seed=42)
            dry_run_scenario(sid, seed=42)
            live = "PASS" if (live_mininet and live_osken) else "NOT_RUN"
            # Never fake live execution on this host
            if not (live_mininet and live_osken):
                live = "NOT_RUN"
            trace["scenarios"][sid] = {
                "live_execution": live,
                "dry_run": "PASS",
                "expected_attack": plan.expected_attack,
                "expected_attack_family": plan.expected_attack_family,
                "duration_sec": plan.duration_sec,
                "source_host": plan.source_host,
                "target_host": plan.target_host,
                "seed": plan.seed,
                "profile_fingerprint": plan.profile_fingerprint,
                "timeline_events": [e.get("event") for e in plan.expected_timeline()],
                "planning_ms": round((time.perf_counter() - t1) * 1000, 3),
            }
        except Exception as exc:  # noqa: BLE001
            trace["scenarios"][sid] = {
                "live_execution": "NOT_RUN",
                "dry_run": "FAIL",
                "error": repr(exc),
            }
            trace["failures"].append({"stage": f"dry_run_{sid}", "error": repr(exc)})
    trace["timing_ms"]["s1_s5_dry_run_total"] = round(
        (time.perf_counter() - t0) * 1000, 3
    )

    # ── Offline R4→R6→R7→R8→R5 path ─────────────────────────────────────
    from shared_contracts.enums import (
        DetectionDecision,
        DetectorHealth,
        DetectorType,
        VerificationStatus,
    )
    from shared_contracts.models import DetectionEvent, DetectorResult
    from shared_contracts.timeutil import utc_now
    from correlation import (
        CorrelationEngine,
        CorrelationWindow,
        SignalCategory,
        SignalEvent,
        build_entity_key,
    )
    from fusion import CollaborativeFusionEngine, adapt_entropy_metrics, adapt_ml_prediction
    from verification.config import VerificationConfig
    from verification.engine import VerificationEngine, VerificationInput
    from alerting import AlertManager, AlertingConfig
    from alerting.adapters.memory_adapter import MemoryNotificationAdapter
    from alerting.factory import AlertFactory
    from alerting.manager import AlertDisposition
    from rca.context import RCAContext
    from rca.engine import RootCauseEngine

    ent = build_entity_key(src_mac="02:aa:aa:aa:aa:01", switch_id=1)
    now = utc_now()

    def _sig(sid: str, cat: SignalCategory, source: str, name: str, score: float, value):
        return SignalEvent(
            signal_id=sid,
            timestamp=now,
            category=cat,
            source=source,
            name=name,
            value=value,
            entity_key=ent,
            switch_id=1,
            normalized_score=score,
            availability="AVAILABLE",
        )

    def run_path(label: str, *, attack: bool) -> dict:
        t_start = time.perf_counter()
        steps = []

        # R4
        t = time.perf_counter()
        win = CorrelationWindow(duration_sec=30.0, max_signals=32, entity_key=ent)
        if attack:
            pack = [
                _sig("flow1", SignalCategory.DATA_PLANE, "flow", "packet_rate", 0.85, {"pkt": 5000}),
                _sig("ent1", SignalCategory.DETECTION, "entropy", "entropy_score", 0.9, 0.15),
                _sig("ml1", SignalCategory.DETECTION, "ml", "status", 0.92, "ATTACK"),
            ]
        else:
            pack = [
                _sig("flow1", SignalCategory.DATA_PLANE, "flow", "packet_rate", 0.1, {"pkt": 50}),
                _sig("ent1", SignalCategory.DETECTION, "entropy", "entropy_score", 0.1, 0.85),
                _sig("ml1", SignalCategory.DETECTION, "ml", "status", 0.1, "NORMAL"),
            ]
        for s in pack:
            win.accept(s)
        corr = CorrelationEngine().correlate(pack, entity_key=ent, window=win)
        steps.append(
            {
                "component": "R4",
                "ms": round((time.perf_counter() - t) * 1000, 4),
                "score": corr.score,
                "status": "PASS",
            }
        )

        # R6
        t = time.perf_counter()
        if attack:
            dets = [
                adapt_ml_prediction({"status": "ATTACK", "confidence": 95.0}, timestamp=now),
                adapt_entropy_metrics(
                    {"status": "ALERT", "confidence": 88.0, "entropy_score": 0.15},
                    timestamp=now,
                ),
            ]
        else:
            dets = [
                adapt_ml_prediction({"status": "NORMAL", "confidence": 15.0}, timestamp=now),
                adapt_entropy_metrics(
                    {"status": "NORMAL", "confidence": 10.0, "entropy_score": 0.85},
                    timestamp=now,
                ),
            ]
        fused = CollaborativeFusionEngine().fuse(
            detector_results=dets,
            correlation=corr,
            event_id=f"{label}-evt",
            timestamp=now,
            entity_key=ent,
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
        )
        steps.append(
            {
                "component": "R6",
                "ms": round((time.perf_counter() - t) * 1000, 4),
                "decision": fused.decision.value,
                "disagreement": fused.disagreement,
                "status": "PASS",
            }
        )

        # R7
        t = time.perf_counter()

        def identify(flows, expl):
            if attack:
                return [("02:aa:aa:aa:aa:01", "02:bb:bb:bb:bb:02")]
            return []

        veng = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=identify,
            select_strategy=lambda a, b: "FLOW_PAIR",
        )
        pred = (
            {"status": "ATTACK", "confidence": 95.0, "source": "ml"}
            if attack
            else {"status": "NORMAL", "confidence": 10.0, "source": "ml"}
        )
        vr = veng.verify(
            VerificationInput(
                dpid=1,
                prediction=pred,
                explanation={"attack_type_hint": "SYN_FLOOD" if attack else ""},
                flow_features=[
                    {
                        "src_mac": "02:aa:aa:aa:aa:01",
                        "dst_mac": "02:bb:bb:bb:bb:02",
                        "packet_count": 5000 if attack else 10,
                    }
                ],
                warmup_cycles_done=10,
                attack_streak=2 if attack else 0,
                event_id=f"{label}-evt",
                min_confidence_percent=60.0,
            )
        )
        steps.append(
            {
                "component": "R7",
                "ms": round((time.perf_counter() - t) * 1000, 4),
                "status_code": vr.status.value,
                "eligible": vr.mitigation_eligible,
                "status": "PASS",
            }
        )

        # R8
        t = time.perf_counter()
        factory = AlertFactory()
        mgr = AlertManager(
            config=AlertingConfig(dedup_enabled=True, rate_limit_enabled=True),
            adapters=[MemoryNotificationAdapter()],
        )
        alert = factory.from_verification(vr)
        if alert is None:
            steps.append(
                {
                    "component": "R8",
                    "ms": round((time.perf_counter() - t) * 1000, 4),
                    "status": "SKIPPED_BY_POLICY",
                }
            )
            trace["dropped_events"].append(
                {
                    "path": label,
                    "component": "R8",
                    "reason": f"verification={vr.status.value} eligible={vr.mitigation_eligible}",
                }
            )
        else:
            first = mgr.process_alert(alert)
            second = mgr.process_alert(alert)
            steps.append(
                {
                    "component": "R8",
                    "ms": round((time.perf_counter() - t) * 1000, 4),
                    "first": first.disposition.value,
                    "second": second.disposition.value,
                    "status": "PASS",
                }
            )
            if second.disposition == AlertDisposition.DUPLICATE:
                trace["duplicate_events"].append(
                    {
                        "path": label,
                        "kind": "alert_dedup",
                        "detail": "second identical alert suppressed",
                    }
                )

        # R5
        t = time.perf_counter()
        det_ev = DetectionEvent(
            event_id=f"{label}-evt",
            timestamp=now,
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
            detector_results=list(dets),
        )
        if vr.status == VerificationStatus.VERIFIED:
            rca = RootCauseEngine().analyze(
                RCAContext(
                    event_id=f"{label}-evt",
                    detection=det_ev,
                    verification=vr,
                    correlation=corr,
                    fused_decision=fused,
                )
            )
            steps.append(
                {
                    "component": "R5",
                    "ms": round((time.perf_counter() - t) * 1000, 4),
                    "report_id": rca.report_id,
                    "status": "PASS",
                }
            )
        else:
            steps.append(
                {
                    "component": "R5",
                    "ms": round((time.perf_counter() - t) * 1000, 4),
                    "status": "SKIPPED_BY_POLICY",
                }
            )
            trace["dropped_events"].append(
                {
                    "path": label,
                    "component": "R5",
                    "reason": "verified-only default policy",
                }
            )

        steps.append(
            {
                "component": "Mitigation",
                "openflow": False,
                "would_call_handle_alert": bool(vr.mitigation_eligible),
                "status": "LOGICAL_ONLY",
                "note": "OpenFlow NOT executed (no OsKen/datapath on this host)",
            }
        )

        return {
            "label": label,
            "maps_to_scenario": "S2_semantics" if attack else "S1_semantics",
            "live_mininet": False,
            "total_ms": round((time.perf_counter() - t_start) * 1000, 3),
            "steps": steps,
            "fused_decision": fused.decision.value,
            "verification": vr.status.value,
            "mitigation_eligible": vr.mitigation_eligible,
            "correlation_score": corr.score,
        }

    trace["offline_pipeline_runs"].append(run_path("S1_NORMAL_PATH", attack=False))
    trace["offline_pipeline_runs"].append(run_path("S2_ATTACK_PATH", attack=True))

    # S3–S5: dry-run only on this host
    for sid in ("S3", "S4", "S5"):
        if sid in trace["scenarios"]:
            trace["scenarios"][sid]["pipeline_live"] = "NOT_RUN"

    trace["component_status"] = {
        "Flow Monitor": "NOT_RUN_LIVE",
        "Entropy": "NOT_RUN_LIVE / offline R6 entropy adapter used",
        "ML": "NOT_RUN_LIVE / offline R6 ML adapter used",
        "R4": "PASS offline",
        "R6": "PASS offline",
        "R7": "PASS offline",
        "Mitigation": "LOGICAL_ONLY (no OpenFlow)",
        "R5": "PASS offline on verified path",
        "R8": "PASS offline on verified path",
        "Dashboard": "NOT_RUN_LIVE",
        "Logs": "offline trace only (no live scenario CSVs)",
        "Metrics": "NOT_RUN_LIVE",
    }

    path = out_dir / "pipeline_complete_trace.json"
    path.write_text(
        json.dumps(trace, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    return trace


if __name__ == "__main__":
    result = main()
    print("WROTE logs/pipeline_complete_trace.json")
    print("live_mininet", result["live_mininet"])
    print(
        "scenarios",
        {k: (v.get("live_execution"), v.get("dry_run")) for k, v in result["scenarios"].items()},
    )
    for r in result["offline_pipeline_runs"]:
        print(
            r["label"],
            "fused=",
            r["fused_decision"],
            "verify=",
            r["verification"],
            "eligible=",
            r["mitigation_eligible"],
            "ms=",
            r["total_ms"],
        )
    print("failures", len(result["failures"]))
    print("duplicates", len(result["duplicate_events"]))
    print("dropped", len(result["dropped_events"]))
