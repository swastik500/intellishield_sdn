#!/usr/bin/env python3
"""R5.2 — Root Cause Analysis Engine tests (no controller integration)."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import (
    DetectionDecision,
    DetectorHealth,
    DetectorType,
    VerificationStatus,
)
from shared_contracts.models import (
    DetectionEvent,
    DetectorResult,
    RootCauseReport,
    VerificationResult,
    VerificationStageResult,
    new_id,
)
from shared_contracts.serialize import to_dict, to_json
from rca import (
    EvidenceKind,
    MitigationEvidence,
    RCAContext,
    RootCauseEngine,
)


def _ts():
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def _verification(
    *,
    status=VerificationStatus.VERIFIED,
    eligible=True,
    attacker="02:aa:aa:aa:aa:01",
    victim="02:bb:bb:bb:bb:02",
    reason="verified_attack",
):
    return VerificationResult(
        verification_id=new_id(),
        timestamp=_ts(),
        event_id="evt-1",
        status=status,
        confidence=0.91,
        stages=[
            VerificationStageResult("WARMUP", True, "ok"),
            VerificationStageResult("ATTACK_CONFIRM", True, "streak_met"),
            VerificationStageResult("CONFIDENCE_GATE", True, "ok"),
        ],
        attacker_mac=attacker,
        victim_mac=victim,
        mitigation_eligible=eligible,
        reason=reason,
    )


def _detection(*, src="02:aa:aa:aa:aa:01", dst="02:bb:bb:bb:bb:02", with_detectors=True):
    dets = []
    if with_detectors:
        dets = [
            DetectorResult(
                detector=DetectorType.ML,
                timestamp=_ts(),
                health=DetectorHealth.SUCCESS,
                decision=DetectionDecision.ATTACK,
                confidence=0.9,
                attack_hint="SYN_FLOOD",
            )
        ]
    return DetectionEvent(
        event_id="evt-1",
        timestamp=_ts(),
        switch_id=1,
        src_mac=src,
        dst_mac=dst,
        detector_results=dets,
    )


def _xai_dict(**overrides):
    base = {
        "summary": "Model predicted ATTACK with confidence 0.94. Decision-path evidence used packet_rate_max.",
        "method": "DECISION_TREE_PATH",
        "leaf_decision": "ATTACK",
        "attack_type_hint": "SYN_FLOOD",
        "decision_path": [{"feature": "packet_rate_max", "operator": ">", "threshold": 0.5}],
        "local_path_features": [{"feature": "packet_rate_max", "scope": "LOCAL_PATH"}],
        "status": "OK",
    }
    base.update(overrides)
    return base


class TestRootCauseEngineR52(unittest.TestCase):
    def setUp(self):
        self.eng = RootCauseEngine()

    def test_verified_attack_complete_evidence(self):
        ctx = RCAContext(
            event_id="evt-1",
            detection=_detection(),
            verification=_verification(),
            explanation=_xai_dict(),
            attack_hint="SYN_FLOOD",
            entropy_evidence={"entropy_score": 0.2, "src_entropy": 0.15},
            mitigation=MitigationEvidence(
                eligible=True, strategy="FLOW_PAIR", result="BLOCKED"
            ),
            baseline_evidence={"entropy_score": 0.8},
            report_id="rca-fixed-1",
        )
        report = self.eng.analyze(ctx)
        self.assertIsInstance(report, RootCauseReport)
        self.assertEqual(report.report_id, "rca-fixed-1")
        self.assertEqual(report.event_id, "evt-1")
        self.assertEqual(report.suspected_source, "02:aa:aa:aa:aa:01")
        self.assertEqual(report.affected_target, "02:bb:bb:bb:bb:02")
        self.assertGreaterEqual(report.confidence, 0.95)
        self.assertIn("SYN_FLOOD", report.summary)
        self.assertIn("verification", report.contributing_signals)
        self.assertIn("xai", report.contributing_signals)
        self.assertEqual(
            report.contributing_features["baseline_evidence"]["entropy_score"], 0.8
        )
        items = report.contributing_features["evidence_items"]
        kinds = {i["key"]: i["kind"] for i in items}
        self.assertEqual(kinds["suspected_source"], EvidenceKind.OBSERVED.value)
        self.assertEqual(kinds["affected_target"], EvidenceKind.OBSERVED.value)

    def test_normal_rejected_event(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-rej",
                verification=_verification(
                    status=VerificationStatus.REJECTED,
                    eligible=False,
                    attacker=None,
                    victim=None,
                    reason="low_confidence",
                ),
            )
        )
        self.assertIn("REJECTED", report.summary)
        self.assertFalse(report.contributing_features["mitigation_eligible"])
        self.assertIsNone(report.suspected_source)

    def test_missing_xai(self):
        report = self.eng.analyze(
            RCAContext(event_id="evt-1", verification=_verification())
        )
        self.assertIn("xai:NOT_AVAILABLE", report.contributing_features["missing_evidence"])

    def test_missing_entropy(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                verification=_verification(),
                explanation=_xai_dict(),
            )
        )
        self.assertIn(
            "entropy:NOT_AVAILABLE", report.contributing_features["missing_evidence"]
        )

    def test_missing_source(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                verification=_verification(attacker=None),
                detection=_detection(src=None),
            )
        )
        self.assertIsNone(report.suspected_source)
        self.assertIn("source:UNKNOWN", report.contributing_features["missing_evidence"])
        self.assertIn("Suspected source=UNKNOWN", report.summary)

    def test_missing_target(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                verification=_verification(victim=None),
                detection=_detection(dst=None),
            )
        )
        self.assertIsNone(report.affected_target)
        self.assertIn("target:UNKNOWN", report.contributing_features["missing_evidence"])

    def test_missing_mitigation(self):
        report = self.eng.analyze(
            RCAContext(event_id="evt-1", verification=_verification())
        )
        self.assertIn(
            "mitigation:NOT_AVAILABLE", report.contributing_features["missing_evidence"]
        )
        # eligibility still OBSERVED from verification
        self.assertTrue(report.contributing_features["mitigation_eligible"])

    def test_ineligible_attack(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                verification=_verification(
                    status=VerificationStatus.INELIGIBLE,
                    eligible=False,
                    reason="warmup",
                ),
            )
        )
        self.assertIn("INELIGIBLE", report.summary)
        self.assertFalse(report.contributing_features["mitigation_eligible"])

    def test_observed_vs_inferred_source(self):
        # OBSERVED via verification attacker
        r1 = self.eng.analyze(
            RCAContext(event_id="e1", verification=_verification())
        )
        item = next(
            i
            for i in r1.contributing_features["evidence_items"]
            if i["key"] == "suspected_source"
        )
        self.assertEqual(item["kind"], EvidenceKind.OBSERVED.value)
        self.assertNotIn("caused the attack", item["statement"].lower())

        # INFERRED via detection src only
        r2 = self.eng.analyze(
            RCAContext(
                event_id="e2",
                detection=_detection(),
                verification=_verification(attacker=None, victim=None),
            )
        )
        item2 = next(
            i
            for i in r2.contributing_features["evidence_items"]
            if i["key"] == "suspected_source"
        )
        self.assertEqual(item2["kind"], EvidenceKind.INFERRED.value)
        self.assertIn("suspected", item2["statement"].lower())

    def test_rca_confidence_semantics_not_ml_copy(self):
        # ML-like verification confidence 0.91 must not equal RCA confidence
        report = self.eng.analyze(
            RCAContext(event_id="evt-1", verification=_verification())
        )
        self.assertNotEqual(report.confidence, 0.91)
        policy = report.contributing_features["rca_confidence_policy"]
        self.assertIn("not ML confidence", policy["semantics"])
        # verification-only: 0.25 + source 0.15 + target 0.10 = 0.50
        self.assertAlmostEqual(report.confidence, 0.50, places=2)

    def test_missing_baseline(self):
        report = self.eng.analyze(
            RCAContext(event_id="evt-1", verification=_verification())
        )
        self.assertEqual(
            report.contributing_features["baseline_evidence"], "NOT_AVAILABLE"
        )
        self.assertIn("Baseline evidence=NOT_AVAILABLE", report.summary)

    def test_available_baseline(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                verification=_verification(),
                baseline_evidence={"src_entropy": 0.9},
            )
        )
        self.assertEqual(
            report.contributing_features["baseline_evidence"]["src_entropy"], 0.9
        )
        self.assertIn("Baseline evidence=AVAILABLE", report.summary)

    def test_deterministic_summary(self):
        ctx = RCAContext(
            event_id="evt-1",
            verification=_verification(),
            explanation=_xai_dict(),
            attack_hint="SYN_FLOOD",
            report_id="fixed",
        )
        a = self.eng.analyze(ctx)
        b = self.eng.analyze(ctx)
        self.assertEqual(a.summary, b.summary)
        self.assertEqual(a.confidence, b.confidence)
        self.assertEqual(
            a.contributing_features["missing_evidence"],
            b.contributing_features["missing_evidence"],
        )

    def test_serialization_and_contract(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                verification=_verification(),
                explanation=_xai_dict(),
            )
        )
        self.assertIsInstance(report, RootCauseReport)
        payload = to_dict(report)
        self.assertEqual(payload["_type"], "RootCauseReport")
        encoded = to_json(report)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["event_id"], "evt-1")
        self.assertNotIn("password", encoded.lower())

    def test_malformed_evidence_and_null_context(self):
        report = self.eng.analyze(None)
        self.assertEqual(report.confidence, 0.0)
        self.assertIn("UNAVAILABLE", report.summary)

        report2 = self.eng.analyze(
            RCAContext(event_id="evt-1", explanation=object())
        )
        self.assertIn("xai:MALFORMED", report2.contributing_features["missing_evidence"])

    def test_no_fabricated_fields(self):
        report = self.eng.analyze(RCAContext(event_id="evt-bare"))
        self.assertIsNone(report.suspected_source)
        self.assertIsNone(report.affected_target)
        self.assertEqual(
            report.contributing_features["baseline_evidence"], "NOT_AVAILABLE"
        )
        # Must not invent attack hint
        self.assertIsNone(report.contributing_features.get("attack_hint"))
        self.assertIn("verification:NOT_AVAILABLE", report.contributing_features["missing_evidence"])

    def test_secrets_stripped_from_entropy(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-1",
                entropy_evidence={"entropy_score": 0.1, "api_key": "SECRET"},
            )
        )
        ent = next(
            i
            for i in report.contributing_features["evidence_items"]
            if i["key"] == "entropy_evidence"
        )
        self.assertNotIn("api_key", ent["value"])

    def test_no_controller_or_mitigation_authorization(self):
        import rca.engine as mod

        src = open(mod.__file__, encoding="utf-8").read()
        self.assertNotIn("flow_monitor", src)
        self.assertNotIn("handle_alert", src)
        self.assertNotIn("from controller", src)
        self.assertNotIn("import mitigation", src)


if __name__ == "__main__":
    unittest.main()
