#!/usr/bin/env python3
"""R5.5 — RCA correctness + evidence completeness (no fabrication)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import (
    VerificationResult,
    VerificationStageResult,
    new_id,
)
from rca import MitigationEvidence, RCAContext, RootCauseEngine
from rca.completeness import measure_evidence_completeness


def _ts():
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def _ver(**kwargs):
    base = dict(
        verification_id=new_id(),
        timestamp=_ts(),
        event_id="evt-gt",
        status=VerificationStatus.VERIFIED,
        confidence=0.9,
        stages=[
            VerificationStageResult("WARMUP", True, "ok"),
            VerificationStageResult("ATTACK_CONFIRM", True, "streak_met"),
        ],
        attacker_mac="02:aa:aa:aa:aa:01",
        victim_mac="02:bb:bb:bb:bb:02",
        mitigation_eligible=True,
        reason="verified_attack",
    )
    base.update(kwargs)
    return VerificationResult(**base)


class TestRCACorrectnessR55(unittest.TestCase):
    def setUp(self):
        self.eng = RootCauseEngine()

    def test_does_not_invent_source_target_hint_baseline(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-bare",
                verification=_ver(attacker_mac=None, victim_mac=None),
            )
        )
        self.assertIsNone(report.suspected_source)
        self.assertIsNone(report.affected_target)
        self.assertIsNone(report.contributing_features.get("attack_hint"))
        self.assertEqual(
            report.contributing_features["baseline_evidence"], "NOT_AVAILABLE"
        )
        self.assertNotIn("caused the attack", (report.summary or "").lower())

    def test_reports_verification_stages_and_eligibility_accurately(self):
        v = _ver(
            status=VerificationStatus.INELIGIBLE,
            mitigation_eligible=False,
            reason="warmup",
            stages=[VerificationStageResult("WARMUP", False, "too_early")],
        )
        report = self.eng.analyze(RCAContext(event_id="evt-1", verification=v))
        self.assertFalse(report.contributing_features["mitigation_eligible"])
        self.assertEqual(
            report.contributing_features["verification_status"], "INELIGIBLE"
        )
        items = {
            i["key"]: i
            for i in report.contributing_features["evidence_items"]
        }
        self.assertIn("stage_WARMUP", items)
        self.assertFalse(items["stage_WARMUP"]["value"]["passed"])
        self.assertEqual(items["stage_WARMUP"]["kind"], "OBSERVED")

    def test_known_ground_truth_identities(self):
        report = self.eng.analyze(
            RCAContext(
                event_id="evt-gt",
                verification=_ver(),
                attack_hint="SYN_FLOOD",
                mitigation=MitigationEvidence(
                    eligible=True, strategy="FLOW_PAIR", result="BLOCKED"
                ),
            )
        )
        self.assertEqual(report.suspected_source, "02:aa:aa:aa:aa:01")
        self.assertEqual(report.affected_target, "02:bb:bb:bb:bb:02")
        self.assertEqual(report.contributing_features["attack_hint"], "SYN_FLOOD")
        self.assertEqual(
            report.contributing_features["mitigation_strategy"], "FLOW_PAIR"
        )
        src_item = next(
            i
            for i in report.contributing_features["evidence_items"]
            if i["key"] == "suspected_source"
        )
        self.assertEqual(src_item["kind"], "OBSERVED")

    def test_completeness_metric_excludes_non_applicable_baseline(self):
        ctx = RCAContext(event_id="e1", verification=_ver())
        # baseline not required and not supplied → not applicable
        c1 = measure_evidence_completeness(
            ctx, require_baseline=False, require_xai=False, require_mitigation_bag=False
        )
        self.assertFalse(c1.by_category["baseline_evidence"]["applicable"])
        self.assertTrue(c1.by_category["verification_evidence"]["available"])
        self.assertTrue(c1.by_category["source_identity"]["available"])
        # With XAI required but missing → lowers rate
        c2 = measure_evidence_completeness(
            ctx, require_baseline=False, require_xai=True, require_mitigation_bag=False
        )
        self.assertTrue(c2.by_category["xai_evidence"]["applicable"])
        self.assertFalse(c2.by_category["xai_evidence"]["available"])
        self.assertLess(c2.rate, c1.rate)

    def test_completeness_full_bundle(self):
        ctx = RCAContext(
            event_id="e1",
            verification=_ver(),
            explanation={"method": "DECISION_TREE_PATH", "summary": "ok"},
            mitigation=MitigationEvidence(eligible=True, strategy="SRC_MAC"),
            baseline_evidence={"src_entropy": 0.9},
            entropy_evidence={"entropy_score": 0.2},
        )
        c = measure_evidence_completeness(
            ctx,
            require_baseline=True,
            require_mitigation_bag=True,
            require_detector=True,
            require_xai=True,
        )
        self.assertEqual(c.available, c.applicable)
        self.assertEqual(c.rate, 1.0)


if __name__ == "__main__":
    unittest.main()
