#!/usr/bin/env python3
"""Unit tests for FOUNDATION shared_contracts package."""

from __future__ import annotations

import json
import math
import os
import sys
import unittest
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts import (
    SCHEMA_VERSION,
    AlertEvent,
    AlertType,
    CandidateStatus,
    CorrelationResult,
    DetectionDecision,
    DetectionEvent,
    DetectorHealth,
    DetectorResult,
    DetectorType,
    FusedDecision,
    ModelCandidate,
    ModelStatus,
    ModelVersion,
    RootCauseReport,
    Severity,
    ValidationResult,
    ValidationStatus,
    VerificationResult,
    VerificationStageResult,
    VerificationStatus,
    format_ts,
    from_dict,
    from_json,
    parse_ts,
    to_dict,
    to_json,
    utc_now,
)
from shared_contracts.enums import parse_detection_decision
from shared_contracts.models import new_id
from shared_contracts.timeutil import format_legacy_ts


class TestConstruction(unittest.TestCase):
    def test_detector_result_required_fields(self):
        ts = utc_now()
        r = DetectorResult(
            detector=DetectorType.ML,
            timestamp=ts,
            decision=DetectionDecision.ATTACK,
            confidence=0.87,
        )
        self.assertEqual(r.detector, DetectorType.ML)
        self.assertEqual(r.decision, DetectionDecision.ATTACK)
        self.assertEqual(r.confidence, 0.87)
        self.assertEqual(r.health, DetectorHealth.SUCCESS)
        self.assertEqual(r.schema_version, SCHEMA_VERSION)

    def test_optional_fields_default(self):
        r = DetectorResult(detector=DetectorType.ADWIN, timestamp=utc_now())
        self.assertEqual(r.decision, DetectionDecision.NONE)
        self.assertIsNone(r.confidence)
        self.assertIsNone(r.score)
        self.assertEqual(r.evidence, {})

    def test_nested_detection_event(self):
        ts = utc_now()
        dr = DetectorResult(
            detector=DetectorType.ENTROPY,
            timestamp=ts,
            decision=DetectionDecision.ALERT,
            confidence=0.9,
            score=0.12,
            threshold=0.2,
        )
        ev = DetectionEvent(
            event_id="evt-1",
            timestamp=ts,
            switch_id=1,
            src_mac="aa:bb:cc:dd:ee:ff",
            detector_results=[dr],
            context={"cycle": 4},
        )
        self.assertEqual(ev.event_id, "evt-1")
        self.assertEqual(len(ev.detector_results), 1)
        self.assertEqual(ev.detector_results[0].detector, DetectorType.ENTROPY)

    def test_empty_optional_collections(self):
        ev = DetectionEvent(event_id="e2", timestamp=utc_now())
        self.assertEqual(ev.detector_results, [])
        self.assertEqual(ev.context, {})


class TestEnums(unittest.TestCase):
    def test_enum_values_match_legacy_strings(self):
        self.assertEqual(DetectionDecision.ATTACK.value, "ATTACK")
        self.assertEqual(DetectionDecision.NORMAL.value, "NORMAL")
        self.assertEqual(DetectionDecision.SUSPICIOUS.value, "SUSPICIOUS")
        self.assertEqual(DetectionDecision.ALERT.value, "ALERT")

    def test_parse_detection_decision(self):
        self.assertEqual(parse_detection_decision("attack"), DetectionDecision.ATTACK)
        self.assertEqual(parse_detection_decision(DetectionDecision.NORMAL), DetectionDecision.NORMAL)
        self.assertEqual(parse_detection_decision(None), DetectionDecision.NONE)
        self.assertEqual(parse_detection_decision("nope"), DetectionDecision.NONE)


class TestTimestamps(unittest.TestCase):
    def test_naive_becomes_utc(self):
        naive = datetime(2026, 7, 1, 12, 0, 0)
        r = DetectorResult(detector=DetectorType.ML, timestamp=naive)
        self.assertIsNotNone(r.timestamp.tzinfo)
        self.assertEqual(r.timestamp.utcoffset().total_seconds(), 0)

    def test_format_and_parse_iso_z(self):
        ts = datetime(2026, 7, 1, 12, 30, 0, tzinfo=timezone.utc)
        text = format_ts(ts)
        self.assertTrue(text.endswith("Z"))
        parsed = parse_ts(text)
        self.assertEqual(parsed, ts)

    def test_legacy_csv_format_parse(self):
        parsed = parse_ts("2026-07-01 12:30:00")
        self.assertIsNotNone(parsed)
        self.assertEqual(format_legacy_ts(parsed), "2026-07-01 12:30:00")


class TestIds(unittest.TestCase):
    def test_new_id_unique(self):
        a, b = new_id(), new_id()
        self.assertNotEqual(a, b)
        self.assertTrue(len(a) > 10)

    def test_empty_event_id_rejected(self):
        with self.assertRaises(ValueError):
            DetectionEvent(event_id="  ", timestamp=utc_now())

    def test_empty_alert_id_rejected(self):
        with self.assertRaises(ValueError):
            AlertEvent(
                alert_id="",
                timestamp=utc_now(),
                severity=Severity.HIGH,
                alert_type=AlertType.DETECTION,
                title="x",
            )


class TestValidation(unittest.TestCase):
    def test_invalid_confidence(self):
        with self.assertRaises(ValueError):
            DetectorResult(
                detector=DetectorType.ML,
                timestamp=utc_now(),
                confidence=1.5,
            )

    def test_nan_confidence(self):
        with self.assertRaises(ValueError):
            DetectorResult(
                detector=DetectorType.ML,
                timestamp=utc_now(),
                confidence=float("nan"),
            )

    def test_inf_score(self):
        with self.assertRaises(ValueError):
            DetectorResult(
                detector=DetectorType.ML,
                timestamp=utc_now(),
                score=float("inf"),
            )

    def test_raw_score_outside_unit_ok(self):
        r = DetectorResult(
            detector=DetectorType.ML,
            timestamp=utc_now(),
            score=85.2,
        )
        self.assertEqual(r.score, 85.2)

    def test_non_json_safe_evidence_rejected(self):
        with self.assertRaises(ValueError):
            DetectorResult(
                detector=DetectorType.ML,
                timestamp=utc_now(),
                evidence={"bad": object()},
            )


class TestSerialization(unittest.TestCase):
    def _sample_event(self) -> DetectionEvent:
        ts = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
        return DetectionEvent(
            event_id="evt-ser",
            timestamp=ts,
            switch_id=1,
            detector_results=[
                DetectorResult(
                    detector=DetectorType.ML,
                    timestamp=ts,
                    decision=DetectionDecision.ATTACK,
                    confidence=0.8,
                    attack_hint="SYN_FLOOD",
                    evidence={"pkt": 1200},
                )
            ],
        )

    def test_to_dict_has_type_and_schema(self):
        d = to_dict(self._sample_event())
        self.assertEqual(d["_type"], "DetectionEvent")
        self.assertEqual(d["schema_version"], SCHEMA_VERSION)
        self.assertEqual(d["detector_results"][0]["decision"], "ATTACK")

    def test_json_round_trip(self):
        ev = self._sample_event()
        text = to_json(ev)
        restored = from_json(text, DetectionEvent)
        self.assertEqual(restored.event_id, ev.event_id)
        self.assertEqual(restored.detector_results[0].decision, DetectionDecision.ATTACK)
        self.assertEqual(restored.detector_results[0].confidence, 0.8)
        self.assertEqual(restored.timestamp, ev.timestamp)

    def test_from_dict_uses_type_discriminator(self):
        d = to_dict(self._sample_event())
        restored = from_dict(d)
        self.assertIsInstance(restored, DetectionEvent)

    def test_dict_is_json_compatible(self):
        d = to_dict(self._sample_event())
        json.dumps(d)  # must not raise


class TestLifecycleContracts(unittest.TestCase):
    def test_model_version_serialize(self):
        mv = ModelVersion(
            model_id="dt-1",
            version="1.0.0",
            algorithm="DecisionTree",
            created_at=utc_now(),
            artifact_uri="logs/models/decision_tree.pkl",
            metrics={"f1": 0.88},
            status=ModelStatus.CHAMPION,
        )
        restored = from_json(to_json(mv), ModelVersion)
        self.assertEqual(restored.model_id, "dt-1")
        self.assertEqual(restored.status, ModelStatus.CHAMPION)
        self.assertEqual(restored.metrics["f1"], 0.88)

    def test_model_candidate_references_version(self):
        mv = ModelVersion(
            model_id="if-1",
            version="2",
            algorithm="IsolationForest",
            created_at=utc_now(),
        )
        cand = ModelCandidate(
            candidate_id="cand-1",
            model=mv,
            status=CandidateStatus.READY,
        )
        restored = from_dict(to_dict(cand), ModelCandidate)
        self.assertEqual(restored.model.model_id, "if-1")
        self.assertEqual(restored.status, CandidateStatus.READY)

    def test_validation_result(self):
        vr = ValidationResult(
            validation_id="val-1",
            timestamp=utc_now(),
            status=ValidationStatus.FAIL,
            model_id="dt-1",
            candidate_id="cand-1",
            metrics={"fpr": 0.2},
            reason="FPR above bound",
        )
        restored = from_json(to_json(vr))
        self.assertEqual(restored.status, ValidationStatus.FAIL)
        self.assertEqual(restored.reason, "FPR above bound")


class TestDownstreamContracts(unittest.TestCase):
    def test_correlation_result(self):
        cr = CorrelationResult(
            correlation_id="corr-1",
            timestamp=utc_now(),
            event_id="evt-1",
            score=0.7,
            severity=Severity.HIGH,
            signal_ids=["entropy", "ml", "cpu"],
        )
        restored = from_dict(to_dict(cr), CorrelationResult)
        self.assertEqual(restored.signal_ids, ["entropy", "ml", "cpu"])

    def test_fused_decision(self):
        fd = FusedDecision(
            fusion_id="fuse-1",
            timestamp=utc_now(),
            decision=DetectionDecision.ATTACK,
            confidence=0.91,
            participating=["ML", "ENTROPY"],
            disagreement=False,
            reason="quorum",
        )
        restored = from_json(to_json(fd), FusedDecision)
        self.assertEqual(restored.decision, DetectionDecision.ATTACK)

    def test_verification_result_with_stages(self):
        vr = VerificationResult(
            verification_id="ver-1",
            timestamp=utc_now(),
            status=VerificationStatus.VERIFIED,
            confidence=0.9,
            stages=[
                VerificationStageResult(stage_name="warmup", passed=True),
                VerificationStageResult(stage_name="streak", passed=True, reason="2/2"),
            ],
            attacker_mac="aa:bb:cc:dd:ee:01",
            mitigation_eligible=True,
        )
        restored = from_dict(to_dict(vr), VerificationResult)
        self.assertEqual(len(restored.stages), 2)
        self.assertTrue(restored.mitigation_eligible)

    def test_root_cause_report(self):
        rca = RootCauseReport(
            report_id="rca-1",
            event_id="evt-1",
            timestamp=utc_now(),
            summary="SYN flood from h1",
            suspected_source="aa:bb:cc:dd:ee:01",
            affected_target="aa:bb:cc:dd:ee:02",
            contributing_signals=["entropy.src", "ml"],
            contributing_features={"packet_rate_max": 10000},
            confidence=0.85,
            explanation_summary="packet_rate_max above normal",
        )
        restored = from_json(to_json(rca), RootCauseReport)
        self.assertEqual(restored.suspected_source, "aa:bb:cc:dd:ee:01")

    def test_alert_event(self):
        alert = AlertEvent(
            alert_id="alert-1",
            timestamp=utc_now(),
            severity=Severity.CRITICAL,
            alert_type=AlertType.DETECTION,
            title="Attack confirmed",
            message="SYN flood",
            event_id="evt-1",
            source="verification",
            rca_report_id="rca-1",
            mitigation_status="BLOCK_SUCCESS",
            dedup_key="evt-1:ATTACK",
        )
        restored = from_dict(to_dict(alert), AlertEvent)
        self.assertEqual(restored.severity, Severity.CRITICAL)
        self.assertEqual(restored.dedup_key, "evt-1:ATTACK")


class TestImportSideEffects(unittest.TestCase):
    def test_import_does_not_create_files(self):
        # Package import already happened; ensure no models/*.pkl created by it.
        models_dir = os.path.join(_ROOT, "logs", "models")
        before = set(os.listdir(models_dir)) if os.path.isdir(models_dir) else set()
        import importlib
        import shared_contracts

        importlib.reload(shared_contracts)
        after = set(os.listdir(models_dir)) if os.path.isdir(models_dir) else set()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
