#!/usr/bin/env python3
"""R4.1 — Signal inventory + SignalEvent / EntityIdentity / CorrelationWindow."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.models import CorrelationResult
from correlation import (
    CATEGORY_RATIONALE,
    SIGNAL_INVENTORY,
    CorrelationWindow,
    EntityIdentity,
    FakeTimeProvider,
    NormalizationClass,
    SignalCategory,
    SignalEvent,
    build_entity_key,
    inventory_summary,
    list_available_signals,
    new_signal_id,
    new_window_id,
)
from correlation.inventory import FORBIDDEN_CLAIMS


def _ts(sec=0):
    return datetime(2026, 7, 26, 12, 0, sec, tzinfo=timezone.utc)


def _sig(
    sid,
    sec,
    cat=SignalCategory.DATA_PLANE,
    source="flow_stats",
    name="packet_rate",
    value=1.0,
    entity=None,
):
    return SignalEvent(
        signal_id=sid,
        timestamp=_ts(sec),
        category=cat,
        source=source,
        name=name,
        value=value,
        entity_key=entity,
    )


class TestR41SignalInventory(unittest.TestCase):
    def test_inventory_has_five_distinct_categories(self):
        cats = {d.category for d in SIGNAL_INVENTORY}
        for c in (
            SignalCategory.DATA_PLANE,
            SignalCategory.CONTROL_PLANE,
            SignalCategory.DETECTION,
            SignalCategory.DRIFT_CLUSTERING,
            SignalCategory.SECURITY_RESPONSE,
        ):
            self.assertIn(c, cats)
        self.assertGreaterEqual(len(SIGNAL_INVENTORY), 30)

    def test_category_rationale_documented(self):
        for key in CATEGORY_RATIONALE:
            self.assertTrue(CATEGORY_RATIONALE[key].strip())

    def test_no_forbidden_layer_claims(self):
        blob = " ".join(
            f"{d.signal_key} {d.notes} {d.producer}".lower() for d in SIGNAL_INVENTORY
        )
        for claim in ("http", "dns", "l7 application", "tls_sni", "endpoint_edr"):
            self.assertNotIn(claim, blob)
        for d in SIGNAL_INVENTORY:
            self.assertFalse(d.claimed_layer_forbidden)
            self.assertIsInstance(d.normalization, NormalizationClass)

    def test_inventory_fields_complete(self):
        for d in SIGNAL_INVENTORY:
            self.assertTrue(d.unit)
            self.assertTrue(d.value_range)
            self.assertTrue(d.timestamp_source)
            self.assertTrue(d.update_frequency)
            self.assertTrue(d.persistence)
            self.assertTrue(d.reliability)
            self.assertTrue(d.correlation_use)

    def test_forbidden_and_summary(self):
        self.assertIn("HTTP", FORBIDDEN_CLAIMS)
        summary = inventory_summary()
        self.assertEqual(summary["correlation_engine"], "CorrelationEngine (R4.2+)")
        self.assertEqual(summary["foundation_correlation_result"], "UNCHANGED")
        self.assertEqual(summary["output_contract"], "shared_contracts.CorrelationResult")
        self.assertEqual(summary["production_integration"], "R4.3_ADVISORY")

    def test_runtime_live_filter(self):
        live = list_available_signals(runtime_live_only=True)
        self.assertTrue(all(d.runtime_live for d in live))
        drift = list_available_signals(category=SignalCategory.DRIFT_CLUSTERING)
        self.assertTrue(all(d.category == SignalCategory.DRIFT_CLUSTERING for d in drift))


class TestR41SignalEvent(unittest.TestCase):
    def test_construction_and_json(self):
        s = SignalEvent(
            signal_id=new_signal_id(),
            timestamp=_ts(),
            category=SignalCategory.DETECTION,
            source="ml",
            name="confidence",
            value=94.0,
            unit="percent",
            normalized_score=0.94,
            entity_key=build_entity_key(src_mac="02:AA:AA:AA:AA:01", switch_id=1),
            event_id="evt-1",
            switch_id=1,
        )
        payload = s.to_dict()
        json.dumps(payload)
        self.assertEqual(payload["category"], "DETECTION")
        self.assertEqual(payload["normalized_score"], 0.94)
        self.assertEqual(s.signal_key, "ml.confidence")

    def test_timestamp_utc(self):
        naive = datetime(2026, 7, 26, 12, 0, 0)
        s = _sig("t1", 0)
        s2 = SignalEvent(
            signal_id="t2",
            timestamp=naive,
            category=SignalCategory.DATA_PLANE,
            source="flow_stats",
            name="packet_rate",
            value=1.0,
        )
        self.assertEqual(s2.timestamp.tzinfo, timezone.utc)

    def test_rejects_non_json_value(self):
        with self.assertRaises(ValueError):
            SignalEvent(
                signal_id="s1",
                timestamp=_ts(),
                category=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value={"nested": object()},  # type: ignore[arg-type]
            )

    def test_invalid_normalized_score(self):
        with self.assertRaises(ValueError):
            SignalEvent(
                signal_id="s1",
                timestamp=_ts(),
                category=SignalCategory.DETECTION,
                source="ml",
                name="confidence",
                value=94.0,
                normalized_score=1.5,
            )

    def test_invalid_availability(self):
        with self.assertRaises(ValueError):
            SignalEvent(
                signal_id="s1",
                timestamp=_ts(),
                category=SignalCategory.CONTROL_PLANE,
                source="controller_stats",
                name="cpu_percent",
                availability="WEIRD",
            )

    def test_not_available_signal(self):
        s = SignalEvent(
            signal_id="s-cpu",
            timestamp=_ts(),
            category=SignalCategory.CONTROL_PLANE,
            source="controller_stats",
            name="cpu_percent",
            value=None,
            availability="NOT_AVAILABLE",
            evidence={"reason": "psutil_missing"},
        )
        self.assertEqual(s.availability, "NOT_AVAILABLE")


class TestR41EntityIdentity(unittest.TestCase):
    def test_entity_key_deterministic(self):
        a = EntityIdentity(src_mac="02:AA:AA:AA:AA:01", switch_id=1)
        b = EntityIdentity(src_mac="02:aa:aa:aa:aa:01", switch_id=1)
        self.assertEqual(a.key(), b.key())
        self.assertEqual(
            a.key(),
            build_entity_key(src_mac="02:AA:AA:AA:AA:01", switch_id=1),
        )

    def test_missing_identity(self):
        self.assertIsNone(EntityIdentity().key())
        self.assertIsNone(build_entity_key())

    def test_partial_fields(self):
        k = build_entity_key(src_mac="02:aa:aa:aa:aa:01")
        self.assertEqual(k, "src:02:aa:aa:aa:aa:01")
        k2 = build_entity_key(src_ip="10.0.0.1", dst_ip="10.0.0.2")
        self.assertIn("src_ip:10.0.0.1", k2)


class TestR41CorrelationWindow(unittest.TestCase):
    def test_fixed_bounds_filter(self):
        start = _ts(0)
        end = _ts(0) + timedelta(seconds=10)
        w = CorrelationWindow(
            window_id=new_window_id(),
            start=start,
            end=end,
            entity_key=build_entity_key(src_mac="02:aa:aa:aa:aa:01"),
        )
        self.assertAlmostEqual(w.duration_sec, 10.0)
        filled = w.with_signals(
            [
                _sig("a", 5, entity=build_entity_key(src_mac="02:aa:aa:aa:aa:01")),
                _sig(
                    "b",
                    30,
                    cat=SignalCategory.DETECTION,
                    source="entropy",
                    name="status",
                    value="ALERT",
                    entity=build_entity_key(src_mac="02:aa:aa:aa:aa:01"),
                ),
                _sig(
                    "c",
                    5,
                    cat=SignalCategory.DETECTION,
                    source="ml",
                    name="status",
                    value="ATTACK",
                    entity=build_entity_key(src_mac="02:ff:ff:ff:ff:ff"),
                ),
            ]
        )
        self.assertEqual(filled.signal_ids, ["a"])

    def test_window_end_before_start_rejected(self):
        with self.assertRaises(ValueError):
            CorrelationWindow(window_id="w1", start=_ts(10), end=_ts(0))

    def test_accept_ordering_and_filters(self):
        clock = FakeTimeProvider(0.0)
        w = CorrelationWindow(duration_sec=20.0, max_signals=10, clock=clock)
        w.accept(_sig("b", 5, cat=SignalCategory.DETECTION, source="ml", name="status"))
        w.accept(
            _sig(
                "a",
                1,
                cat=SignalCategory.DATA_PLANE,
                entity=build_entity_key(src_mac="02:aa:aa:aa:aa:01"),
            )
        )
        ordered = w.get()
        self.assertEqual([s.signal_id for s in ordered], ["a", "b"])
        by_cat = w.get(category=SignalCategory.DETECTION)
        self.assertEqual([s.signal_id for s in by_cat], ["b"])
        by_ent = w.get(entity_key=build_entity_key(src_mac="02:aa:aa:aa:aa:01"))
        self.assertEqual([s.signal_id for s in by_ent], ["a"])
        by_time = w.get(since=_ts(4), until=_ts(6))
        self.assertEqual([s.signal_id for s in by_time], ["b"])

    def test_event_time_expiry(self):
        clock = FakeTimeProvider(0.0)
        w = CorrelationWindow(duration_sec=10.0, max_signals=50, clock=clock)
        w.accept(_sig("old", 0))
        w.accept(_sig("mid", 5))
        w.accept(_sig("new", 15))  # reference advances; old expires
        ids = set(w.signal_ids)
        self.assertNotIn("old", ids)
        self.assertIn("mid", ids)
        self.assertIn("new", ids)

    def test_monotonic_insert_ttl(self):
        clock = FakeTimeProvider(0.0)
        w = CorrelationWindow(
            duration_sec=1000.0,
            max_signals=50,
            clock=clock,
            insert_ttl_sec=5.0,
        )
        w.accept(_sig("x", 0))
        clock.advance(6.0)
        removed = w.expire(reference_ts=_ts(0))
        self.assertGreaterEqual(removed, 1)
        self.assertEqual(w.size(), 0)

    def test_bounded_size(self):
        clock = FakeTimeProvider(0.0)
        w = CorrelationWindow(duration_sec=100.0, max_signals=3, clock=clock)
        for i in range(5):
            w.accept(_sig(f"s{i}", i))
        self.assertEqual(w.size(), 3)
        ids = w.signal_ids
        self.assertEqual(ids, ["s2", "s3", "s4"])

    def test_duplicate_id_replaces(self):
        w = CorrelationWindow(duration_sec=30.0, max_signals=10, clock=FakeTimeProvider())
        w.accept(_sig("dup", 1, value=1.0))
        w.accept(_sig("dup", 2, value=9.0))
        self.assertEqual(w.size(), 1)
        self.assertEqual(w.get()[0].value, 9.0)

    def test_boundary_timestamp_inclusive(self):
        start, end = _ts(0), _ts(0) + timedelta(seconds=10)
        w = CorrelationWindow(start=start, end=end, max_signals=10)
        self.assertTrue(w.accept(_sig("lo", 0)))
        self.assertTrue(w.accept(_sig("hi", 10)))
        self.assertFalse(w.accept(_sig("out", 11)))

    def test_different_categories_in_window(self):
        w = CorrelationWindow(duration_sec=30.0, max_signals=20, clock=FakeTimeProvider())
        w.accept(_sig("d", 1, cat=SignalCategory.DATA_PLANE))
        w.accept(
            _sig("e", 2, cat=SignalCategory.DETECTION, source="entropy", name="status")
        )
        w.accept(
            _sig("c", 3, cat=SignalCategory.CONTROL_PLANE, source="controller_stats", name="cpu_percent")
        )
        cats = set(w.categories_present())
        self.assertEqual(len(cats), 3)

    def test_fake_clock_no_sleep(self):
        clock = FakeTimeProvider(0.0)
        self.assertEqual(clock.monotonic(), 0.0)
        clock.advance(5.0)
        self.assertEqual(clock.monotonic(), 5.0)

    def test_no_controller_import(self):
        import correlation

        src = open(correlation.__file__).read()
        self.assertNotIn("flow_monitor", src)

    def test_foundation_correlation_result_unchanged(self):
        r = CorrelationResult(
            correlation_id=new_signal_id(),
            timestamp=_ts(),
            score=0.5,
            signal_ids=["a", "b"],
            evidence={"note": "R4.2 will populate"},
        )
        self.assertEqual(r.schema_version, "1.0")
        self.assertFalse(hasattr(r, "participating_layers"))  # optional via evidence

    def test_no_correlation_engine_in_r41_package(self):
        # R4.2 adds CorrelationEngine; R4.1 models remain free of scoring APIs
        from correlation.models import CorrelationWindow

        self.assertFalse(hasattr(CorrelationWindow, "correlate"))
        self.assertFalse(hasattr(CorrelationWindow, "score"))


if __name__ == "__main__":
    unittest.main()
