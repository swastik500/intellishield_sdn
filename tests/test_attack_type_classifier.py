"""Tests for attack type hint classification."""

import os
import tempfile
import unittest

from ml_models.attack_type_classifier import (
    classify_attack_type,
    resolve_attack_hint_from_lab_logs,
)
from ml_models.feature_builder import FEATURE_NAMES


def _vec(**overrides):
    base = {
        "packet_rate_mean": 100.0,
        "packet_rate_max": 200.0,
        "byte_rate_mean": 50_000.0,
        "byte_rate_max": 100_000.0,
        "flow_count": 8.0,
        "duration_mean": 10.0,
        "unique_src_count": 3.0,
        "unique_dst_count": 3.0,
        "src_entropy": 0.9,
        "dst_entropy": 0.9,
        "packet_entropy": 0.9,
        "byte_entropy": 0.9,
        "flow_entropy": 0.9,
        "entropy_score": 0.9,
        "flow_concentration": 0.1,
    }
    base.update(overrides)
    return [float(base[name]) for name in FEATURE_NAMES]


class TestAttackTypeClassifier(unittest.TestCase):
    def test_lab_log_prefers_udp_over_syn_heuristics(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "attack_logs.csv")
            with open(path, "w", newline="") as f:
                f.write("timestamp,attack_type,source_host,target_host,attack_rate,duration,status\n")
                f.write("2026-07-09 12:04:09,UDP_FLOOD,h1,h2,0,30,LAUNCHED\n")
                f.write("2026-07-09 12:04:39,ALL,h1,N/A,0,0,STOPPED\n")

            hint = resolve_attack_hint_from_lab_logs(
                "2026-07-09 12:04:10", logs_dir=tmp,
            )
            self.assertEqual(hint, "UDP_FLOOD")

            classified = classify_attack_type(
                _vec(
                    packet_rate_mean=9000,
                    packet_rate_max=12000,
                    src_entropy=0.1,
                    packet_entropy=0.1,
                    flow_count=2,
                ),
                status="ATTACK",
                timestamp="2026-07-09 12:04:10",
                logs_dir=tmp,
            )
            self.assertEqual(classified, "UDP_FLOOD")

    def test_heuristic_syn_flood(self):
        hint = classify_attack_type(
            _vec(
                packet_rate_mean=9000,
                packet_rate_max=12000,
                byte_rate_mean=200_000,
                src_entropy=0.1,
                packet_entropy=0.1,
                flow_count=2,
            ),
            status="ATTACK",
        )
        self.assertEqual(hint, "SYN_FLOOD")

    def test_heuristic_udp_flood(self):
        hint = classify_attack_type(
            _vec(
                packet_rate_mean=3000,
                packet_rate_max=5000,
                byte_rate_mean=2_000_000,
                byte_entropy=0.1,
                dst_entropy=0.1,
                flow_count=3,
            ),
            status="ATTACK",
        )
        self.assertEqual(hint, "UDP_FLOOD")

    def test_heuristic_burst(self):
        hint = classify_attack_type(
            _vec(
                packet_rate_mean=1500,
                packet_rate_max=9000,
                flow_count=3,
                src_entropy=0.2,
                packet_entropy=0.2,
            ),
            status="ATTACK",
        )
        self.assertEqual(hint, "BURST")

    def test_lab_log_prefers_burst_when_both_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "attack_logs.csv")
            with open(path, "w", newline="") as f:
                f.write("timestamp,attack_type,source_host,target_host,attack_rate,duration,status\n")
                f.write("2026-07-09 12:05:42,SYN_FLOOD,h1,h2,20000,8,LAUNCHED\n")
                f.write("2026-07-09 12:05:42,BURST,h1,h2,20000,8,RUNNING\n")
                f.write("2026-07-09 12:05:50,ALL,h1,N/A,0,0,STOPPED\n")

            hint = resolve_attack_hint_from_lab_logs(
                "2026-07-09 12:05:45", logs_dir=tmp,
            )
            self.assertEqual(hint, "BURST")


if __name__ == "__main__":
    unittest.main()
