#!/usr/bin/env python3
"""R4.5 — Sensitivity analysis + category ablation (synthetic, reproducible)."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from correlation import (
    CorrelationConfig,
    CorrelationEngine,
    SignalCategory,
    SignalEvent,
    build_entity_key,
)


def _ts(sec=0):
    return datetime(2026, 7, 26, 16, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec)


ENT = build_entity_key(src_mac="02:aa:aa:aa:aa:01", switch_id=1)


def _full_pack():
    return [
        SignalEvent(
            signal_id="flow",
            timestamp=_ts(0),
            category=SignalCategory.DATA_PLANE,
            source="flow_stats",
            name="packet_rate",
            value=8000.0,
            normalized_score=0.9,
            entity_key=ENT,
        ),
        SignalEvent(
            signal_id="ent",
            timestamp=_ts(1),
            category=SignalCategory.DETECTION,
            source="entropy",
            name="status",
            value="ALERT",
            entity_key=ENT,
        ),
        SignalEvent(
            signal_id="ml",
            timestamp=_ts(2),
            category=SignalCategory.DETECTION,
            source="ml",
            name="status",
            value="ATTACK",
            entity_key=ENT,
        ),
        SignalEvent(
            signal_id="cpu",
            timestamp=_ts(2),
            category=SignalCategory.CONTROL_PLANE,
            source="controller_stats",
            name="cpu_percent",
            value=75.0,
            unit="percent",
        ),
    ]


class TestR45SensitivityAblation(unittest.TestCase):
    def test_sensitivity_grid(self):
        """
        Sweep window / diversity_target / correlated_min_score / DETECTION weight
        on TWO packs: mild and strong — not a single attack scenario.
        """
        mild = [
            SignalEvent(
                signal_id="ml",
                timestamp=_ts(0),
                category=SignalCategory.DETECTION,
                source="ml",
                name="status",
                value="WARNING",
                entity_key=ENT,
            ),
            SignalEvent(
                signal_id="flow",
                timestamp=_ts(5),
                category=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=200.0,
                normalized_score=0.25,
                entity_key=ENT,
            ),
        ]
        strong = _full_pack()

        windows = [15.0, 30.0, 60.0]
        diversity_targets = [2, 3, 4]
        thresholds = [0.35, 0.45, 0.55]
        det_weights = [0.8, 1.0, 1.2]

        rows = []
        for W, K, thr, dw in product(windows, diversity_targets, thresholds, det_weights):
            weights = dict(CorrelationConfig().category_weights)
            weights[SignalCategory.DETECTION.value] = dw
            cfg = CorrelationConfig(
                window_duration_sec=W,
                diversity_target=K,
                correlated_min_score=thr,
                category_weights=weights,
            )
            eng = CorrelationEngine(cfg)
            for name, pack in (("mild", mild), ("strong", strong)):
                r = eng.correlate(pack, entity_key=ENT)
                rows.append(
                    {
                        "pack": name,
                        "window_sec": W,
                        "diversity_target": K,
                        "correlated_min_score": thr,
                        "detection_weight": dw,
                        "score": round(float(r.score or 0.0), 6),
                        "status": (r.evidence or {}).get("status"),
                        "diversity_count": (r.evidence or {}).get("diversity_count"),
                    }
                )

        # Sanity: for default-like params, strong > mild
        def _pick(pack, W=30.0, K=3, thr=0.45, dw=1.0):
            for row in rows:
                if (
                    row["pack"] == pack
                    and row["window_sec"] == W
                    and row["diversity_target"] == K
                    and row["correlated_min_score"] == thr
                    and row["detection_weight"] == dw
                ):
                    return row["score"]
            return None

        self.assertGreater(_pick("strong"), _pick("mild"))

        # Wider window should not reverse strong>mild on default weights
        self.assertGreater(_pick("strong", W=60.0), _pick("mild", W=60.0))

        out = os.path.join(_ROOT, "logs", "r45_correlation_sensitivity.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        payload = {
            "n_rows": len(rows),
            "grid": {
                "windows": windows,
                "diversity_targets": diversity_targets,
                "thresholds": thresholds,
                "detection_weights": det_weights,
            },
            "rows": rows,
            "note": "synthetic sensitivity; not tuned on a single attack scenario",
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        self.assertTrue(os.path.isfile(out))
        self.assertEqual(len(rows), len(windows) * len(diversity_targets) * len(thresholds) * len(det_weights) * 2)

    def test_category_ablation(self):
        """Remove one evidence category at a time from the full pack."""
        eng = CorrelationEngine()
        full = _full_pack()
        full_score = float(eng.correlate(full, entity_key=ENT).score or 0.0)

        ablations = {
            "all": full_score,
            "minus_flow": None,
            "minus_entropy": None,
            "minus_ml": None,
            "minus_controller": None,
        }

        def without(pred):
            return [s for s in full if not pred(s)]

        ablations["minus_flow"] = float(
            eng.correlate(
                without(lambda s: s.source == "flow_stats"),
                entity_key=ENT,
            ).score
            or 0.0
        )
        ablations["minus_entropy"] = float(
            eng.correlate(
                without(lambda s: s.source == "entropy"),
                entity_key=ENT,
            ).score
            or 0.0
        )
        ablations["minus_ml"] = float(
            eng.correlate(
                without(lambda s: s.source == "ml"),
                entity_key=ENT,
            ).score
            or 0.0
        )
        ablations["minus_controller"] = float(
            eng.correlate(
                without(lambda s: s.source == "controller_stats"),
                entity_key=ENT,
            ).score
            or 0.0
        )

        # Removing a contributing category should not increase score
        for key in ("minus_flow", "minus_entropy", "minus_ml", "minus_controller"):
            self.assertLessEqual(ablations[key], full_score + 1e-9)

        # Removing DETECTION sources (entropy+ml separately) should hurt more than
        # removing optional controller in typical packs
        self.assertLessEqual(ablations["minus_ml"], ablations["minus_controller"] + 0.05)

        out = os.path.join(_ROOT, "logs", "r45_correlation_ablation.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "scores": ablations,
                    "deltas_from_all": {
                        k: round(full_score - v, 6)
                        for k, v in ablations.items()
                        if k != "all"
                    },
                    "note": "synthetic ablation of available categories only",
                },
                fh,
                indent=2,
            )
        self.assertTrue(os.path.isfile(out))


if __name__ == "__main__":
    unittest.main()
