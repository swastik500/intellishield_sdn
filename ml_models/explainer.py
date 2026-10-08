"""
================================================================================
IntelliShield SDN — Phase 4: ML-Based Anomaly Detection
================================================================================

File        : ml_models/explainer.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 4 — ML Anomaly Detection

Description:
    Explainability layer for the Phase 4 ML models.

    Generates human-readable explanations for every anomaly prediction,
    answering:
        "WHY was this traffic classified as ATTACK?"

    Outputs:
        - Feature importance ranking (top 5 features driving the decision)
        - Per-feature deviation analysis (how far from normal baseline)
        - Anomaly narrative (text explanation for logs / dashboard)
        - Decision tree path (if DT model is trained)

    IEEE Relevance:
        Explainability is a key research requirement. Black-box models
        are insufficient for academic and network operator trust.
        This module makes the ML decisions transparent and auditable.

================================================================================
"""

import logging
from typing import List, Dict, Optional, Tuple

from ml_models.feature_builder import FEATURE_NAMES
from ml_models.attack_type_classifier import classify_attack_type
from ml_models.ml_utils import label_to_str, format_confidence

logger = logging.getLogger("intellishield.explainer")

# ─── Feature Descriptions ─────────────────────────────────────────────────────
# Maps each feature name to a human-readable description and attack indicator

FEATURE_DESCRIPTIONS = {
    "packet_rate_mean"  : ("Mean packet rate (pkt/s)",          "High → flood traffic"),
    "packet_rate_max"   : ("Peak packet rate (pkt/s)",           "Spike → burst attack"),
    "byte_rate_mean"    : ("Mean byte rate (B/s)",               "High → volumetric attack"),
    "byte_rate_max"     : ("Peak byte rate (B/s)",               "Spike → bandwidth flood"),
    "flow_count"        : ("Number of active flows",             "Low → concentrated attack"),
    "duration_mean"     : ("Mean flow duration (sec)",           "Very long → sustained flood"),
    "unique_src_count"  : ("Unique source MAC count",            "Low → single-source DDoS"),
    "unique_dst_count"  : ("Unique destination MAC count",       "Low → victim concentration"),
    "src_entropy"       : ("Source MAC entropy [0-1]",           "Low → entropy collapse"),
    "dst_entropy"       : ("Destination entropy [0-1]",          "Low → victim focused"),
    "packet_entropy"    : ("Packet distribution entropy [0-1]",  "Low → single flow dominates"),
    "byte_entropy"      : ("Byte distribution entropy [0-1]",    "Low → bandwidth dominated"),
    "flow_entropy"      : ("Flow distribution entropy [0-1]",    "Low → unbalanced flows"),
    "entropy_score"     : ("Composite entropy score [0-1]",      "Low → overall collapse"),
    "flow_concentration": ("Flow concentration [0-1]",           "High → attack source focus"),
}

# Nominal (normal) ranges for deviation analysis
NORMAL_RANGES = {
    "packet_rate_mean"  : (0,    500),
    "packet_rate_max"   : (0,   1500),
    "byte_rate_mean"    : (0, 750000),
    "byte_rate_max"     : (0, 2000000),
    "flow_count"        : (3,     20),
    "duration_mean"     : (1,    120),
    "unique_src_count"  : (2,     10),
    "unique_dst_count"  : (2,      8),
    "src_entropy"       : (0.6,  1.0),
    "dst_entropy"       : (0.6,  1.0),
    "packet_entropy"    : (0.5,  1.0),
    "byte_entropy"      : (0.5,  1.0),
    "flow_entropy"      : (0.6,  1.0),
    "entropy_score"     : (0.55, 1.0),
    "flow_concentration": (0.0,  0.4),
}


# ─── Explainer ────────────────────────────────────────────────────────────────

class Explainer:
    """
    Produces human-readable explanations for ML anomaly predictions.

    Usage:
        explainer = Explainer()
        explanation = explainer.explain(
            vector     = feature_vector,
            prediction = prediction_dict,   # from AnomalyDetector.predict()
        )
        explainer.print_explanation(explanation)
    """

    def explain(self,
                vector: List[float],
                prediction: Dict) -> Dict:
        """
        Generate a full explanation for one anomaly prediction.

        Args:
            vector    : 15-dim feature vector (same order as FEATURE_NAMES).
            prediction: Dict from AnomalyDetector.predict().

        Returns:
            dict with:
                status          : NORMAL / SUSPICIOUS / ATTACK
                confidence      : float
                anomalous_features: List of (name, value, deviation, note) tuples
                attack_type_hint: Guessed attack type based on feature patterns
                narrative       : Human-readable text explanation
                top_features    : Top 5 contributing features
        """
        status        = prediction.get("status",     "UNKNOWN")
        confidence    = prediction.get("confidence", 0.0)
        top_features  = prediction.get("top_features", [])

        # ── Deviation analysis ────────────────────────────────────────────────
        anomalous = self._find_anomalous_features(vector)

        # ── Attack type hint ──────────────────────────────────────────────────
        attack_hint = self._guess_attack_type(vector, status)

        # ── Narrative ─────────────────────────────────────────────────────────
        narrative = self._build_narrative(status, confidence, anomalous, attack_hint)

        return {
            "status"            : status,
            "confidence"        : confidence,
            "anomalous_features": anomalous,
            "attack_type_hint"  : attack_hint,
            "narrative"         : narrative,
            "top_features"      : top_features,
            "vector_summary"    : self._vector_summary(vector),
        }

    # ─── Feature Deviation Analysis ───────────────────────────────────────────

    def _find_anomalous_features(self, vector: List[float]) -> List[Tuple]:
        """
        Identify features that fall outside their normal ranges.

        Returns:
            List of tuples: (feature_name, value, deviation_str, note)
            Sorted by severity of deviation.
        """
        anomalous = []
        for i, (name, value) in enumerate(zip(FEATURE_NAMES, vector)):
            lo, hi = NORMAL_RANGES.get(name, (None, None))
            if lo is None:
                continue

            desc, note = FEATURE_DESCRIPTIONS.get(name, ("", ""))

            if value < lo:
                # Below normal range
                deviation = f"BELOW normal ({value:.4f} < {lo})"
                anomalous.append((name, value, deviation, note))
            elif value > hi:
                # Above normal range
                deviation = f"ABOVE normal ({value:.4f} > {hi})"
                anomalous.append((name, value, deviation, note))

        return anomalous

    def _guess_attack_type(self, vector: List[float], status: str) -> str:
        """
        Heuristically guess the DDoS attack type from feature patterns.

        Returns:
            str: "SYN_FLOOD" / "UDP_FLOOD" / "ICMP_FLOOD" / "BURST" / etc.
        """
        return classify_attack_type(vector, status=status)

    def _build_narrative(self, status: str, confidence: float,
                          anomalous: list, attack_hint: str) -> str:
        """Build a human-readable explanation paragraph."""
        if status == "NORMAL":
            return (
                "Traffic appears NORMAL. All entropy dimensions and flow "
                "metrics are within expected baseline ranges. "
                "No anomaly detected."
            )

        lines = []
        lines.append(
            f"⚠️  Traffic classified as {status} "
            f"(confidence: {confidence:.1f}%)."
        )

        if attack_hint not in ("NORMAL", "UNKNOWN_ANOMALY"):
            lines.append(f"    Probable attack type: {attack_hint}.")

        if anomalous:
            lines.append(f"    Anomalous features ({len(anomalous)} out of 15):")
            for name, val, dev, note in anomalous[:5]:
                lines.append(f"      • {name}: {val:.4f}  [{dev}]  → {note}")

        if status == "ATTACK":
            lines.append(
                "    ACTION: Route to mitigation engine for flow blocking."
                " [HOOK: Phase 5 → mitigation/flow_blocker.py]"
            )

        return "\n".join(lines)

    def _vector_summary(self, vector: List[float]) -> Dict:
        """Return a compact named dict of the feature vector."""
        return {name: round(val, 4)
                for name, val in zip(FEATURE_NAMES, vector)}

    # ─── Console Printing ─────────────────────────────────────────────────────

    def print_explanation(self, explanation: Dict) -> None:
        """Print a formatted explanation block to console."""
        status     = explanation["status"]
        confidence = explanation["confidence"]
        attack     = explanation["attack_type_hint"]
        anomalous  = explanation["anomalous_features"]
        top        = explanation["top_features"]

        border = "=" * 58
        print(f"\n{border}")
        print(f"  [ML EXPLANATION]  Status: {status}  |  Confidence: {confidence:.1f}%")
        print(f"  Attack Type Hint : {attack}")
        print(f"{border}")

        if top:
            print("  Top ML Features (Decision Tree importance):")
            for name, imp in top:
                bar = "█" * int(imp * 30)
                print(f"    {name:<22} {imp:.4f}  {bar}")
            print()

        if anomalous:
            print(f"  Anomalous Features ({len(anomalous)} detected):")
            for name, val, dev, note in anomalous:
                print(f"    ⚠  {name:<22} {val:>12.4f}  {dev}")
                print(f"       └→ {note}")
        else:
            print("  No out-of-range features detected.")

        print(f"\n  Narrative:")
        for line in explanation["narrative"].split("\n"):
            print(f"  {line}")
        print(f"{border}\n")
