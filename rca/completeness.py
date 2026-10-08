"""
RCA evidence-completeness metric (R5.5).

Reports available / applicable evidence. Non-applicable categories are
excluded from the denominator (not treated as failures).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from rca.context import RCAContext

CATEGORIES = (
    "source_identity",
    "target_identity",
    "detector_evidence",
    "xai_evidence",
    "verification_evidence",
    "mitigation_evidence",
    "baseline_evidence",
)


@dataclass(frozen=True)
class CompletenessResult:
    available: int
    applicable: int
    rate: float
    by_category: Dict[str, Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "applicable": self.applicable,
            "rate": self.rate,
            "by_category": self.by_category,
        }


def measure_evidence_completeness(
    context: Optional[RCAContext],
    *,
    require_baseline: bool = False,
    require_mitigation_bag: bool = False,
    require_detector: bool = False,
    require_xai: bool = True,
) -> CompletenessResult:
    """
    Score completeness of an RCAContext.

    Categories marked non-applicable (e.g. baseline when not required and
    not supplied) do not reduce the rate.
    """
    if context is None:
        by_cat = {
            c: {"applicable": False, "available": False}
            for c in CATEGORIES
        }
        return CompletenessResult(0, 0, 0.0, by_cat)

    v = context.verification
    has_source = bool(
        (v is not None and v.attacker_mac)
        or (context.detection is not None and context.detection.src_mac)
        or context.source_mac
    )
    has_target = bool(
        (v is not None and v.victim_mac)
        or (context.detection is not None and context.detection.dst_mac)
        or context.target_mac
    )
    has_detector = bool(
        (
            context.detection is not None
            and list(context.detection.detector_results or [])
        )
        or context.entropy_evidence
    )
    has_xai = context.explanation is not None
    has_verification = v is not None
    has_mitigation = context.mitigation is not None
    has_baseline = context.baseline_evidence is not None

    # Applicability: always for core identity/verification; optional bags
    # only when required OR already supplied (supplied ⇒ applicable).
    applicable_flags = {
        "source_identity": True,
        "target_identity": True,
        "verification_evidence": True,
        "xai_evidence": bool(require_xai or has_xai),
        "detector_evidence": bool(require_detector or has_detector),
        "mitigation_evidence": bool(require_mitigation_bag or has_mitigation),
        "baseline_evidence": bool(require_baseline or has_baseline),
    }
    available_flags = {
        "source_identity": has_source,
        "target_identity": has_target,
        "detector_evidence": has_detector,
        "xai_evidence": has_xai,
        "verification_evidence": has_verification,
        "mitigation_evidence": has_mitigation,
        "baseline_evidence": has_baseline,
    }

    by_category: Dict[str, Dict[str, Any]] = {}
    available = 0
    applicable = 0
    for cat in CATEGORIES:
        app = bool(applicable_flags[cat])
        by_category[cat] = {
            "applicable": app,
            "available": bool(available_flags[cat]) if app else False,
        }
        if app:
            applicable += 1
            if available_flags[cat]:
                available += 1

    rate = round(available / applicable, 6) if applicable else 0.0
    return CompletenessResult(available, applicable, rate, by_category)
