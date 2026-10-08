"""
Champion selector for Online AutoML.

Ranks passed candidate models based on a balanced scoring formula:
  Score = F1_score - 1.5 * FPR - 0.005 * latency_ms

Prevents performance regression against the current champion before promotion.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from shared_contracts.enums import CandidateStatus
from online_automl.candidates import AutoMLCandidate

logger = logging.getLogger("intellishield.online_automl.selector")


class ChampionSelector:
    """
    Selects the champion candidate from passed validation models.
    """

    def __init__(
        self,
        max_f1_regression: float = 0.05,
        max_fpr_increase: float = 0.05,
    ) -> None:
        self.max_f1_regression = max_f1_regression
        self.max_fpr_increase = max_fpr_increase

    @staticmethod
    def compute_score(metrics: Dict[str, float]) -> float:
        """
        Composite model fitness score: F1 - 1.5*FPR - 0.005*latency_ms.
        """
        f1 = float(metrics.get("f1_score", 0.0))
        fpr = float(metrics.get("false_positive_rate", 0.0))
        lat = float(metrics.get("latency_ms", 0.0))
        return f1 - 1.5 * fpr - 0.005 * lat

    def select_champion(
        self,
        candidates: List[AutoMLCandidate],
        current_champion: Optional[AutoMLCandidate] = None,
    ) -> Tuple[Optional[AutoMLCandidate], str]:
        """
        Select best candidate among passed models.

        Args:
            candidates: List of evaluated candidates.
            current_champion: Optional existing champion model.

        Returns:
            Tuple of (selected_champion_candidate_or_None, decision_reason)
        """
        # Filter candidates that passed validation gate (CandidateStatus.READY)
        valid_candidates = [c for c in candidates if c.status == CandidateStatus.READY]

        if not valid_candidates:
            return None, "No candidates passed validation policy gates"

        # Rank valid candidates by score
        ranked = sorted(
            valid_candidates,
            key=lambda c: self.compute_score(c.metrics),
            reverse=True,
        )

        best_cand = ranked[0]
        best_score = self.compute_score(best_cand.metrics)

        # Check regression against current champion
        if current_champion is not None and current_champion.metrics:
            champ_f1 = float(current_champion.metrics.get("f1_score", 0.0))
            champ_fpr = float(current_champion.metrics.get("false_positive_rate", 0.0))
            cand_f1 = float(best_cand.metrics.get("f1_score", 0.0))
            cand_fpr = float(best_cand.metrics.get("false_positive_rate", 0.0))

            if cand_f1 < (champ_f1 - self.max_f1_regression):
                reason = f"Best candidate {best_cand.algorithm_name} regressed F1 ({cand_f1:.4f} < {champ_f1:.4f} - {self.max_f1_regression})"
                logger.info("[ChampionSelector] %s", reason)
                return None, reason

            if cand_fpr > (champ_fpr + self.max_fpr_increase):
                reason = f"Best candidate {best_cand.algorithm_name} increased FPR ({cand_fpr:.4f} > {champ_fpr:.4f} + {self.max_fpr_increase})"
                logger.info("[ChampionSelector] %s", reason)
                return None, reason

        # Promote selected best candidate
        best_cand.status = CandidateStatus.PROMOTED
        reason = f"Promoted {best_cand.algorithm_name} ({best_cand.candidate_id}) as new Champion (score: {best_score:.4f})"
        logger.info("[ChampionSelector] %s", reason)

        return best_cand, reason
