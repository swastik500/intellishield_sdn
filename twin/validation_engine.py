"""TwinValidationEngine — policy gates → shared_contracts.ValidationResult."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from shared_contracts.enums import TwinOutcomeCode, ValidationStatus
from shared_contracts.models import (
    ModelCandidate,
    TwinValidationPolicy,
    ValidationResult,
)
from shared_contracts.timeutil import utc_now
from twin.experiment_plan import ExperimentEvidence
from twin.profile import default_validation_policy


# Map outcome codes onto ValidationStatus (contract permits PASS/FAIL/ERROR/SKIPPED)
_STATUS_MAP = {
    TwinOutcomeCode.PASS: ValidationStatus.PASS,
    TwinOutcomeCode.FAIL: ValidationStatus.FAIL,
    TwinOutcomeCode.INSUFFICIENT_EVIDENCE: ValidationStatus.SKIPPED,
    TwinOutcomeCode.EXPERIMENT_FAILED: ValidationStatus.ERROR,
}


@dataclass
class GateFinding:
    code: str
    detail: str
    severity: str = "fail"  # fail | insufficient | experiment


@dataclass
class TwinValidationEngine:
    """Evaluate candidate metrics against TwinValidationPolicy + optional baseline."""

    policy: TwinValidationPolicy = field(default_factory=default_validation_policy)

    def evaluate(
        self,
        *,
        candidate: ModelCandidate,
        evidence: Sequence[ExperimentEvidence],
        baseline_metrics: Optional[Dict[str, Any]] = None,
        artifact_uri: str = "",
    ) -> ValidationResult:
        findings: List[GateFinding] = []
        aggregated = self._aggregate_metrics(evidence)

        # Experiment failure takes precedence (not a model FAIL)
        if any(not e.experiment_ok for e in evidence):
            errs = [e.experiment_error or "experiment failed" for e in evidence if not e.experiment_ok]
            return self._result(
                candidate,
                TwinOutcomeCode.EXPERIMENT_FAILED,
                aggregated,
                reason="EXPERIMENT_FAILED: " + "; ".join(errs),
                artifact_uri=artifact_uri,
                findings=findings,
            )

        # Required scenarios
        have = {e.scenario_id for e in evidence}
        for sid in self.policy.require_scenario_ids:
            if sid not in have:
                findings.append(
                    GateFinding(
                        "missing_scenario",
                        f"required scenario {sid} absent",
                        "insufficient",
                    )
                )

        # Missing artifacts / metrics → insufficient evidence (never PASS)
        for e in evidence:
            for miss in e.missing_artifacts:
                findings.append(
                    GateFinding(
                        "missing_artifact",
                        f"{e.scenario_id}: missing {miss}",
                        "insufficient",
                    )
                )

        for key in self.policy.require_metric_keys:
            if aggregated.get(key) is None:
                findings.append(
                    GateFinding(
                        "missing_metric",
                        f"required metric {key!r} absent or null",
                        "insufficient",
                    )
                )

        if any(f.severity == "insufficient" for f in findings):
            return self._result(
                candidate,
                TwinOutcomeCode.INSUFFICIENT_EVIDENCE,
                aggregated,
                reason="INSUFFICIENT_EVIDENCE: "
                + "; ".join(f.detail for f in findings if f.severity == "insufficient"),
                artifact_uri=artifact_uri,
                findings=findings,
                baseline_metrics=baseline_metrics,
            )

        # Hard quality gates
        self._check_min("precision", aggregated, self.policy.min_precision, findings)
        self._check_min("recall", aggregated, self.policy.min_recall, findings)
        self._check_min("f1_score", aggregated, self.policy.min_f1, findings)
        self._check_max(
            "false_positive_rate", aggregated, self.policy.max_fpr, findings
        )
        self._check_max(
            "false_negative_rate", aggregated, self.policy.max_fnr, findings
        )
        self._check_max(
            "detection_latency_s",
            aggregated,
            self.policy.max_detection_latency_sec,
            findings,
        )
        self._check_max(
            "runtime_latency_s",
            aggregated,
            self.policy.max_runtime_latency_sec,
            findings,
        )
        if self.policy.max_false_mitigations is not None:
            fm = aggregated.get("false_mitigations")
            if fm is not None and float(fm) > self.policy.max_false_mitigations:
                findings.append(
                    GateFinding(
                        "max_false_mitigations",
                        f"false_mitigations={fm} > {self.policy.max_false_mitigations}",
                    )
                )

        # Baseline comparison (bounded regression — need not improve every metric)
        if baseline_metrics:
            self._check_regression(
                aggregated,
                baseline_metrics,
                "f1_score",
                self.policy.max_f1_regression,
                higher_is_better=True,
                findings=findings,
            )
            self._check_regression(
                aggregated,
                baseline_metrics,
                "precision",
                self.policy.max_precision_regression,
                higher_is_better=True,
                findings=findings,
            )
            self._check_regression(
                aggregated,
                baseline_metrics,
                "false_positive_rate",
                self.policy.max_fpr_increase,
                higher_is_better=False,
                findings=findings,
            )

        if any(f.severity == "insufficient" for f in findings):
            return self._result(
                candidate,
                TwinOutcomeCode.INSUFFICIENT_EVIDENCE,
                aggregated,
                reason="INSUFFICIENT_EVIDENCE: "
                + "; ".join(f.detail for f in findings if f.severity == "insufficient"),
                artifact_uri=artifact_uri,
                findings=findings,
                baseline_metrics=baseline_metrics,
            )

        if findings:
            return self._result(
                candidate,
                TwinOutcomeCode.FAIL,
                aggregated,
                reason="FAIL: " + "; ".join(f.detail for f in findings),
                artifact_uri=artifact_uri,
                findings=findings,
                baseline_metrics=baseline_metrics,
            )

        return self._result(
            candidate,
            TwinOutcomeCode.PASS,
            aggregated,
            reason="PASS: all policy gates satisfied",
            artifact_uri=artifact_uri,
            findings=findings,
            baseline_metrics=baseline_metrics,
        )

    def _aggregate_metrics(
        self, evidence: Sequence[ExperimentEvidence]
    ) -> Dict[str, Any]:
        """Mean of available numeric metrics across scenarios."""
        keys = {
            "precision",
            "recall",
            "f1_score",
            "false_positive_rate",
            "false_negative_rate",
            "detection_latency_s",
            "runtime_latency_s",
            "false_mitigations",
            "accuracy",
        }
        buckets: Dict[str, List[float]] = {k: [] for k in keys}
        for e in evidence:
            for k in keys:
                v = e.metric(k)
                if v is not None:
                    buckets[k].append(v)
        out: Dict[str, Any] = {
            "scenario_ids": [e.scenario_id for e in evidence],
            "evidence_source": sorted({e.source for e in evidence}),
        }
        for k, vals in buckets.items():
            out[k] = round(sum(vals) / len(vals), 6) if vals else None
        return out

    def _check_min(
        self,
        key: str,
        metrics: Dict[str, Any],
        threshold: Optional[float],
        findings: List[GateFinding],
    ) -> None:
        if threshold is None:
            return
        val = metrics.get(key)
        if val is None:
            findings.append(
                GateFinding("missing_metric", f"{key} missing for min gate", "insufficient")
            )
            return
        if float(val) < threshold:
            findings.append(
                GateFinding(f"min_{key}", f"{key}={val} < min {threshold}")
            )

    def _check_max(
        self,
        key: str,
        metrics: Dict[str, Any],
        threshold: Optional[float],
        findings: List[GateFinding],
    ) -> None:
        if threshold is None:
            return
        val = metrics.get(key)
        if val is None:
            findings.append(
                GateFinding("missing_metric", f"{key} missing for max gate", "insufficient")
            )
            return
        if float(val) > threshold:
            findings.append(
                GateFinding(f"max_{key}", f"{key}={val} > max {threshold}")
            )

    def _check_regression(
        self,
        cand: Dict[str, Any],
        baseline: Dict[str, Any],
        key: str,
        tolerance: Optional[float],
        *,
        higher_is_better: bool,
        findings: List[GateFinding],
    ) -> None:
        if tolerance is None:
            return
        c = cand.get(key)
        b = baseline.get(key)
        if c is None or b is None:
            return  # baseline optional; missing baseline metric skips regression
        c_f, b_f = float(c), float(b)
        if higher_is_better:
            drop = b_f - c_f
            if drop > tolerance:
                findings.append(
                    GateFinding(
                        f"regression_{key}",
                        f"{key} regression {drop:.4f} > allowed {tolerance}",
                    )
                )
        else:
            increase = c_f - b_f
            if increase > tolerance:
                findings.append(
                    GateFinding(
                        f"regression_{key}",
                        f"{key} increase {increase:.4f} > allowed {tolerance}",
                    )
                )

    def _result(
        self,
        candidate: ModelCandidate,
        outcome: TwinOutcomeCode,
        metrics: Dict[str, Any],
        *,
        reason: str,
        artifact_uri: str,
        findings: List[GateFinding],
        baseline_metrics: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        payload = dict(metrics)
        payload["outcome_code"] = outcome.value
        payload["policy_id"] = self.policy.policy_id
        payload["policy_version"] = self.policy.version
        payload["findings"] = [
            {"code": f.code, "detail": f.detail, "severity": f.severity}
            for f in findings
        ]
        if baseline_metrics:
            payload["baseline_metrics"] = {
                k: baseline_metrics[k]
                for k in (
                    "precision",
                    "recall",
                    "f1_score",
                    "false_positive_rate",
                    "detection_latency_s",
                )
                if k in baseline_metrics
            }
        return ValidationResult(
            validation_id=str(uuid4()),
            timestamp=utc_now(),
            status=_STATUS_MAP[outcome],
            model_id=candidate.model.model_id,
            candidate_id=candidate.candidate_id,
            metrics=payload,
            reason=reason,
            artifact_uri=artifact_uri,
        )
