"""
XAIEngine — deterministic prediction explanation (R5.1).

Evidence-only. No LLM. No SHAP.
Does not authorize mitigation. Failures return structured degraded/unavailable.
"""

from __future__ import annotations

import logging
import math
import traceback
from typing import Any, List, Optional, Sequence, Tuple

from ml_models.attack_type_classifier import classify_attack_type
from ml_models.feature_builder import FEATURE_NAMES
from shared_contracts.timeutil import utc_now
from xai.config import XAIConfig
from xai.deviations import find_anomalous_features
from xai.models import (
    AttributionScope,
    EvidenceKind,
    ExplanationMethod,
    ExplanationStatus,
    FeatureAttribution,
    PredictionExplanation,
    empty_insufficient,
    new_explanation_id,
)
from xai.tree_path import (
    extract_decision_path,
    is_decision_tree_like,
    top_feature_importances,
)

logger = logging.getLogger("intellishield.xai")

N_FEATURES = len(FEATURE_NAMES)


class XAIEngine:
    """Build PredictionExplanation from feature vector + prediction (+ optional DT)."""

    def __init__(self, config: Optional[XAIConfig] = None) -> None:
        self.config = config or XAIConfig()

    def explain(
        self,
        vector: Optional[Sequence[float]],
        prediction: Optional[dict],
        *,
        decision_tree: Any = None,
        scaler: Any = None,
        event_id: Optional[str] = None,
        model_id: Optional[str] = None,
        model_name: str = "decision_tree",
    ) -> PredictionExplanation:
        """
        Explain one prediction.

        Production runtime is NOT modified by this call.
        Never raises; returns UNAVAILABLE/DEGRADED on failure.
        """
        pred = prediction or {}
        status_label = str(pred.get("status", "UNKNOWN") or "UNKNOWN")

        if not self.config.enabled:
            return empty_insufficient(
                reason="xai_disabled",
                event_id=event_id,
                prediction_status=status_label,
                model_id=model_id,
            )

        try:
            return self._explain_inner(
                vector,
                pred,
                decision_tree=decision_tree,
                scaler=scaler,
                event_id=event_id,
                model_id=model_id,
                model_name=model_name,
            )
        except Exception:  # noqa: BLE001
            logger.error("[XAIEngine.explain] fail-safe:\n%s", traceback.format_exc())
            return empty_insufficient(
                reason="xai_internal_error",
                event_id=event_id,
                prediction_status=status_label,
                model_id=model_id,
            )

    def explain_from_detector(
        self,
        detector: Any,
        vector: Optional[Sequence[float]],
        prediction: Optional[dict],
        *,
        event_id: Optional[str] = None,
        model_id: Optional[str] = None,
    ) -> PredictionExplanation:
        """Convenience: pull DT/scaler from AnomalyDetector-like object."""
        dt = None
        scaler = None
        try:
            if detector is not None:
                dt = getattr(detector, "decision_tree", None) or getattr(
                    detector, "_dt", None
                )
                scaler = getattr(detector, "scaler", None) or getattr(
                    detector, "_scaler", None
                )
        except Exception:  # noqa: BLE001
            dt = scaler = None
        return self.explain(
            vector,
            prediction,
            decision_tree=dt,
            scaler=scaler,
            event_id=event_id,
            model_id=model_id,
            model_name="decision_tree",
        )

    def _explain_inner(
        self,
        vector: Optional[Sequence[float]],
        prediction: dict,
        *,
        decision_tree: Any,
        scaler: Any,
        event_id: Optional[str],
        model_id: Optional[str],
        model_name: str,
    ) -> PredictionExplanation:
        status = str(prediction.get("status", "UNKNOWN") or "UNKNOWN")
        conf_f = _opt_float(prediction.get("confidence"))
        if "confidence" not in prediction or prediction.get("confidence") is None:
            conf_missing = True
        else:
            conf_missing = conf_f is None

        missing: List[str] = []
        observed: List[str] = []
        inferred: List[str] = []
        refs: List[str] = ["prediction.status"]
        if not conf_missing:
            refs.append("prediction.confidence")
        else:
            missing.append("confidence:NOT_AVAILABLE")

        # ── Feature vector validation ──
        vec_ok, vec_list, vec_errors = _validate_vector(vector)
        missing.extend(vec_errors)
        if vec_ok:
            observed.append(f"feature_vector_dim={len(vec_list)}")
            refs.append("feature_vector")
            refs.append("ml_models.feature_builder.FEATURE_NAMES")

        if any(e.startswith("feature_count_mismatch") for e in vec_errors):
            return PredictionExplanation(
                explanation_id=new_explanation_id(),
                timestamp=utc_now(),
                event_id=event_id,
                model_id=model_id,
                status=ExplanationStatus.DEGRADED.value,
                method=ExplanationMethod.FEATURE_MISMATCH.value,
                prediction_status=status,
                confidence_percent=conf_f,
                model_name=model_name if decision_tree is not None else "none",
                model_available=decision_tree is not None,
                summary=(
                    f"Explanation DEGRADED: feature-count mismatch "
                    f"(got {len(vector) if vector is not None else 0}, "
                    f"expected {N_FEATURES}). Refusing to map wrong features."
                ),
                narrative=(
                    "FEATURE_MISMATCH: vector length does not match "
                    "FEATURE_NAMES. No decision-path explanation generated."
                ),
                missing_evidence=missing,
                observed_facts=observed,
                feature_names=list(FEATURE_NAMES),
            )

        # ── Model support check ──
        model_available = decision_tree is not None
        unsupported = False
        if decision_tree is not None and not is_decision_tree_like(decision_tree):
            unsupported = True
            model_available = False
            missing.append("model:UNSUPPORTED")
            return PredictionExplanation(
                explanation_id=new_explanation_id(),
                timestamp=utc_now(),
                event_id=event_id,
                model_id=model_id,
                status=ExplanationStatus.DEGRADED.value,
                method=ExplanationMethod.UNSUPPORTED_MODEL.value,
                prediction_status=status,
                confidence_percent=conf_f,
                model_name=type(decision_tree).__name__,
                model_available=False,
                summary=(
                    f"Explanation DEGRADED: unsupported model type "
                    f"{type(decision_tree).__name__}. Native DT path XAI requires "
                    "DecisionTreeClassifier-like API."
                ),
                narrative="UNSUPPORTED_MODEL: no decision_path/tree_ interface.",
                missing_evidence=missing,
                observed_facts=observed + [f"prediction_status={status}"],
                feature_names=list(FEATURE_NAMES),
            )

        if decision_tree is None:
            missing.append("decision_tree:NOT_AVAILABLE")
        if scaler is None and decision_tree is not None:
            missing.append("scaler:NOT_AVAILABLE")

        # Validate DT n_features vs schema when possible
        if decision_tree is not None and is_decision_tree_like(decision_tree):
            try:
                n_model = int(decision_tree.tree_.n_features)
                if n_model != N_FEATURES:
                    missing.append(
                        f"model_feature_count_mismatch:model={n_model},schema={N_FEATURES}"
                    )
                    return PredictionExplanation(
                        explanation_id=new_explanation_id(),
                        timestamp=utc_now(),
                        event_id=event_id,
                        model_id=model_id,
                        status=ExplanationStatus.DEGRADED.value,
                        method=ExplanationMethod.FEATURE_MISMATCH.value,
                        prediction_status=status,
                        confidence_percent=conf_f,
                        model_name=model_name,
                        model_available=True,
                        summary=(
                            f"Explanation DEGRADED: model n_features={n_model} "
                            f"!= schema {N_FEATURES}."
                        ),
                        narrative="FEATURE_MISMATCH: refusing silent wrong-feature mapping.",
                        missing_evidence=missing,
                        observed_facts=observed,
                        feature_names=list(FEATURE_NAMES),
                    )
            except Exception:  # noqa: BLE001
                missing.append("model_feature_count:UNKNOWN")

        path_steps = []
        leaf_decision = None
        leaf_node_id = None
        global_imps: List[FeatureAttribution] = []
        local_feats: List[FeatureAttribution] = []

        if (
            decision_tree is not None
            and scaler is not None
            and vec_ok
            and not unsupported
        ):
            try:
                import numpy as np

                X = np.asarray([vec_list], dtype=float)
                X_scaled = scaler.transform(X)[0]
                # Validate scaled length
                if len(X_scaled) != N_FEATURES:
                    missing.append(
                        f"scaled_feature_count_mismatch:got={len(X_scaled)}"
                    )
                else:
                    path_steps, leaf_decision, leaf_node_id = extract_decision_path(
                        decision_tree,
                        X_scaled,
                        FEATURE_NAMES,
                        max_steps=self.config.max_path_steps,
                    )
                    if path_steps:
                        observed.append(f"decision_path_steps={len(path_steps)}")
                        refs.append(
                            "sklearn.DecisionTreeClassifier.decision_path"
                        )
                        # Local path features (dedup preserving order)
                        seen = set()
                        for step in path_steps:
                            if step.feature in seen:
                                continue
                            seen.add(step.feature)
                            try:
                                idx = FEATURE_NAMES.index(step.feature)
                                raw_val = float(vec_list[idx])
                            except ValueError:
                                raw_val = None
                            local_feats.append(
                                FeatureAttribution(
                                    feature=step.feature,
                                    value=(
                                        None
                                        if raw_val is None
                                        else round(raw_val, 6)
                                    ),
                                    note=(
                                        "LOCAL decision-path evidence "
                                        f"({step.feature} {step.operator} "
                                        f"{step.threshold}); not global causality"
                                    ),
                                    evidence_kind=EvidenceKind.OBSERVED.value,
                                    scope=AttributionScope.LOCAL_PATH.value,
                                )
                            )
                    else:
                        missing.append("decision_path:INSUFFICIENT_EVIDENCE")

                    if leaf_decision is not None:
                        observed.append(f"leaf_decision={leaf_decision}")

                    for name, imp in top_feature_importances(
                        decision_tree,
                        FEATURE_NAMES,
                        limit=self.config.max_importance_features,
                    ):
                        try:
                            idx = FEATURE_NAMES.index(name)
                            raw_val = float(vec_list[idx]) if idx < len(vec_list) else None
                        except ValueError:
                            raw_val = None
                        global_imps.append(
                            FeatureAttribution(
                                feature=name,
                                value=None if raw_val is None else round(raw_val, 6),
                                importance=imp,
                                note=(
                                    "GLOBAL feature_importances_ "
                                    "(not per-prediction causality)"
                                ),
                                evidence_kind=EvidenceKind.OBSERVED.value,
                                scope=AttributionScope.GLOBAL_IMPORTANCE.value,
                            )
                        )
                    if global_imps:
                        refs.append(
                            "sklearn.DecisionTreeClassifier.feature_importances_"
                        )
            except Exception:  # noqa: BLE001
                missing.append("decision_path:ERROR")
                logger.debug(
                    "[XAIEngine] tree path failed:\n%s", traceback.format_exc()
                )

        # Heuristic deviations (INFERRED) — only on valid vectors
        anomalous: List[FeatureAttribution] = []
        if self.config.include_feature_deviation and vec_ok:
            anomalous = find_anomalous_features(
                vec_list, max_features=self.config.max_anomalous_features
            )
            if anomalous:
                inferred.append(
                    f"heuristic_normal_range_deviations={len(anomalous)}"
                )
                refs.append("ml_models.explainer.NORMAL_RANGES")

        attack_hint = "NOT_AVAILABLE"
        if self.config.include_attack_hint and vec_ok:
            try:
                attack_hint = str(classify_attack_type(vec_list, status=status))
                inferred.append(f"attack_type_hint={attack_hint}")
                refs.append("ml_models.attack_type_classifier.classify_attack_type")
            except Exception:  # noqa: BLE001
                attack_hint = "UNKNOWN"
                missing.append("attack_type_hint:ERROR")
        elif not vec_ok:
            missing.append("attack_type_hint:NOT_AVAILABLE")

        iso_score = _opt_float(prediction.get("iso_score"))
        dt_label_i = _opt_int(prediction.get("dt_label"))
        dt_conf = _opt_float(prediction.get("dt_confidence"))
        if iso_score is not None:
            observed.append(f"iso_score={iso_score}")
            refs.append("prediction.iso_score")
        if dt_label_i is not None:
            observed.append(f"dt_label={dt_label_i}")
            refs.append("prediction.dt_label")
        if dt_conf is not None:
            observed.append(f"dt_confidence={dt_conf}")
            refs.append("prediction.dt_confidence")

        if status != "UNKNOWN":
            observed.append(f"prediction_status={status}")
        if conf_f is not None:
            observed.append(f"confidence_percent={conf_f}")

        method = _select_method(path_steps, anomalous, model_available)
        expl_status = _explanation_status(path_steps, model_available, missing, vec_ok)
        summary = _build_summary(
            status=status,
            confidence=conf_f,
            path_steps=path_steps,
            leaf_decision=leaf_decision,
            model_available=model_available,
            missing=missing,
        )
        narrative = _build_narrative(
            status=status,
            confidence=conf_f,
            path_steps=path_steps,
            leaf_decision=leaf_decision,
            anomalous=anomalous,
            attack_hint=attack_hint,
            missing=missing,
            model_available=model_available,
            global_imps=global_imps,
            local_feats=local_feats,
        )

        return PredictionExplanation(
            explanation_id=new_explanation_id(),
            timestamp=utc_now(),
            event_id=event_id,
            model_id=model_id,
            status=expl_status,
            method=method,
            prediction_status=status,
            confidence_percent=conf_f,
            model_name=model_name if model_available else "none",
            model_available=bool(model_available),
            decision_path=path_steps,
            leaf_decision=leaf_decision,
            leaf_node_id=leaf_node_id,
            global_feature_importances=global_imps,
            local_path_features=local_feats,
            anomalous_features=anomalous,
            attack_type_hint=attack_hint,
            summary=summary,
            narrative=narrative,
            evidence_refs=refs,
            missing_evidence=missing,
            observed_facts=observed,
            inferred_statements=inferred,
            iso_score=iso_score,
            dt_label=dt_label_i,
            dt_confidence=dt_conf,
            feature_names=list(FEATURE_NAMES),
        )


def _validate_vector(
    vector: Optional[Sequence[float]],
) -> Tuple[bool, List[float], List[str]]:
    errors: List[str] = []
    if vector is None or len(vector) == 0:
        return False, [], ["feature_vector:NOT_AVAILABLE"]
    if len(vector) != N_FEATURES:
        return (
            False,
            [],
            [
                f"feature_count_mismatch:got={len(vector)},expected={N_FEATURES}"
            ],
        )
    out: List[float] = []
    for i, x in enumerate(vector):
        try:
            v = float(x)
        except (TypeError, ValueError):
            errors.append(f"feature_invalid:{FEATURE_NAMES[i]}")
            continue
        if not math.isfinite(v):
            errors.append(f"feature_nonfinite:{FEATURE_NAMES[i]}")
            continue
        out.append(v)
    if errors:
        return False, [], errors
    return True, out, []


def _opt_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(v):
        return None
    return v


def _opt_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _select_method(path_steps, anomalous, model_available: bool) -> str:
    has_path = bool(path_steps)
    has_dev = bool(anomalous)
    if has_path and has_dev:
        return ExplanationMethod.COMPOSITE.value
    if has_path:
        return ExplanationMethod.DECISION_TREE_PATH.value
    if has_dev:
        return ExplanationMethod.FEATURE_DEVIATION.value
    return ExplanationMethod.INSUFFICIENT_EVIDENCE.value


def _explanation_status(
    path_steps, model_available: bool, missing: List[str], vec_ok: bool
) -> str:
    if path_steps:
        if any("confidence:NOT_AVAILABLE" in m for m in missing):
            return ExplanationStatus.DEGRADED.value
        return ExplanationStatus.OK.value
    if vec_ok:
        return ExplanationStatus.DEGRADED.value
    if not model_available:
        return ExplanationStatus.UNAVAILABLE.value
    return ExplanationStatus.DEGRADED.value


def _build_summary(
    *,
    status: str,
    confidence: Optional[float],
    path_steps,
    leaf_decision: Optional[str],
    model_available: bool,
    missing: List[str],
) -> str:
    conf_txt = (
        f"{confidence / 100.0:.2f}"
        if confidence is not None and confidence > 1.0
        else (f"{confidence:.2f}" if confidence is not None else "NOT_AVAILABLE")
    )
    # Prefer percent→unit display: production confidence is 0–100
    if confidence is not None:
        unit = confidence / 100.0 if confidence > 1.0 else confidence
        conf_txt = f"{unit:.2f}"

    if path_steps:
        feats = []
        seen = set()
        for s in path_steps:
            if s.feature not in seen:
                seen.add(s.feature)
                feats.append(s.feature)
        feat_txt = ", ".join(feats[:5])
        exceeded = []
        for s in path_steps[:5]:
            exceeded.append(f"{s.feature} {s.operator} {s.threshold}")
        leaf = leaf_decision or "UNKNOWN"
        return (
            f"Model predicted {status} with confidence {conf_txt}. "
            f"Decision-path evidence used {feat_txt}; "
            f"leaf={leaf}. Splits: " + "; ".join(exceeded[:3]) + "."
        )

    if not model_available:
        return (
            f"Model predicted {status} with confidence {conf_txt}. "
            "Decision Tree path NOT_AVAILABLE; explanation degraded."
        )
    reason = missing[0] if missing else "decision_path unavailable"
    return (
        f"Model predicted {status} with confidence {conf_txt}. "
        f"Explanation degraded ({reason})."
    )


def _build_narrative(
    *,
    status: str,
    confidence: Optional[float],
    path_steps,
    leaf_decision: Optional[str],
    anomalous,
    attack_hint: str,
    missing: List[str],
    model_available: bool,
    global_imps,
    local_feats,
) -> str:
    lines = []
    conf_txt = f"{confidence:.1f}%" if confidence is not None else "NOT_AVAILABLE"
    lines.append(
        f"OBSERVED: prediction_status={status} confidence_percent={conf_txt}."
    )

    if model_available and path_steps:
        lines.append(
            f"OBSERVED (LOCAL decision-path evidence): path_length={len(path_steps)} "
            f"leaf_decision={leaf_decision or 'UNKNOWN'}."
        )
        for step in path_steps[:5]:
            dist = (
                f", distance={step.threshold_distance}"
                if step.threshold_distance is not None
                else ""
            )
            lines.append(
                f"  LOCAL: {step.feature} {step.operator} {step.threshold} "
                f"(scaled_value={step.feature_value}{dist}, go {step.direction})."
            )
        if len(path_steps) > 5:
            lines.append(f"  ... {len(path_steps) - 5} additional LOCAL splits.")
    elif not model_available:
        lines.append("NOT_AVAILABLE: Decision Tree model not provided for path XAI.")

    if local_feats:
        names = ", ".join(f.feature for f in local_feats)
        lines.append(f"LOCAL_PATH features: {names}.")

    if global_imps:
        lines.append(
            "GLOBAL feature_importances_ (not per-prediction causality): "
            + ", ".join(
                f"{f.feature}={f.importance}" for f in global_imps[:5]
            )
        )

    if anomalous:
        lines.append(
            f"INFERRED: {len(anomalous)} feature(s) outside heuristic NORMAL_RANGES "
            "(not live baseline; not SHAP)."
        )
        for a in anomalous[:5]:
            lines.append(f"  INFERRED: {a.feature}={a.value} [{a.deviation}]")

    if attack_hint not in ("NOT_AVAILABLE", "NORMAL", ""):
        lines.append(
            f"INFERRED: attack_type_hint={attack_hint} "
            "(heuristic classifier; not observed ground truth)."
        )

    if missing:
        lines.append("MISSING: " + "; ".join(missing[:8]))

    lines.append(
        "NOTE: This is a prediction explanation (XAI), not a root-cause report (RCA)."
    )
    return "\n".join(lines)
