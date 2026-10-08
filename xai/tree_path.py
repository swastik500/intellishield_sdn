"""
Native Decision Tree path extraction (R5.1).

Uses sklearn tree_.feature / threshold / children_* — no SHAP.
Requires the same scaled feature vector the DT was trained/predicted on.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Tuple

from xai.models import AttributionScope, DecisionPathStep, EvidenceKind


_CLASS_LABELS = {0: "NORMAL", 1: "ATTACK"}


def is_decision_tree_like(model: Any) -> bool:
    """True if object exposes sklearn DecisionTreeClassifier path APIs."""
    if model is None:
        return False
    if not hasattr(model, "decision_path"):
        return False
    if not hasattr(model, "tree_"):
        return False
    tree = getattr(model, "tree_", None)
    if tree is None:
        return False
    return all(hasattr(tree, attr) for attr in ("feature", "threshold", "children_left", "children_right", "value", "n_features"))


def extract_decision_path(
    decision_tree: Any,
    scaled_vector: Sequence[float],
    feature_names: Sequence[str],
    *,
    max_steps: int = 32,
) -> Tuple[List[DecisionPathStep], Optional[str], Optional[int]]:
    """
    Walk the DT path taken by ``scaled_vector``.

    Returns:
        (steps, leaf_decision_label, leaf_node_id)

    If the model is missing or incompatible, returns ([], None, None).
    """
    if not is_decision_tree_like(decision_tree):
        return [], None, None

    tree = decision_tree.tree_

    try:
        import numpy as np

        X = np.asarray([list(scaled_vector)], dtype=float)
        expected = int(tree.n_features)
        if X.shape[1] != expected:
            return [], None, None

        node_indicator = decision_tree.decision_path(X)
        node_index = node_indicator.indices[
            node_indicator.indptr[0] : node_indicator.indptr[1]
        ]

        feature = tree.feature
        threshold = tree.threshold
        children_left = tree.children_left
        children_right = tree.children_right
        value = tree.value

        steps: List[DecisionPathStep] = []
        leaf_id: Optional[int] = None

        for depth, node_id in enumerate(node_index):
            node_id = int(node_id)
            if children_left[node_id] == children_right[node_id]:
                leaf_id = node_id
                break
            if depth >= max_steps:
                leaf_id = node_id
                break

            feat_idx = int(feature[node_id])
            if feat_idx < 0 or feat_idx >= len(feature_names):
                break

            thr = float(threshold[node_id])
            feat_val = float(scaled_vector[feat_idx])
            if feat_val <= thr:
                operator = "<="
                direction = "left"
            else:
                operator = ">"
                direction = "right"

            steps.append(
                DecisionPathStep(
                    node_id=node_id,
                    feature=str(feature_names[feat_idx]),
                    threshold=round(thr, 6),
                    operator=operator,
                    feature_value=round(feat_val, 6),
                    direction=direction,
                    threshold_distance=round(abs(feat_val - thr), 6),
                    evidence_kind=EvidenceKind.OBSERVED.value,
                    scope=AttributionScope.LOCAL_PATH.value,
                )
            )

        leaf_decision = None
        if leaf_id is not None:
            counts = value[leaf_id][0]
            pred_idx = int(counts.argmax())
            classes = getattr(decision_tree, "classes_", None)
            if classes is not None and pred_idx < len(classes):
                raw = int(classes[pred_idx])
                leaf_decision = _CLASS_LABELS.get(raw, str(raw))
            else:
                leaf_decision = _CLASS_LABELS.get(pred_idx, str(pred_idx))

        return steps, leaf_decision, leaf_id
    except Exception:  # noqa: BLE001
        return [], None, None


def top_feature_importances(
    decision_tree: Any,
    feature_names: Sequence[str],
    *,
    limit: int = 5,
) -> List[Tuple[str, float]]:
    """Return [(name, importance), ...] from model.feature_importances_ (GLOBAL)."""
    if decision_tree is None:
        return []
    try:
        importances = getattr(decision_tree, "feature_importances_", None)
        if importances is None:
            return []
        pairs = [
            (str(feature_names[i]), round(float(importances[i]), 6))
            for i in range(min(len(feature_names), len(importances)))
        ]
        pairs.sort(key=lambda x: x[1], reverse=True)
        return pairs[: max(0, int(limit))]
    except Exception:  # noqa: BLE001
        return []
