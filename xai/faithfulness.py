"""
Model-grounded explanation faithfulness checks (R5.5).

For native Decision Tree path XAI:
  reported path / feature / threshold / branch must match sklearn's
  decision_path and reproduce the model leaf/prediction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

from xai.tree_path import extract_decision_path, is_decision_tree_like


_CLASS_LABELS = {0: "NORMAL", 1: "ATTACK"}


@dataclass(frozen=True)
class PathFaithfulnessResult:
    ok: bool
    leaf_matches_prediction: bool
    path_matches_sklearn: bool
    reported_leaf: Optional[str]
    model_prediction_label: Optional[str]
    step_count: int
    errors: tuple


def model_prediction_label(decision_tree: Any, scaled_vector: Sequence[float]) -> Optional[str]:
    if not is_decision_tree_like(decision_tree):
        return None
    try:
        import numpy as np

        pred = int(decision_tree.predict(np.asarray([list(scaled_vector)], dtype=float))[0])
        return _CLASS_LABELS.get(pred, str(pred))
    except Exception:  # noqa: BLE001
        return None


def verify_path_against_model(
    decision_tree: Any,
    scaled_vector: Sequence[float],
    feature_names: Sequence[str],
    *,
    reported_steps: Optional[list] = None,
    reported_leaf: Optional[str] = None,
    max_steps: int = 32,
) -> PathFaithfulnessResult:
    """
    Mechanically verify native path extraction against the live model.

    If reported_steps/leaf omitted, re-extract and compare to sklearn node path.
    """
    errors: List[str] = []
    if not is_decision_tree_like(decision_tree):
        return PathFaithfulnessResult(
            False, False, False, None, None, 0, ("unsupported_model",)
        )

    steps, leaf, _leaf_id = extract_decision_path(
        decision_tree, scaled_vector, feature_names, max_steps=max_steps
    )
    if reported_steps is None:
        reported_steps = steps
    if reported_leaf is None:
        reported_leaf = leaf

    # Reconstruct sklearn node index path
    try:
        import numpy as np

        X = np.asarray([list(scaled_vector)], dtype=float)
        node_indicator = decision_tree.decision_path(X)
        node_index = list(
            node_indicator.indices[
                node_indicator.indptr[0] : node_indicator.indptr[1]
            ]
        )
        tree = decision_tree.tree_
        feature = tree.feature
        threshold = tree.threshold
        children_left = tree.children_left
        children_right = tree.children_right

        # Expected split steps = all non-leaf nodes on path
        expected = []
        for node_id in node_index:
            node_id = int(node_id)
            if children_left[node_id] == children_right[node_id]:
                break
            feat_idx = int(feature[node_id])
            thr = float(threshold[node_id])
            feat_val = float(scaled_vector[feat_idx])
            direction = "left" if feat_val <= thr else "right"
            operator = "<=" if direction == "left" else ">"
            expected.append(
                {
                    "node_id": node_id,
                    "feature": str(feature_names[feat_idx]),
                    "threshold": round(thr, 6),
                    "operator": operator,
                    "direction": direction,
                }
            )

        path_ok = True
        if len(reported_steps) != len(expected):
            path_ok = False
            errors.append(
                f"step_count_mismatch:reported={len(reported_steps)},expected={len(expected)}"
            )
        else:
            for i, (rep, exp) in enumerate(zip(reported_steps, expected)):
                r_feat = getattr(rep, "feature", None) if not isinstance(rep, dict) else rep.get("feature")
                r_thr = getattr(rep, "threshold", None) if not isinstance(rep, dict) else rep.get("threshold")
                r_op = getattr(rep, "operator", None) if not isinstance(rep, dict) else rep.get("operator")
                r_dir = getattr(rep, "direction", None) if not isinstance(rep, dict) else rep.get("direction")
                r_node = getattr(rep, "node_id", None) if not isinstance(rep, dict) else rep.get("node_id")
                if int(r_node) != int(exp["node_id"]):
                    path_ok = False
                    errors.append(f"step[{i}].node_id")
                if str(r_feat) != exp["feature"]:
                    path_ok = False
                    errors.append(f"step[{i}].feature")
                if abs(float(r_thr) - float(exp["threshold"])) > 1e-9:
                    path_ok = False
                    errors.append(f"step[{i}].threshold")
                if str(r_op) != exp["operator"]:
                    path_ok = False
                    errors.append(f"step[{i}].operator")
                if str(r_dir) != exp["direction"]:
                    path_ok = False
                    errors.append(f"step[{i}].direction")
    except Exception as exc:  # noqa: BLE001
        path_ok = False
        errors.append(f"sklearn_compare_error:{type(exc).__name__}")

    pred_label = model_prediction_label(decision_tree, scaled_vector)
    leaf_ok = (
        reported_leaf is not None
        and pred_label is not None
        and str(reported_leaf) == str(pred_label)
    )
    if not leaf_ok:
        errors.append(
            f"leaf_mismatch:reported={reported_leaf},predict={pred_label}"
        )

    ok = bool(path_ok and leaf_ok)
    return PathFaithfulnessResult(
        ok=ok,
        leaf_matches_prediction=bool(leaf_ok),
        path_matches_sklearn=bool(path_ok),
        reported_leaf=reported_leaf,
        model_prediction_label=pred_label,
        step_count=len(reported_steps or []),
        errors=tuple(errors),
    )


def faithfulness_rate(
    decision_tree: Any,
    scaled_vectors: Sequence[Sequence[float]],
    feature_names: Sequence[str],
) -> dict:
    """Return measurable correctness rate over a deterministic set."""
    total = len(scaled_vectors)
    if total == 0:
        return {"total": 0, "correct": 0, "rate": 0.0, "failures": []}
    correct = 0
    failures = []
    for i, vec in enumerate(scaled_vectors):
        result = verify_path_against_model(decision_tree, vec, feature_names)
        if result.ok:
            correct += 1
        else:
            failures.append({"index": i, "errors": list(result.errors)})
    return {
        "total": total,
        "correct": correct,
        "rate": round(correct / total, 6),
        "failures": failures[:20],
    }
