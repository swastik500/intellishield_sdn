"""Production vs candidate artifact isolation (R3.3)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Sequence, Union

from shared_contracts.models import ModelCandidate, ModelVersion
from twin.validate import TwinValidationError

# Canonical production model locations — candidates must NEVER write here.
PRODUCTION_MODEL_RELPATHS: tuple[str, ...] = (
    "logs/models/isolation_forest.pkl",
    "logs/models/decision_tree.pkl",
    "logs/models/scaler.pkl",
)

PathLike = Union[str, Path]


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def production_model_paths(*, root: PathLike | None = None) -> list[Path]:
    base = Path(root) if root else project_root()
    return [base / rel for rel in PRODUCTION_MODEL_RELPATHS]


def resolve_path(path: PathLike, *, root: PathLike | None = None) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = (Path(root) if root else project_root()) / p
    return p.resolve()


def is_production_model_path(path: PathLike, *, root: PathLike | None = None) -> bool:
    target = resolve_path(path, root=root)
    for prod in production_model_paths(root=root):
        try:
            if target == prod.resolve():
                return True
        except OSError:
            if os.path.normpath(str(target)) == os.path.normpath(str(prod)):
                return True
    return False


def assert_not_production_path(path: PathLike, *, root: PathLike | None = None) -> Path:
    """Raise if *path* points at a production model artifact."""
    resolved = resolve_path(path, root=root)
    if is_production_model_path(resolved, root=root):
        raise TwinValidationError(
            f"refusing to use/overwrite production model path: {resolved}"
        )
    return resolved


def assert_candidate_isolated(
    candidate: ModelCandidate,
    *,
    root: PathLike | None = None,
    allow_missing_artifact: bool = True,
) -> Path:
    """
    Ensure candidate artifact_uri is set and is not a production model path.

    Does not copy or install into logs/models/.
    """
    uri = (candidate.model.artifact_uri or "").strip()
    if not uri:
        raise TwinValidationError(
            "ModelCandidate.model.artifact_uri required for twin isolation"
        )
    path = assert_not_production_path(uri, root=root)
    if not allow_missing_artifact and not path.is_file():
        raise TwinValidationError(f"candidate artifact missing: {path}")
    # Parent must not be production models dir
    prod_dir = (Path(root) if root else project_root()) / "logs" / "models"
    try:
        if path.parent.resolve() == prod_dir.resolve():
            raise TwinValidationError(
                "candidate artifact must not live in logs/models/ "
                "(use twin artifact directory)"
            )
    except TwinValidationError:
        raise
    except OSError:
        pass
    return path


def assert_baseline_isolated(
    baseline: ModelVersion | None,
    *,
    root: PathLike | None = None,
) -> None:
    """Baseline may reference production paths (read-only); must not be written."""
    if baseline is None:
        return
    # Read-only OK — no write assertion. Document only.
    _ = baseline.artifact_uri


def twin_candidate_dir(
    candidate_id: str,
    *,
    root: PathLike | None = None,
) -> Path:
    """Dedicated twin artifact directory for a candidate (created on demand)."""
    base = Path(root) if root else project_root()
    out = base / "logs" / "twin" / "candidates" / candidate_id
    out.mkdir(parents=True, exist_ok=True)
    # Never equal to logs/models
    assert out.resolve() != (base / "logs" / "models").resolve()
    return out


def ensure_paths_not_written(
    written_paths: Iterable[PathLike],
    *,
    root: PathLike | None = None,
) -> None:
    """Post-condition: no production model path was written."""
    for p in written_paths:
        if is_production_model_path(p, root=root):
            raise TwinValidationError(
                f"production model path was modified during twin run: {p}"
            )
