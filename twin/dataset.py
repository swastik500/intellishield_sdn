"""
Twin training-dataset generation (R3.4).

Labels derive ONLY from scenario-control attack windows (ATTACK_START/STOP).
Never from ML / R6 / R7 / mitigation predictions.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union
from uuid import uuid4

from evaluation.experiment_windows import (
    MONITOR_INTERVAL_DEFAULT,
    AttackWindow,
    load_experiment_windows,
    parse_ts,
)
from ml_models.feature_builder import FEATURE_NAMES
from shared_contracts.enums import TwinRunPurpose
from shared_contracts.timeutil import format_ts, utc_now
from twin.bounds import assert_dataset_sample_bound
from twin.feature_schema import (
    FEATURE_SCHEMA_VERSION,
    assert_compatible_feature_names,
    assert_compatible_feature_vector,
    canonical_feature_schema,
    feature_schema_hash,
)
from twin.isolation import project_root
from twin.leakage import assert_no_leakage
from twin.validate import TwinValidationError

PathLike = Union[str, Path]

# Forbidden columns that would indicate model-derived labels
_FORBIDDEN_LABEL_SOURCES = frozenset(
    {
        "ml_prediction",
        "ml_status",
        "prediction",
        "fused_decision",
        "r6_decision",
        "verification_status",
        "mitigation_action",
        "heuristic_label",
    }
)

SplitName = str  # TRAINING | VALIDATION | TEST


@dataclass(frozen=True)
class DatasetSample:
    timestamp: str
    switch_id: str
    label: int  # 0 NORMAL, 1 ATTACK
    split: SplitName
    scenario_id: str
    run_id: str
    features: List[float]


@dataclass
class DatasetBuildResult:
    dataset_id: str
    output_dir: Path
    samples_csv: Path
    manifest_path: Path
    sample_count: int
    class_distribution: Dict[str, int]
    manifest: Dict[str, Any] = field(default_factory=dict)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def label_from_windows(
    timestamp_str: str,
    windows: Sequence[AttackWindow],
    *,
    pad_sec: float = MONITOR_INTERVAL_DEFAULT,
) -> int:
    """
    Ground-truth label from scenario attack windows only.

    Returns 1 if inside any ATTACK window, else 0.
    """
    ts = parse_ts(timestamp_str)
    if ts is None:
        raise TwinValidationError(f"unparseable timestamp for labeling: {timestamp_str!r}")
    for w in windows:
        if w.contains(ts, pad_sec=pad_sec):
            return 1
    return 0


def default_split_for_scenario(
    scenario_id: str,
    *,
    purpose: Optional[TwinRunPurpose] = None,
    split_map: Optional[Mapping[str, str]] = None,
) -> SplitName:
    """
    Assign split at scenario/run provenance level (not random adjacent rows).

    Explicit split_map wins. Else purpose mapping. Else S1→TRAINING,
    S2/S3→VALIDATION, S4/S5→TEST (deterministic, leakage-aware).
    """
    if split_map and scenario_id in split_map:
        return _normalize_split(split_map[scenario_id])
    if purpose == TwinRunPurpose.TRAINING:
        return "TRAINING"
    if purpose == TwinRunPurpose.VALIDATION:
        return "VALIDATION"
    if purpose == TwinRunPurpose.TEST:
        return "TEST"
    # Deterministic scenario-level default (no row shuffle)
    sid = scenario_id.upper()
    if sid in ("S1",):
        return "TRAINING"
    if sid in ("S2", "S3"):
        return "VALIDATION"
    return "TEST"


def _normalize_split(value: str) -> SplitName:
    key = str(value).strip().upper()
    aliases = {
        "TRAIN": "TRAINING",
        "TRAINING": "TRAINING",
        "VAL": "VALIDATION",
        "VALID": "VALIDATION",
        "VALIDATION": "VALIDATION",
        "TEST": "TEST",
        "HOLDHOUT": "TEST",
    }
    if key not in aliases:
        raise TwinValidationError(f"unsupported split assignment: {value!r}")
    return aliases[key]


def _read_feature_rows(features_csv: Path) -> List[Dict[str, str]]:
    if not features_csv.is_file():
        raise TwinValidationError(f"features CSV not found: {features_csv}")
    with features_csv.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise TwinValidationError("features CSV has no header")
        fields = [f for f in reader.fieldnames if f]
        # Reject model-derived label columns
        lower = {f.lower() for f in fields}
        bad = lower & {b.lower() for b in _FORBIDDEN_LABEL_SOURCES}
        if bad:
            raise TwinValidationError(
                f"refusing model-derived label columns in features CSV: {sorted(bad)}"
            )
        # Schema: require FEATURE_NAMES present
        missing = [n for n in FEATURE_NAMES if n not in fields]
        if missing:
            raise TwinValidationError(
                f"feature schema mismatch: missing columns {missing}"
            )
        assert_compatible_feature_names(FEATURE_NAMES)
        rows = list(reader)
    return rows


class TwinDatasetGenerator:
    """
    Build provenance-rich labeled datasets from twin/logs feature rows.

    Does not train models. Does not oversample.
    """

    def __init__(self, *, root: Optional[PathLike] = None) -> None:
        self.root = Path(root) if root else project_root()

    def generate(
        self,
        *,
        run_id: str,
        profile_id: str,
        profile_fingerprint: str,
        scenario_id: str,
        scenario_version: str = "1.0.0",
        seed: int = 42,
        features_csv: Optional[PathLike] = None,
        logs_dir: Optional[PathLike] = None,
        windows: Optional[Sequence[AttackWindow]] = None,
        split: Optional[str] = None,
        purpose: Optional[TwinRunPurpose] = None,
        split_map: Optional[Mapping[str, str]] = None,
        dataset_id: Optional[str] = None,
        output_root: Optional[PathLike] = None,
        pad_sec: float = MONITOR_INTERVAL_DEFAULT,
    ) -> DatasetBuildResult:
        if not run_id or not str(run_id).strip():
            raise TwinValidationError("run_id required")
        if not profile_id or not profile_fingerprint:
            raise TwinValidationError("profile_id and profile_fingerprint required")

        logs_dir_p = Path(logs_dir) if logs_dir else self.root / "logs"
        features_path = (
            Path(features_csv)
            if features_csv
            else logs_dir_p / "ml_features.csv"
        )

        attack_windows: List[AttackWindow]
        if windows is not None:
            attack_windows = list(windows)
        else:
            attack_windows = load_experiment_windows(str(logs_dir_p))

        rows = _read_feature_rows(features_path)
        assigned_split = (
            _normalize_split(split)
            if split
            else default_split_for_scenario(
                scenario_id, purpose=purpose, split_map=split_map
            )
        )

        samples: List[DatasetSample] = []
        for row in rows:
            # Ignore any 'label' column from CSV — recompute from windows only
            ts = row.get("timestamp", "")
            switch_id = str(row.get("switch_id", ""))
            vec = [row[name] for name in FEATURE_NAMES]
            features = assert_compatible_feature_vector(vec)
            label = label_from_windows(ts, attack_windows, pad_sec=pad_sec)
            samples.append(
                DatasetSample(
                    timestamp=ts,
                    switch_id=switch_id,
                    label=label,
                    split=assigned_split,
                    scenario_id=scenario_id,
                    run_id=run_id,
                    features=features,
                )
            )
        assert_dataset_sample_bound(len(samples))

        ds_id = dataset_id or f"twin-ds-{uuid4().hex[:12]}"
        out_root = Path(output_root) if output_root else self.root / "logs" / "twin" / "datasets"
        out_dir = out_root / ds_id
        out_dir.mkdir(parents=True, exist_ok=True)

        samples_csv = out_dir / "samples.csv"
        self._write_samples_csv(samples_csv, samples)

        class_dist = Counter("ATTACK" if s.label == 1 else "NORMAL" for s in samples)
        split_dist = Counter(s.split for s in samples)

        schema = canonical_feature_schema()
        manifest = {
            "schema": "intellishield.twin.dataset_manifest.v1",
            "dataset_id": ds_id,
            "created_at": format_ts(utc_now()),
            "feature_schema_version": schema["feature_schema_version"],
            "feature_schema_hash": schema["feature_schema_hash"],
            "feature_dim": schema["feature_dim"],
            "feature_names": schema["feature_names"],
            "label_source": "SCENARIO_CONTROL",
            "label_rule": "ATTACK_START/STOP windows via experiment_windows",
            "forbidden_label_sources": sorted(_FORBIDDEN_LABEL_SOURCES),
            "profile_id": profile_id,
            "profile_fingerprint": profile_fingerprint,
            "scenario_list": [scenario_id],
            "scenario_versions": {scenario_id: scenario_version},
            "run_ids": [run_id],
            "seeds": [seed],
            "split_policy": {
                "type": "scenario_run_provenance",
                "assignment": {scenario_id: assigned_split},
                "notes": (
                    "Splits assigned at scenario/run level; "
                    "no random row shuffle of temporally adjacent samples"
                ),
            },
            "split_distribution": dict(split_dist),
            "class_distribution": {
                "NORMAL": int(class_dist.get("NORMAL", 0)),
                "ATTACK": int(class_dist.get("ATTACK", 0)),
                "total": len(samples),
            },
            "sample_count": len(samples),
            "oversampling": False,
            "checksums": {
                "samples.csv": _sha256_file(samples_csv),
            },
            "source_experiment": {
                "run_id": run_id,
                "features_csv": str(features_path),
                "logs_dir": str(logs_dir_p),
            },
        }
        manifest_path = out_dir / "dataset_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        # Update checksum to include manifest self-hash of samples only (already set)

        return DatasetBuildResult(
            dataset_id=ds_id,
            output_dir=out_dir,
            samples_csv=samples_csv,
            manifest_path=manifest_path,
            sample_count=len(samples),
            class_distribution=manifest["class_distribution"],
            manifest=manifest,
        )

    def generate_from_runs(
        self,
        run_specs: Sequence[Mapping[str, Any]],
        *,
        dataset_id: Optional[str] = None,
        output_root: Optional[PathLike] = None,
        logs_dir: Optional[PathLike] = None,
        features_csv: Optional[PathLike] = None,
        windows: Optional[Sequence[AttackWindow]] = None,
        split_map: Optional[Mapping[str, str]] = None,
        pad_sec: float = MONITOR_INTERVAL_DEFAULT,
    ) -> DatasetBuildResult:
        """
        Merge multiple twin runs into one dataset.

        Each run_spec requires: run_id, profile_id, profile_fingerprint,
        scenario_id, seed. Optional: scenario_version, purpose, split.
        """
        if not run_specs:
            raise TwinValidationError("run_specs must be non-empty")

        logs_dir_p = Path(logs_dir) if logs_dir else self.root / "logs"
        features_path = (
            Path(features_csv) if features_csv else logs_dir_p / "ml_features.csv"
        )
        attack_windows = (
            list(windows)
            if windows is not None
            else load_experiment_windows(str(logs_dir_p))
        )
        rows = _read_feature_rows(features_path)

        samples: List[DatasetSample] = []
        scenario_versions: Dict[str, str] = {}
        run_ids: List[str] = []
        seeds: List[int] = []
        fingerprints: List[str] = []
        split_assignment: Dict[str, str] = {}

        # For multi-run: assign each sample once using first matching run's
        # scenario — typically one features CSV per experiment; labels from
        # shared windows; split from that run's scenario_id.
        # When multiple runs share one CSV (lab reuse), duplicate samples per
        # run with provenance — bounded by number of runs.
        for spec in run_specs:
            run_id = str(spec["run_id"])
            scenario_id = str(spec["scenario_id"])
            profile_id = str(spec["profile_id"])
            fingerprint = str(spec["profile_fingerprint"])
            seed = int(spec.get("seed", 0))
            scenario_version = str(spec.get("scenario_version", "1.0.0"))
            purpose = spec.get("purpose")
            if isinstance(purpose, str):
                try:
                    purpose = TwinRunPurpose(purpose)
                except ValueError:
                    purpose = None

            assigned = (
                _normalize_split(str(spec["split"]))
                if spec.get("split")
                else default_split_for_scenario(
                    scenario_id, purpose=purpose, split_map=split_map
                )
            )
            split_assignment[f"{run_id}:{scenario_id}"] = assigned
            scenario_versions[scenario_id] = scenario_version
            run_ids.append(run_id)
            seeds.append(seed)
            fingerprints.append(fingerprint)
            _ = profile_id  # retained in manifest source list

            for row in rows:
                ts = row.get("timestamp", "")
                switch_id = str(row.get("switch_id", ""))
                features = assert_compatible_feature_vector(
                    [row[name] for name in FEATURE_NAMES]
                )
                label = label_from_windows(ts, attack_windows, pad_sec=pad_sec)
                samples.append(
                    DatasetSample(
                        timestamp=ts,
                        switch_id=switch_id,
                        label=label,
                        split=assigned,
                        scenario_id=scenario_id,
                        run_id=run_id,
                        features=features,
                    )
                )

        assert_dataset_sample_bound(len(samples))

        ds_id = dataset_id or f"twin-ds-{uuid4().hex[:12]}"
        out_root = Path(output_root) if output_root else self.root / "logs" / "twin" / "datasets"
        out_dir = out_root / ds_id
        out_dir.mkdir(parents=True, exist_ok=True)
        samples_csv = out_dir / "samples.csv"
        self._write_samples_csv(samples_csv, samples)
        # Multi-run exports may span splits — fail closed on leakage
        if len({s.split for s in samples}) > 1:
            assert_no_leakage(samples_csv)

        class_dist = Counter("ATTACK" if s.label == 1 else "NORMAL" for s in samples)
        split_dist = Counter(s.split for s in samples)
        schema = canonical_feature_schema()
        first = run_specs[0]
        manifest = {
            "schema": "intellishield.twin.dataset_manifest.v1",
            "dataset_id": ds_id,
            "created_at": format_ts(utc_now()),
            "feature_schema_version": schema["feature_schema_version"],
            "feature_schema_hash": schema["feature_schema_hash"],
            "feature_dim": schema["feature_dim"],
            "feature_names": schema["feature_names"],
            "label_source": "SCENARIO_CONTROL",
            "label_rule": "ATTACK_START/STOP windows via experiment_windows",
            "forbidden_label_sources": sorted(_FORBIDDEN_LABEL_SOURCES),
            "profile_id": str(first["profile_id"]),
            "profile_fingerprints": sorted(set(fingerprints)),
            "scenario_list": sorted({str(s["scenario_id"]) for s in run_specs}),
            "scenario_versions": scenario_versions,
            "run_ids": run_ids,
            "seeds": seeds,
            "split_policy": {
                "type": "scenario_run_provenance",
                "assignment": split_assignment,
                "notes": (
                    "Splits assigned at scenario/run level; "
                    "no random row shuffle of temporally adjacent samples"
                ),
            },
            "split_distribution": dict(split_dist),
            "class_distribution": {
                "NORMAL": int(class_dist.get("NORMAL", 0)),
                "ATTACK": int(class_dist.get("ATTACK", 0)),
                "total": len(samples),
            },
            "sample_count": len(samples),
            "oversampling": False,
            "checksums": {"samples.csv": _sha256_file(samples_csv)},
            "source_experiment": {
                "features_csv": str(features_path),
                "logs_dir": str(logs_dir_p),
                "run_specs": [dict(s) for s in run_specs],
            },
        }
        manifest_path = out_dir / "dataset_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return DatasetBuildResult(
            dataset_id=ds_id,
            output_dir=out_dir,
            samples_csv=samples_csv,
            manifest_path=manifest_path,
            sample_count=len(samples),
            class_distribution=manifest["class_distribution"],
            manifest=manifest,
        )

    def _write_samples_csv(self, path: Path, samples: Sequence[DatasetSample]) -> None:
        headers = [
            "timestamp",
            "switch_id",
            "label",
            "label_name",
            "split",
            "scenario_id",
            "run_id",
        ] + list(FEATURE_NAMES)
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for s in samples:
                writer.writerow(
                    [
                        s.timestamp,
                        s.switch_id,
                        s.label,
                        "ATTACK" if s.label == 1 else "NORMAL",
                        s.split,
                        s.scenario_id,
                        s.run_id,
                        *s.features,
                    ]
                )
