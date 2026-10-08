"""Resource bounds for twin orchestration (R3.5)."""

from __future__ import annotations

from twin.scenario_spec import MAX_VARIANTS_HARD
from twin.validate import TwinValidationError

# Hard caps — prevent unbounded artifact / run growth
MAX_SCENARIO_MATRIX_ROWS = 32
MAX_TWIN_HISTORY_READ = 100
MAX_DATASET_EXPORT_SAMPLES = 100_000
MAX_CONCURRENT_TWIN_RUNS = 1  # lab safety: no parallel Mininet twin spawns from API
MAX_ARTIFACT_INDEX_DIRS = 200
MAX_SNAPSHOT_CSV_ROWS = 5_000
MAX_SNAPSHOT_JSONL_LINES = 2_000


def assert_variant_count(count: int) -> None:
    if count < 1 or count > MAX_VARIANTS_HARD:
        raise TwinValidationError(
            f"variant count {count} outside [1, {MAX_VARIANTS_HARD}]"
        )


def assert_matrix_rows(count: int) -> None:
    if count < 1 or count > MAX_SCENARIO_MATRIX_ROWS:
        raise TwinValidationError(
            f"scenario matrix rows {count} outside [1, {MAX_SCENARIO_MATRIX_ROWS}]"
        )


def assert_history_limit(limit: int) -> int:
    if limit < 0:
        raise TwinValidationError("history limit must be >= 0")
    return min(int(limit), MAX_TWIN_HISTORY_READ)


def assert_dataset_sample_bound(count: int) -> None:
    if count > MAX_DATASET_EXPORT_SAMPLES:
        raise TwinValidationError(
            f"dataset sample count {count} exceeds bound {MAX_DATASET_EXPORT_SAMPLES}"
        )
