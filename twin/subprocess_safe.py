"""Safe subprocess boundary for twin experiments (no shell injection)."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence


ALLOWED_PYTHON_MODULES = frozenset(
    {
        "traffic_generator.traffic_scheduler",
        "scripts.compute_metrics",
        "scripts.bundle_experiment",
        "ml_models.model_trainer",
    }
)


@dataclass(frozen=True)
class SubprocessResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_python_module(
    module: str,
    args: Sequence[str] = (),
    *,
    cwd: Optional[Path] = None,
    timeout_sec: float = 120.0,
    env: Optional[dict] = None,
) -> SubprocessResult:
    """
    Run ``python -m <module> ...`` with shell=False and an allow-list.

    Raises ValueError for unknown modules. Captures stdout/stderr.
    """
    if module not in ALLOWED_PYTHON_MODULES:
        raise ValueError(
            f"module {module!r} not in twin allow-list; "
            f"allowed={sorted(ALLOWED_PYTHON_MODULES)}"
        )
    # Validate args are strings (no nested lists / injection)
    argv_tail = [str(a) for a in args]
    for a in argv_tail:
        if "\x00" in a:
            raise ValueError("NUL byte in argument rejected")

    argv = [sys.executable, "-m", module, *argv_tail]
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            shell=False,
            env=env,
            check=False,
        )
        return SubprocessResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return SubprocessResult(
            argv=argv,
            returncode=-1,
            stdout=out or "",
            stderr=(err or "") + f"\n[twin] timeout after {timeout_sec}s",
            timed_out=True,
        )
