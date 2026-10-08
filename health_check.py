#!/usr/bin/env python3
"""
IntelliShield SDN — Release 1.0 health check

Usage:
  python3 health_check.py
  python3 health_check.py --strict   # treat optional SDN binaries as FAIL on Mac-ish hosts

Exit codes:
  0 = all required checks PASS
  1 = one or more required checks FAIL
"""

from __future__ import annotations

import argparse
import importlib
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent
MIN_PY = (3, 10)

REQUIRED_PACKAGES = [
    "numpy",
    "sklearn",
    "pandas",
    "scipy",
    "joblib",
    "fastapi",
    "uvicorn",
    "pydantic",
]

REQUIRED_FOLDERS = [
    "controller",
    "entropy_engine",
    "ml_models",
    "mitigation",
    "rl_engine",
    "dashboard",
    "traffic_generator",
    "shared_contracts",
    "correlation",
    "fusion",
    "verification",
    "alerting",
    "rca",
    "xai",
    "tests",
    "logs",
]

OPTIONAL_FOLDERS = ["twin", "evaluation", "scripts", "advanced_analytics"]

LOG_SUBDIRS = ["logs/twin", "logs/archive", "logs/experiments", "logs/models"]

ENV_VARS_DOCUMENTED = [
    "INTELLISHIELD_OPS_PROFILE",
    "INTELLISHIELD_R6_FUSION",
    "INTELLISHIELD_SUDO_PASS",
    "INTELLISHIELD_AUTO_TRAIN_SYNTHETIC",
    "PYTHONPATH",
]

CONTROLLER_IMPORTS = [
    "shared_contracts",
    "shared_contracts.ops_profile",
    "correlation",
    "fusion",
    "verification",
    "alerting",
    "rca",
    "xai",
    "entropy_engine",
    "ml_models",
    "mitigation",
    "rl_engine",
]

DASHBOARD_IMPORTS = ["fastapi", "uvicorn", "pydantic"]


def _ok(msg: str) -> Tuple[str, str]:
    return ("PASS", msg)


def _fail(msg: str) -> Tuple[str, str]:
    return ("FAIL", msg)


def _warn(msg: str) -> Tuple[str, str]:
    return ("WARN", msg)


def check_python() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    ver = sys.version_info[:3]
    if ver >= MIN_PY:
        out.append(_ok(f"Python {ver[0]}.{ver[1]}.{ver[2]} (>= {MIN_PY[0]}.{MIN_PY[1]})"))
    else:
        out.append(_fail(f"Python {ver[0]}.{ver[1]}.{ver[2]} — need >= {MIN_PY[0]}.{MIN_PY[1]}"))
    return out


def check_packages() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for name in REQUIRED_PACKAGES:
        try:
            mod = importlib.import_module(name)
            ver = getattr(mod, "__version__", "?")
            out.append(_ok(f"package {name} ({ver})"))
        except Exception as exc:
            out.append(_fail(f"package {name}: {exc}"))
    # optional
    for name in ("httpx", "pytest", "psutil"):
        try:
            importlib.import_module(name)
            out.append(_ok(f"optional package {name}"))
        except Exception:
            out.append(_warn(f"optional package {name} missing (needed for tests/dashboard TestClient)"))
    return out


def check_folders() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for rel in REQUIRED_FOLDERS:
        p = ROOT / rel
        if p.is_dir():
            out.append(_ok(f"folder {rel}/"))
        else:
            out.append(_fail(f"folder missing: {rel}/ — Release 1.0 incomplete (git pull may not have R1.0 packages)"))
    for rel in OPTIONAL_FOLDERS:
        p = ROOT / rel
        if p.is_dir():
            out.append(_ok(f"optional folder {rel}/"))
        else:
            out.append(_warn(f"optional folder missing: {rel}/"))
    for rel in LOG_SUBDIRS:
        p = ROOT / rel
        if p.is_dir():
            out.append(_ok(f"log dir {rel}/"))
        else:
            out.append(_warn(f"log dir missing (will be created by update scripts): {rel}/"))
    return out


def check_env() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    # Ensure ROOT on path for later imports
    root_s = str(ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)

    pp = os.environ.get("PYTHONPATH", "")
    if root_s in pp.split(os.pathsep) or not pp:
        if root_s in pp.split(os.pathsep):
            out.append(_ok("PYTHONPATH includes repo root"))
        else:
            out.append(_warn("PYTHONPATH unset — set to repo root before osken-manager"))
    else:
        out.append(_warn(f"PYTHONPATH does not include repo root: {pp!r}"))

    profile = os.environ.get("INTELLISHIELD_OPS_PROFILE", "production")
    out.append(_ok(f"INTELLISHIELD_OPS_PROFILE={profile!r} (default production if unset)"))

    fusion = os.environ.get("INTELLISHIELD_R6_FUSION", "1")
    out.append(_ok(f"INTELLISHIELD_R6_FUSION={fusion!r} (default 1)"))

    if os.environ.get("INTELLISHIELD_SUDO_PASS"):
        out.append(_warn("INTELLISHIELD_SUDO_PASS is set (lab only — prefer sudoers)"))
    else:
        out.append(_ok("INTELLISHIELD_SUDO_PASS unset (OK if sudoers configured)"))

    auto = os.environ.get("INTELLISHIELD_AUTO_TRAIN_SYNTHETIC", "0")
    out.append(_ok(f"INTELLISHIELD_AUTO_TRAIN_SYNTHETIC={auto!r}"))

    env_file = ROOT / ".env"
    example = ROOT / ".env.example"
    if example.is_file():
        out.append(_ok(".env.example present"))
    else:
        out.append(_warn(".env.example missing"))
    if env_file.is_file():
        out.append(_ok(".env present (not overwritten by health check)"))
    else:
        out.append(_warn(".env missing — copy from .env.example for lab defaults"))
    return out


def check_imports() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    root_s = str(ROOT)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)
    for name in CONTROLLER_IMPORTS:
        try:
            importlib.import_module(name)
            out.append(_ok(f"import {name}"))
        except Exception as exc:
            out.append(_fail(f"import {name}: {exc}"))
    for name in DASHBOARD_IMPORTS:
        try:
            importlib.import_module(name)
            out.append(_ok(f"dashboard dep {name}"))
        except Exception as exc:
            out.append(_fail(f"dashboard dep {name}: {exc}"))
    # Dashboard module import (does not bind port)
    try:
        # Avoid side effects: only compile-check path exists
        api = ROOT / "dashboard" / "api.py"
        if api.is_file():
            out.append(_ok("dashboard/api.py present"))
        else:
            out.append(_fail("dashboard/api.py missing"))
    except Exception as exc:
        out.append(_fail(f"dashboard check: {exc}"))
    return out


def check_binaries(strict: bool) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    system = platform.system().lower()
    bins = {
        "osken-manager": "OsKen controller (Ubuntu: python3-os-ken)",
        "mn": "Mininet CLI",
        "ovs-vsctl": "Open vSwitch",
    }
    for name, desc in bins.items():
        path = shutil.which(name)
        if path:
            out.append(_ok(f"binary {name} → {path}"))
        else:
            msg = f"binary {name} not found ({desc})"
            if strict or system == "linux":
                # On Linux lab VM these are required for live SDN; on Mac WARN
                if system == "linux":
                    out.append(_fail(msg + " — required for live Mininet lab"))
                else:
                    out.append(_warn(msg + " — expected on Ubuntu lab VM only"))
            else:
                out.append(_warn(msg))
    return out


def check_tests() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    tests = list((ROOT / "tests").glob("test_*.py")) if (ROOT / "tests").is_dir() else []
    out.append(_ok(f"discovered {len(tests)} test_*.py modules") if tests else _fail("no tests found"))
    r1 = [
        "test_shared_contracts_foundation.py",
        "test_ops_confidence_calibration.py",
        "test_fusion_engine_r62.py",
        "test_verification_engine_r71.py",
        "test_alerting_core_r81.py",
    ]
    for name in r1:
        p = ROOT / "tests" / name
        if p.is_file():
            out.append(_ok(f"Release 1.0 test present: {name}"))
        else:
            out.append(_fail(f"Release 1.0 test missing: {name}"))
    return out


def check_config() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    req = ROOT / "requirements.txt"
    if req.is_file():
        out.append(_ok("requirements.txt present"))
    else:
        out.append(_fail("requirements.txt missing"))
    dash_req = ROOT / "dashboard" / "requirements.txt"
    if dash_req.is_file():
        out.append(_ok("dashboard/requirements.txt present"))
    else:
        out.append(_warn("dashboard/requirements.txt missing"))
    # No Redis/Postgres expected
    out.append(_ok("Redis/PostgreSQL not required (file/JSONL storage)"))
    return out


def check_api_availability() -> List[Tuple[str, str]]:
    """Best-effort local dashboard probe (non-fatal WARN if down)."""
    out: List[Tuple[str, str]] = []
    try:
        import urllib.request

        with urllib.request.urlopen("http://127.0.0.1:8080/api/status", timeout=1.5) as resp:
            code = getattr(resp, "status", 200)
            if code == 200:
                out.append(_ok("dashboard API responding on :8080/api/status"))
            else:
                out.append(_warn(f"dashboard API status code {code}"))
    except Exception:
        out.append(_warn("dashboard API not reachable on :8080 (start with python3 dashboard/api.py)"))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="IntelliShield Release 1.0 health check")
    parser.add_argument("--strict", action="store_true", help="Stricter binary checks")
    args = parser.parse_args()

    print("=" * 64)
    print("IntelliShield SDN — Release 1.0 Health Check")
    print(f"Root: {ROOT}")
    print(f"Platform: {platform.system()} {platform.machine()}")
    print("=" * 64)

    sections = [
        ("Python", check_python()),
        ("Packages", check_packages()),
        ("Folders", check_folders()),
        ("Environment", check_env()),
        ("Imports", check_imports()),
        ("Binaries", check_binaries(args.strict)),
        ("Tests", check_tests()),
        ("Configuration", check_config()),
        ("API", check_api_availability()),
    ]

    fails = 0
    warns = 0
    passes = 0
    for title, rows in sections:
        print(f"\n## {title}")
        for status, msg in rows:
            print(f"  [{status}] {msg}")
            if status == "FAIL":
                fails += 1
            elif status == "WARN":
                warns += 1
            else:
                passes += 1

    print("\n" + "=" * 64)
    print(f"SUMMARY: PASS={passes}  WARN={warns}  FAIL={fails}")
    if fails:
        print("RESULT: FAIL")
        print("See UPGRADE_GUIDE.md / UPDATE_AUDIT.md")
        print("=" * 64)
        return 1
    print("RESULT: PASS")
    if warns:
        print(f"(with {warns} warning(s) — review before live Mininet demos)")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
