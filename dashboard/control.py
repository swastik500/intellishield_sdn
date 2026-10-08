"""
IntelliShield SDN — Dashboard Master Control

Runs lab operations (controller, scenarios, metrics, training) as background
jobs so the dashboard UI can trigger them without SSH.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from evaluation.csv_log_io import KNOWN_CSV_HEADERS, ensure_csv_header

_ROOT = Path(__file__).resolve().parent.parent
_LOGS = _ROOT / "logs"
_CONTROLLER = _ROOT / "controller" / "flow_monitor.py"

_LOG_FILES = [
    "scenario_logs.csv",
    "entropy_logs.csv",
    "ml_predictions.csv",
    "mitigation_actions.csv",
    "detection_alerts.csv",
    "rl_decisions.csv",
]

SCENARIOS = {
    "1": "Normal baseline (60s)",
    "2": "SYN flood h1→h2",
    "3": "UDP flood h1→h2",
    "4": "Burst attack",
    "5": "Mixed SYN + UDP",
    "6": "S6 Zero-Day (SSL) attack",
}


@dataclass
class Job:
    id: str
    name: str
    command: str
    status: str = "running"  # running | success | failed
    started_at: str = ""
    ended_at: Optional[str] = None
    exit_code: Optional[int] = None
    log: List[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def append(self, line: str) -> None:
        with self._lock:
            self.log.append(line.rstrip("\n"))
            if len(self.log) > 500:
                self.log = self.log[-500:]

    def to_dict(self, tail: int = 80) -> dict:
        with self._lock:
            lines = self.log[-tail:]
        return {
            "id"         : self.id,
            "name"       : self.name,
            "command"    : self.command,
            "status"     : self.status,
            "started_at" : self.started_at,
            "ended_at"   : self.ended_at,
            "exit_code"  : self.exit_code,
            "log_tail"   : lines,
        }


class ControlPanel:
    """Thread-safe job runner for dashboard operations."""

    def __init__(self, root: Path = _ROOT):
        self.root = root
        self.logs = root / "logs"
        self.jobs: Dict[str, Job] = {}
        self._jobs_lock = threading.Lock()
        self._scenario_lock = threading.Lock()
        self._scenario_running = False

    # ── Process helpers ───────────────────────────────────────────────────

    def controller_running(self) -> bool:
        return self._controller_pids() != []

    def _controller_pids(self) -> List[int]:
        """PIDs of osken-manager running our flow_monitor (not dashboard/bash)."""
        try:
            marker = str(_CONTROLLER.resolve())
            out = subprocess.run(
                ["pgrep", "-f", "osken-manager"],
                capture_output=True, text=True, timeout=5,
            )
            pids = []
            for line in out.stdout.strip().splitlines():
                if not line.strip().isdigit():
                    continue
                pid = int(line.strip())
                try:
                    cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(
                        "utf-8", errors="ignore"
                    )
                except OSError:
                    continue
                if "osken-manager" in cmd and marker in cmd:
                    pids.append(pid)
            return pids
        except Exception:
            return []

    def _stop_controller_processes(self, job: Optional[Job] = None) -> None:
        for pid in self._controller_pids():
            if job:
                job.append(f"Stopping controller PID {pid}")
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if self._controller_pids():
            time.sleep(1)
            for pid in self._controller_pids():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def _start_controller_process(self, job: Optional[Job] = None) -> None:
        log_path = Path("/tmp/controller.log")
        log_fh = open(log_path, "a", encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.root) + os.pathsep + env.get("PYTHONPATH", "")
        subprocess.Popen(
            ["osken-manager", str(_CONTROLLER.resolve())],
            cwd=str(self.root),
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        if job:
            job.append(f"Started osken-manager → {log_path}")

    def _restart_controller_worker(self, job: Job, warmup_sec: int) -> None:
        try:
            job.append("Restarting controller…")
            self._stop_controller_processes(job)
            time.sleep(2)
            self._start_controller_process(job)
            job.append(f"Warmup {warmup_sec}s…")
            time.sleep(warmup_sec)
            if self.controller_running():
                job.append("Controller is running.")
                job.status = "success"
                job.exit_code = 0
            else:
                job.append("Controller failed to start — check /tmp/controller.log")
                job.status = "failed"
                job.exit_code = 1
        except Exception as exc:
            job.append(f"ERROR: {exc}")
            job.status = "failed"
            job.exit_code = -1
        finally:
            job.ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _sudo_prefix(self) -> List[str]:
        if os.environ.get("INTELLISHIELD_SUDO_PASS"):
            return ["sudo", "-S"]
        return ["sudo", "-n"]

    def _run_sync(self, cmd: List[str], cwd: Optional[Path] = None,
                  input_text: str = "", timeout: int = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            cwd=str(cwd or self.root),
            capture_output=True,
            text=True,
            input=input_text or None,
            timeout=timeout,
        )

    def _start_job(self, name: str, cmd: List[str], cwd: Optional[Path] = None,
                   stdin: str = "") -> Job:
        job_id = uuid.uuid4().hex[:10]
        job = Job(
            id=job_id,
            name=name,
            command=" ".join(shlex.quote(c) for c in cmd),
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._jobs_lock:
            self.jobs[job_id] = job
            # Keep last 30 jobs
            if len(self.jobs) > 30:
                for old in sorted(self.jobs.keys())[:-30]:
                    del self.jobs[old]

        def _worker():
            try:
                proc = subprocess.Popen(
                    cmd,
                    cwd=str(cwd or self.root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    stdin=subprocess.PIPE if stdin else None,
                )
                if stdin and proc.stdin:
                    proc.stdin.write(stdin)
                    proc.stdin.close()
                assert proc.stdout is not None
                for line in proc.stdout:
                    job.append(line)
                proc.wait()
                job.exit_code = proc.returncode
                job.status = "success" if proc.returncode == 0 else "failed"
            except Exception as exc:
                job.append(f"ERROR: {exc}")
                job.status = "failed"
                job.exit_code = -1
            finally:
                job.ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if "scenario" in name.lower():
                    with self._scenario_lock:
                        self._scenario_running = False

        threading.Thread(target=_worker, daemon=True).start()
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def list_jobs(self) -> List[dict]:
        with self._jobs_lock:
            items = sorted(self.jobs.values(), key=lambda j: j.started_at, reverse=True)
        return [j.to_dict() for j in items[:20]]

    # ── Operations ────────────────────────────────────────────────────────

    def archive_logs(self) -> dict:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self.logs / "archive" / stamp
        dest.mkdir(parents=True, exist_ok=True)
        moved = []
        for name in _LOG_FILES:
            src = self.logs / name
            if src.exists():
                shutil.move(str(src), str(dest / name))
                moved.append(name)
        for name in moved:
            headers = KNOWN_CSV_HEADERS.get(name)
            if headers:
                ensure_csv_header(self.logs / name, headers)
        return {"archived_to": str(dest), "files": moved}

    def restart_controller(self, warmup_sec: int = 20) -> Job:
        job_id = uuid.uuid4().hex[:10]
        job = Job(
            id=job_id,
            name="Restart controller",
            command=f"osken-manager {_CONTROLLER}",
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._jobs_lock:
            self.jobs[job_id] = job
        threading.Thread(
            target=self._restart_controller_worker,
            args=(job, warmup_sec),
            daemon=True,
        ).start()
        return job

    def stop_controller(self) -> dict:
        try:
            self._stop_controller_processes()
            return {"ok": True, "message": "Controller stop signalled"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def run_scenario(self, scenario_id: str) -> Job:
        if scenario_id not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario_id}")
        with self._scenario_lock:
            if self._scenario_running:
                raise RuntimeError("Another scenario is already running")
            self._scenario_running = True

        sudo = self._sudo_prefix()
        pw = os.environ.get("INTELLISHIELD_SUDO_PASS", "")
        cmd = sudo + [
            "python3", "-m", "traffic_generator.traffic_scheduler",
            "--scenario", scenario_id,
        ]
        return self._start_job(
            f"Scenario {scenario_id}: {SCENARIOS[scenario_id]}",
            cmd,
            stdin=f"{pw}\n" if pw else "",
        )

    def run_scenario_batch(self, scenario_ids: List[str],
                           archive_first: bool = True,
                           restart_controller: bool = True) -> Job:
        ids = [s for s in scenario_ids if s in SCENARIOS]
        if not ids:
            raise ValueError("No valid scenario IDs")

        with self._scenario_lock:
            if self._scenario_running:
                raise RuntimeError("Another scenario is already running")
            self._scenario_running = True

        sudo = self._sudo_prefix()
        pw = os.environ.get("INTELLISHIELD_SUDO_PASS", "")
        return self._start_batch_python(ids, archive_first, restart_controller, pw, sudo)

    def _start_batch_python(self, ids: List[str], archive_first: bool,
                            restart_controller: bool, pw: str,
                            sudo: List[str]) -> Job:
        job_id = uuid.uuid4().hex[:10]
        job = Job(
            id=job_id,
            name=f"Batch scenarios {','.join(ids)}",
            command="python batch orchestrator",
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        with self._jobs_lock:
            self.jobs[job_id] = job

        def _worker():
            try:
                if archive_first:
                    result = self.archive_logs()
                    job.append(f"Archived → {result.get('archived_to', '?')}")
                if restart_controller:
                    self._stop_controller_processes(job)
                    time.sleep(2)
                    self._start_controller_process(job)
                    job.append("Controller warmup 20s…")
                    time.sleep(20)
                for sid in ids:
                    job.append(f"── Scenario {sid}: {SCENARIOS[sid]} ──")
                    cmd = sudo + [
                        "python3", "-m", "traffic_generator.traffic_scheduler",
                        "--scenario", sid,
                    ]
                    proc = subprocess.run(
                        cmd,
                        cwd=str(self.root),
                        capture_output=True,
                        text=True,
                        input=f"{pw}\n" if pw else None,
                        timeout=600,
                    )
                    if proc.stdout:
                        job.append(proc.stdout[-2000:])
                    if proc.returncode != 0:
                        job.append(proc.stderr or f"Exit code {proc.returncode}")
                        job.status = "failed"
                        job.exit_code = proc.returncode
                        return
                job.append("Computing metrics…")
                proc = subprocess.run(
                    ["python3", "scripts/compute_metrics.py",
                     "--json-out", "logs/metrics_report.json",
                     "--bundle"],
                    cwd=str(self.root),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if proc.stdout:
                    job.append(proc.stdout[-1500:])
                job.status = "success" if proc.returncode == 0 else "failed"
                job.exit_code = proc.returncode
            except Exception as exc:
                job.append(f"ERROR: {exc}")
                job.status = "failed"
                job.exit_code = -1
            finally:
                job.ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with self._scenario_lock:
                    self._scenario_running = False

        threading.Thread(target=_worker, daemon=True).start()
        return job

    def _archive_shell(self) -> str:
        moves = " ".join(f"logs/{f}" for f in _LOG_FILES)
        return (
            'ARCH=logs/archive/$(date +%Y%m%d_%H%M%S) && mkdir -p "$ARCH" && '
            f'mv {moves} "$ARCH"/ 2>/dev/null || true && '
            'echo "Archived to $ARCH"'
        )

    def compute_metrics(self) -> Job:
        return self._start_job(
            "Compute metrics",
            ["python3", "scripts/compute_metrics.py",
             "--json-out", "logs/metrics_report.json",
             "--bundle"],
        )

    def bundle_experiment(self, bundle_id: str = "") -> Job:
        cmd = ["python3", "scripts/bundle_experiment.py"]
        if bundle_id:
            cmd.extend(["--bundle-id", bundle_id])
        return self._start_job("Bundle experiment", cmd)

    def train_models(self) -> Job:
        return self._start_job(
            "Train ML models",
            ["python3", "-m", "ml_models.model_trainer", "--from-csv"],
        )

    def status(self) -> dict:
        with self._scenario_lock:
            scenario_busy = self._scenario_running
        running_jobs = [j.to_dict(tail=5) for j in self.jobs.values() if j.status == "running"]
        return {
            "controller_running": self.controller_running(),
            "scenario_running"  : scenario_busy,
            "sudo_password_set" : bool(os.environ.get("INTELLISHIELD_SUDO_PASS")),
            "project_root"      : str(self.root),
            "running_jobs"      : running_jobs,
            "scenarios"         : SCENARIOS,
        }


# Singleton used by api.py
panel = ControlPanel()
