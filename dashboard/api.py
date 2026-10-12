"""
================================================================================
IntelliShield SDN — Phase 8: Live Dashboard API
================================================================================

File    : dashboard/api.py
Phase   : Phase 8 — Real-Time Monitoring Dashboard
Version : 1.0.0

Description:
    FastAPI backend that reads IntelliShield log CSV files in real-time and
    serves structured JSON for the dashboard frontend.

    Endpoints:
        GET /api/status       — Phase health (which detectors are active)
        GET /api/traffic      — Last N flow stats (packet rate, byte rate)
        GET /api/entropy      — Latest entropy scores per dimension
        GET /api/alerts       — Recent entropy detection alerts (CSV legacy)
        GET /api/security-alerts — R8 AlertEvent history (alerts.jsonl)
        GET /api/security-alerts/stats — R8 alert counters
        GET /api/root-cause-reports — R5 RCA history (root_cause_reports.jsonl)
        GET /api/root-cause-reports/{id} — R5 single RCA report
        GET /api/root-cause-reports/by-event/{event_id} — newest RCA for event
        GET /api/correlation-results — R4 CorrelationResult history
        GET /api/correlation-results/{id} — R4 single correlation
        GET /api/correlation-results/stats — R4 bounded stats
        GET /api/fused-decisions — R6 FusedDecision history
        GET /api/fused-decisions/{id} — R6 single fusion
        GET /api/fused-decisions/stats — R6 bounded stats
        GET /api/verification-traces — R7 verification_trace.jsonl (read-only)
        GET /api/verification-traces/{id} — R7 single verification trace
        GET /api/topology — Read-only switches + learned hosts (topology_status.json)
        GET /api/digital-twin/profiles — R3 Twin profiles (read-only)
        GET /api/digital-twin/runs — R3 Twin experiment runs
        GET /api/digital-twin/runs/{id} — R3 single twin run
        GET /api/digital-twin/validation — R3 validation summaries
        GET /api/digital-twin/datasets — R3 training datasets
        GET /api/digital-twin/stats — R3 twin bounded stats
        GET /api/digital-twin/snapshots — R3 observational snapshots
        GET /api/digital-twin/snapshots/{id} — R3 single snapshot
        GET /api/digital-twin/replays — R3 scenario replay results
        GET /api/digital-twin/simulations — R3 what-if simulations
        GET /api/blocklist    — Active mitigation blocks
        GET /api/rl           — RL adaptive threshold decisions
        GET /api/drift        — ADWIN drift events
        GET /api/summary      — Single-call stats summary card data

    Serves static frontend from dashboard/static/index.html

Usage (on VM):
    cd ~/intellishield-sdn
    python3 dashboard/api.py

    Then open: http://192.168.64.5:8080
================================================================================
"""

import os
import csv
import json
import logging
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from collections import defaultdict

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

_HERE     = Path(__file__).parent
_ROOT     = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no extra dependency). Does not override existing env."""
    if not path.is_file():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception:
        pass


_load_dotenv(_ROOT / ".env")

from evaluation.csv_log_io import KNOWN_CSV_HEADERS, ensure_csv_header, load_csv_rows

# Master Control panel: script mode has dashboard/ on sys.path (`from control import panel`);
# package/tests mode imports via dashboard.control.
try:
    from control import panel  # type: ignore  # noqa: F401 — dashboard/control.py as top-level
except ImportError:  # pragma: no cover
    from dashboard.control import panel

try:
    from dashboard.auth import auth_router, load_auth_config
    from dashboard.auth.errors import AuthError, auth_exception_handler, authentication_required
    from dashboard.auth.deps import COOKIE_NAME, resolve_principal
    from dashboard.commands import commands_router
except ImportError:  # pragma: no cover — script path when dashboard/ is on sys.path
    from auth import auth_router, load_auth_config
    from auth.errors import AuthError, auth_exception_handler, authentication_required
    from deps import COOKIE_NAME, resolve_principal
    from commands import commands_router

# ── Paths ─────────────────────────────────────────────────────────────────────

_LOGS     = _ROOT / "logs"
_STATIC   = _HERE / "static"

FLOW_CSV        = _LOGS / "flow_stats.csv"
ENTROPY_CSV     = _LOGS / "entropy_logs.csv"
ALERTS_CSV      = _LOGS / "detection_alerts.csv"
SECURITY_ALERTS_JSONL = _LOGS / "alerts.jsonl"
RCA_REPORTS_JSONL = _LOGS / "root_cause_reports.jsonl"
CORR_RESULTS_JSONL = _LOGS / "correlation_results.jsonl"
FUSED_DECISIONS_JSONL = _LOGS / "fused_decisions.jsonl"
VERIFICATION_TRACE_JSONL = _LOGS / "verification_trace.jsonl"
TWIN_LOGS_DIR = _LOGS
MITIGATION_CSV  = _LOGS / "mitigation_actions.csv"
TOPOLOGY_STATUS_JSON = _LOGS / "topology_status.json"
RL_CSV          = _LOGS / "rl_decisions.csv"
DRIFT_CSV       = _LOGS / "drift_alerts.csv"
ML_PRED_CSV     = _LOGS / "ml_predictions.csv"
ML_ALERT_CSV    = _LOGS / "ml_alerts.csv"
ML_SUMMARY      = _LOGS / "ml_summary.json"
MIT_SUMMARY     = _LOGS / "mitigation_summary.json"
PPO_WEIGHTS     = _LOGS / "ppo_weights.pkl"
CLUSTER_SUMMARY = _LOGS / "cluster_summary.json"
PORT_STATS_CSV  = _LOGS / "port_stats.csv"  # written every poll cycle by controller


def repair_known_log_headers() -> List[str]:
    """Repair headerless CSV logs so dashboard parsing uses real field names."""
    repaired = []
    for name, headers in KNOWN_CSV_HEADERS.items():
        path = _LOGS / name
        if not path.exists():
            continue
        try:
            before_rows = load_csv_rows(path, fallback_headers=headers, tail_n=1)
            ensure_csv_header(path, headers)
            after_rows = load_csv_rows(path, fallback_headers=headers, tail_n=1)
            if before_rows and after_rows:
                repaired.append(name)
        except Exception as exc:
            logger.warning("Could not repair CSV header for %s: %s", path, exc)
    return repaired


# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "IntelliShield SDN — Live Dashboard API",
    description = "Real-time DDoS detection and mitigation monitoring",
    version     = "1.0.0",
)

# CORS: never pair credentials with allow_origins=["*"].
# Lab default remains open origins without credentials (same-origin SOC cookies still work).
# Set INTELLISHIELD_CORS_ORIGINS to an explicit list when cross-origin credentialed auth is needed.
_auth_cfg_for_cors = load_auth_config()
_cors_origins = list(_auth_cfg_for_cors.cors_origins) if _auth_cfg_for_cors.cors_origins else ["*"]
_cors_credentials = bool(_auth_cfg_for_cors.cors_origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(AuthError, auth_exception_handler)
app.include_router(auth_router)
app.include_router(commands_router)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dashboard")

_REPAIRED_LOGS = repair_known_log_headers()
if _REPAIRED_LOGS:
    logger.info("CSV log header repair checked: %s", ", ".join(_REPAIRED_LOGS))


# ── CSV Helpers ───────────────────────────────────────────────────────────────

def read_csv_tail(path: Path, n: int = 100) -> List[Dict[str, str]]:
    """Read the last `n` rows of a CSV file safely."""
    try:
        return load_csv_rows(path, tail_n=n)
    except Exception as e:
        logger.warning("Could not read %s: %s", path, e)
        return []


def read_json_safe(path: Path) -> dict:
    """Read a JSON file safely, returning empty dict on failure."""
    if not path.exists():
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def read_jsonl_tail(path: Path, limit: int = 50, scan_max: int = 5000) -> List[Dict[str, Any]]:
    """
    Bounded newest-first JSONL reader for dashboard surfaces.

    Does not modify security packages — reads an existing append-only log only.
    """
    limit = max(0, min(int(limit), 500))
    if limit == 0 or not path.exists():
        return []
    try:
        # Read up to scan_max trailing lines without loading arbitrary full files.
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = 64 * 1024
            data = b""
            while size > 0 and data.count(b"\n") <= scan_max:
                step = min(block, size)
                size -= step
                fh.seek(size)
                data = fh.read(step) + data
                if size == 0:
                    break
        lines = [ln for ln in data.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        lines = lines[-scan_max:]
        parsed: List[Dict[str, Any]] = []
        for line in lines:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                parsed.append(obj)
        parsed.reverse()  # newest first
        return parsed[:limit]
    except Exception as exc:
        logger.warning("JSONL tail read failed for %s: %s", path, exc)
        return []


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the primary DDoS Dashboard UI (new UI under static/soc/)."""
    soc = _STATIC / "soc" / "index.html"
    if soc.exists():
        return HTMLResponse(content=soc.read_text(encoding="utf-8"))
    # Fallback to preserved legacy UI if DDoS Dashboard assets are missing
    legacy = _STATIC / "legacy" / "index.html"
    if legacy.exists():
        return HTMLResponse(content=legacy.read_text(encoding="utf-8"))
    index = _STATIC / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard frontend not found.</h1>")


@app.get("/legacy", response_class=HTMLResponse)
def serve_legacy_dashboard():
    """Preserved legacy dashboard (includes Master Control) — temporary fallback."""
    legacy = _STATIC / "legacy" / "index.html"
    if legacy.exists():
        return HTMLResponse(content=legacy.read_text(encoding="utf-8"))
    index = _STATIC / "index.html"
    if index.exists():
        return HTMLResponse(content=index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Legacy dashboard not found.</h1>")


@app.get("/api/status")
def get_status():
    """Return which IntelliShield phases are currently active."""
    def file_active(path: Path) -> bool:
        if not path.exists():
            return False
        age = (datetime.now().timestamp() - path.stat().st_mtime)
        return age < 300   # active if written in last 5 minutes

    return {
        "phase1_flow_monitor" : file_active(FLOW_CSV) or file_active(PORT_STATS_CSV),
        "phase2_entropy"      : file_active(ENTROPY_CSV),
        "phase4_ml"           : file_active(ML_PRED_CSV),
        "phase5_mitigation"   : MITIGATION_CSV.exists(),
        "phase6_adwin"        : DRIFT_CSV.exists(),
        "phase7_rl"           : PPO_WEIGHTS.exists(),
        # Controller is live if port_stats (written every cycle) OR flow_stats is fresh
        "controller_running"  : file_active(PORT_STATS_CSV) or file_active(FLOW_CSV),
        # Dashboard display must be in IST (UTC+05:30)
        "server_time"         : datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/topology")
def get_topology():
    """
    Read-only network topology snapshot (switches + learned hosts).

    Sourced from logs/topology_status.json written by the controller.
    Does not invent devices. Does not discover switch–switch links (no LLDP).
    Never mutates the network.
    """
    stale_after_sec = 30.0
    empty = {
        "schema_version": 1,
        "available": False,
        "freshness": "UNAVAILABLE",
        "controller_connected": False,
        "switch_count": 0,
        "host_count": 0,
        "link_count": 0,
        "switches": [],
        "hosts": [],
        "links": [],
        "updated_at": None,
        "age_seconds": None,
        "source": "topology_status.json",
        "path": str(TOPOLOGY_STATUS_JSON),
        "limitations": [
            "No topology snapshot file yet — start the controller (and Mininet) to publish.",
            "Host–switch attachments only; switch–switch links are not discovered.",
        ],
        "note": "READ ONLY observational snapshot — not authoritative for mitigation.",
    }
    try:
        if not TOPOLOGY_STATUS_JSON.exists():
            return empty
        raw = read_json_safe(TOPOLOGY_STATUS_JSON)
        if not raw:
            out = dict(empty)
            out["freshness"] = "UNAVAILABLE"
            out["error"] = "empty_or_unreadable"
            return out

        updated_unix = raw.get("updated_at_unix")
        age = None
        freshness = "STALE"
        if isinstance(updated_unix, (int, float)):
            age = max(0.0, time.time() - float(updated_unix))
            freshness = "LIVE" if age <= stale_after_sec else "STALE"
        elif TOPOLOGY_STATUS_JSON.exists():
            age = max(0.0, time.time() - TOPOLOGY_STATUS_JSON.stat().st_mtime)
            freshness = "LIVE" if age <= stale_after_sec else "STALE"

        switches = raw.get("switches") if isinstance(raw.get("switches"), list) else []
        hosts = raw.get("hosts") if isinstance(raw.get("hosts"), list) else []
        links = raw.get("links") if isinstance(raw.get("links"), list) else []
        last_known = raw.get("last_known") if isinstance(raw.get("last_known"), dict) else None
        connection_state = raw.get("connection_state") or (
            "CONNECTED" if switches else "NO_SWITCHES"
        )

        return {
            "schema_version": raw.get("schema_version", 1),
            "available": True,
            "freshness": freshness,
            "connection_state": connection_state,
            "controller_connected": bool(raw.get("controller_connected", True)),
            "switch_count": int(raw.get("switch_count", len(switches)) or 0),
            "host_count": int(raw.get("host_count", len(hosts)) or 0),
            "link_count": int(raw.get("link_count", len(links)) or 0),
            "switches": switches,
            "hosts": hosts,
            "links": links,
            "last_known": last_known,
            "updated_at": raw.get("updated_at"),
            "age_seconds": round(age, 3) if age is not None else None,
            "poll_interval_sec": raw.get("poll_interval_sec"),
            "limitations": raw.get("limitations")
            if isinstance(raw.get("limitations"), list)
            else empty["limitations"],
            "source": "topology_status.json",
            "path": str(TOPOLOGY_STATUS_JSON),
            "note": raw.get("note")
            or "READ ONLY observational snapshot — not authoritative for mitigation.",
        }
    except Exception as exc:
        logger.warning("topology read failed: %s", exc)
        out = dict(empty)
        out["error"] = type(exc).__name__
        return out


@app.get("/api/traffic")
def get_traffic(n: int = 60):
    """Return the last `n` poll-cycle traffic aggregates for charting."""
    rows = read_csv_tail(FLOW_CSV, n=500)
    if not rows:
        return {"points": [], "total_rows": 0}

    agg: Dict[str, Dict] = defaultdict(lambda: {"packet_rate": 0.0, "byte_rate": 0.0, "flow_count": 0})
    for r in rows:
        ts = r.get("timestamp", "")
        agg[ts]["packet_rate"] += safe_float(r.get("packet_rate", 0))
        agg[ts]["byte_rate"]   += safe_float(r.get("byte_rate", 0))
        agg[ts]["flow_count"]  += 1

    points = [
        {
            "timestamp"  : ts,
            "packet_rate": round(v["packet_rate"], 2),
            "byte_rate"  : round(v["byte_rate"], 2),
            "flow_count" : v["flow_count"],
        }
        for ts, v in sorted(agg.items())
    ][-n:]

    return {"points": points, "total_rows": len(rows)}


@app.get("/api/entropy")
def get_entropy(n: int = 60):
    """Return the last `n` entropy readings."""
    rows = read_csv_tail(ENTROPY_CSV, n=n)
    if not rows:
        return {"points": [], "latest": None}

    points = [
        {
            "timestamp"     : r.get("timestamp", ""),
            "src_entropy"   : safe_float(r.get("src_entropy", 1)),
            "dst_entropy"   : safe_float(r.get("dst_entropy", 1)),
            "packet_entropy": safe_float(r.get("packet_entropy", 1)),
            "byte_entropy"  : safe_float(r.get("byte_entropy", 1)),
            "flow_entropy"  : safe_float(r.get("flow_entropy", 1)),
            "entropy_score" : safe_float(r.get("entropy_score", 1)),
            "status"        : r.get("status", "NORMAL"),
            "confidence"    : safe_float(r.get("confidence", 0)),
        }
        for r in rows
    ]

    return {"points": points, "latest": points[-1] if points else None}


@app.get("/api/alerts")
def get_alerts(n: int = 20):
    """Return the last `n` detection alerts (newest first)."""
    rows = read_csv_tail(ALERTS_CSV, n=n)
    alerts = [
        {
            "timestamp" : r.get("timestamp", ""),
            "switch_id" : r.get("switch_id", "?"),
            "alert_type": r.get("alert_type", "UNKNOWN"),
            "dimension" : r.get("dimension", ""),
            "value"     : safe_float(r.get("entropy_value", 0)),
            "threshold" : safe_float(r.get("threshold", 0)),
            "score"     : safe_float(r.get("entropy_score", 0)),
            "confidence": safe_float(r.get("confidence", 0)),
            "status"    : r.get("status", "ALERT"),
        }
        for r in reversed(rows)
    ]
    return {"alerts": alerts, "total": len(alerts)}


@app.get("/api/security-alerts")
def get_security_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
):
    """
    R8 AlertEvent history from logs/alerts.jsonl (newest first).

    Does not replace GET /api/alerts (legacy detection_alerts.csv).
    """
    try:
        from alerting.persistence import alert_record_for_api, read_alert_history

        if limit < 0 or limit > 500:
            raise HTTPException(status_code=400, detail="limit must be in [0, 500]")
        if severity is not None and not str(severity).strip():
            raise HTTPException(status_code=400, detail="severity must be non-empty")
        if alert_type is not None and not str(alert_type).strip():
            raise HTTPException(status_code=400, detail="alert_type must be non-empty")

        records = read_alert_history(
            str(SECURITY_ALERTS_JSONL),
            limit=limit,
            severity=severity,
            alert_type=alert_type,
            since=since,
            until=until,
        )
        alerts = [alert_record_for_api(r) for r in records]
        return {
            "alerts": alerts,
            "total": len(alerts),
            "source": "alerts.jsonl",
            "path": str(SECURITY_ALERTS_JSONL),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("security-alerts read failed: %s", exc)
        return {
            "alerts": [],
            "total": 0,
            "source": "alerts.jsonl",
            "path": str(SECURITY_ALERTS_JSONL),
            "error": type(exc).__name__,
        }


@app.get("/api/security-alerts/stats")
def get_security_alert_stats():
    """Bounded stats over recent R8 AlertEvent JSONL history."""
    try:
        from alerting.persistence import alert_history_stats

        return alert_history_stats(str(SECURITY_ALERTS_JSONL))
    except Exception as exc:
        logger.warning("security-alerts stats failed: %s", exc)
        return {
            "total": 0,
            "exists": SECURITY_ALERTS_JSONL.exists(),
            "empty": True,
            "error": type(exc).__name__,
        }


@app.get("/api/root-cause-reports")
def get_root_cause_reports(
    limit: int = 20,
    event_id: Optional[str] = None,
):
    """
    R5 RootCauseReport history from logs/root_cause_reports.jsonl (newest first).

    Bounded read — does not load unlimited history.
    """
    try:
        from rca.persistence import rca_record_for_api, read_rca_history

        if limit < 0 or limit > 500:
            raise HTTPException(status_code=400, detail="limit must be in [0, 500]")
        records = read_rca_history(
            str(RCA_REPORTS_JSONL),
            limit=limit,
            event_id=event_id,
        )
        reports = [rca_record_for_api(r) for r in records]
        return {
            "reports": reports,
            "total": len(reports),
            "source": "root_cause_reports.jsonl",
            "path": str(RCA_REPORTS_JSONL),
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("root-cause-reports read failed: %s", exc)
        return {
            "reports": [],
            "total": 0,
            "source": "root_cause_reports.jsonl",
            "path": str(RCA_REPORTS_JSONL),
            "error": type(exc).__name__,
        }


@app.get("/api/root-cause-reports/by-event/{event_id}")
def get_root_cause_by_event(event_id: str):
    """Newest RCA report for an event_id (bounded scan)."""
    try:
        from rca.persistence import get_rca_by_event, rca_record_for_api

        if not event_id or not str(event_id).strip():
            raise HTTPException(status_code=400, detail="event_id required")
        rec = get_rca_by_event(str(RCA_REPORTS_JSONL), str(event_id).strip())
        if rec is None:
            raise HTTPException(status_code=404, detail="RCA report not found for event")
        return rca_record_for_api(rec)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("root-cause by-event failed: %s", exc)
        raise HTTPException(status_code=500, detail=type(exc).__name__) from exc


@app.get("/api/root-cause-reports/{report_id}")
def get_root_cause_report(report_id: str):
    """Single RootCauseReport by report_id (bounded scan)."""
    try:
        from rca.persistence import get_rca_report, rca_record_for_api

        if not report_id or not str(report_id).strip():
            raise HTTPException(status_code=400, detail="report_id required")
        # Avoid collision with the by-event static path segment if mis-ordered —
        # FastAPI matches more specific routes first when declared above.
        rec = get_rca_report(str(RCA_REPORTS_JSONL), str(report_id).strip())
        if rec is None:
            raise HTTPException(status_code=404, detail="RCA report not found")
        return rca_record_for_api(rec)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("root-cause report lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail=type(exc).__name__) from exc


@app.get("/api/correlation-results")
def get_correlation_results(
    limit: int = 20,
    event_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
):
    """
    R4 CorrelationResult history from logs/correlation_results.jsonl (newest first).

    Advisory evidence only — not a final attack detector.
    """
    try:
        from correlation.persistence import (
            correlation_record_for_api,
            read_correlation_history,
        )

        if limit < 0 or limit > 500:
            raise HTTPException(status_code=400, detail="limit must be in [0, 500]")
        records = read_correlation_history(
            str(CORR_RESULTS_JSONL),
            limit=limit,
            event_id=event_id,
            since=since,
            until=until,
        )
        results = [correlation_record_for_api(r) for r in records]
        return {
            "results": results,
            "total": len(results),
            "source": "correlation_results.jsonl",
            "path": str(CORR_RESULTS_JSONL),
            "note": "Correlation expresses co-occurrence — not causation.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("correlation-results read failed: %s", exc)
        return {
            "results": [],
            "total": 0,
            "source": "correlation_results.jsonl",
            "path": str(CORR_RESULTS_JSONL),
            "error": type(exc).__name__,
            "note": "Correlation expresses co-occurrence — not causation.",
        }


@app.get("/api/correlation-results/stats")
def get_correlation_results_stats():
    """Bounded stats over recent R4 CorrelationResult JSONL history."""
    try:
        from correlation.persistence import correlation_history_stats

        return correlation_history_stats(str(CORR_RESULTS_JSONL))
    except Exception as exc:
        logger.warning("correlation-results stats failed: %s", exc)
        return {
            "total": 0,
            "exists": CORR_RESULTS_JSONL.exists(),
            "empty": True,
            "error": type(exc).__name__,
        }


@app.get("/api/correlation-results/{correlation_id}")
def get_correlation_result_by_id(correlation_id: str):
    """Single CorrelationResult by correlation_id (bounded scan)."""
    try:
        from correlation.persistence import (
            correlation_record_for_api,
            get_correlation_result,
        )

        if not correlation_id or not str(correlation_id).strip():
            raise HTTPException(status_code=400, detail="correlation_id required")
        if str(correlation_id).strip().lower() == "stats":
            # Defensive: should be matched by /stats route above
            return get_correlation_results_stats()
        rec = get_correlation_result(
            str(CORR_RESULTS_JSONL), str(correlation_id).strip()
        )
        if rec is None:
            raise HTTPException(status_code=404, detail="Correlation result not found")
        return correlation_record_for_api(rec)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("correlation-result lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail=type(exc).__name__) from exc


@app.get("/api/fused-decisions")
def get_fused_decisions(
    limit: int = 20,
    event_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
):
    """
    R6 FusedDecision history from logs/fused_decisions.jsonl (newest first).

    Collaborative evidence only — R7 still gates mitigation.
    ADWIN/HDBSCAN appear as context indicators, not attack detectors.
    """
    try:
        from fusion.history import (
            fused_decision_record_for_api,
            read_fused_decision_history,
        )

        if limit < 0 or limit > 500:
            raise HTTPException(status_code=400, detail="limit must be in [0, 500]")
        records = read_fused_decision_history(
            str(FUSED_DECISIONS_JSONL),
            limit=limit,
            event_id=event_id,
            since=since,
            until=until,
        )
        results = [fused_decision_record_for_api(r) for r in records]
        return {
            "results": results,
            "total": len(results),
            "source": "fused_decisions.jsonl",
            "path": str(FUSED_DECISIONS_JSONL),
            "note": "Collaborative fusion — not causation; R7 gates mitigation.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("fused-decisions read failed: %s", exc)
        return {
            "results": [],
            "total": 0,
            "source": "fused_decisions.jsonl",
            "path": str(FUSED_DECISIONS_JSONL),
            "error": type(exc).__name__,
            "note": "Collaborative fusion — not causation; R7 gates mitigation.",
        }


@app.get("/api/fused-decisions/stats")
def get_fused_decisions_stats():
    """Bounded stats over recent R6 FusedDecision JSONL history."""
    try:
        from fusion.history import fused_decision_history_stats

        return fused_decision_history_stats(str(FUSED_DECISIONS_JSONL))
    except Exception as exc:
        logger.warning("fused-decisions stats failed: %s", exc)
        return {
            "total": 0,
            "exists": FUSED_DECISIONS_JSONL.exists(),
            "empty": True,
            "error": type(exc).__name__,
        }


@app.get("/api/verification-traces")
def get_verification_traces(
    limit: int = 50,
    event_id: Optional[str] = None,
    status: Optional[str] = None,
):
    """
    R7 verification_trace.jsonl history (newest first) — read-only.

    Dashboard-only log viewer. Does not change verification algorithms or gates.
    """
    try:
        if limit < 0 or limit > 500:
            raise HTTPException(status_code=400, detail="limit must be in [0, 500]")
        need = 500 if (event_id or status) else limit
        records = read_jsonl_tail(VERIFICATION_TRACE_JSONL, limit=need)
        if event_id:
            eid = str(event_id).strip()
            records = [r for r in records if str(r.get("event_id", "")) == eid]
        if status:
            st = str(status).strip().upper()
            records = [
                r for r in records
                if str(r.get("status", "")).upper() == st
            ]
        traces = records[:limit]
        return {
            "traces": traces,
            "total": len(traces),
            "source": "verification_trace.jsonl",
            "path": str(VERIFICATION_TRACE_JSONL),
            "note": "R7 verification outcomes are backend-authored. UI is observer-only.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("verification-traces read failed: %s", exc)
        return {
            "traces": [],
            "total": 0,
            "source": "verification_trace.jsonl",
            "path": str(VERIFICATION_TRACE_JSONL),
            "error": type(exc).__name__,
            "note": "R7 verification outcomes are backend-authored. UI is observer-only.",
        }


@app.get("/api/verification-traces/{verification_id}")
def get_verification_trace_by_id(verification_id: str):
    """Single R7 verification trace by verification_id (bounded scan)."""
    if not verification_id or not str(verification_id).strip():
        raise HTTPException(status_code=400, detail="verification_id required")
    vid = str(verification_id).strip()
    records = read_jsonl_tail(VERIFICATION_TRACE_JSONL, limit=500)
    for rec in records:
        if str(rec.get("verification_id", "")) == vid:
            return rec
    raise HTTPException(status_code=404, detail="Verification trace not found")


@app.get("/api/fused-decisions/{fusion_id}")
def get_fused_decision_by_id(fusion_id: str):
    """Single FusedDecision by fusion_id (bounded scan)."""
    try:
        from fusion.history import (
            fused_decision_record_for_api,
            get_fused_decision,
        )

        if not fusion_id or not str(fusion_id).strip():
            raise HTTPException(status_code=400, detail="fusion_id required")
        if str(fusion_id).strip().lower() == "stats":
            return get_fused_decisions_stats()
        rec = get_fused_decision(str(FUSED_DECISIONS_JSONL), str(fusion_id).strip())
        if rec is None:
            raise HTTPException(status_code=404, detail="Fused decision not found")
        return fused_decision_record_for_api(rec)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("fused-decision lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail=type(exc).__name__) from exc


# ── R3 Digital Twin (read-only observability) ─────────────────────────────────


@app.get("/api/digital-twin/profiles")
def get_digital_twin_profiles():
    """R3 Twin profiles observed in artifacts + default factory (read-only)."""
    try:
        from twin.history import read_twin_profiles_summary

        profiles = read_twin_profiles_summary(str(TWIN_LOGS_DIR))
        return {
            "profiles": profiles,
            "count": len(profiles),
            "control": "READ_ONLY",
            "source": "logs/twin/",
        }
    except Exception as exc:
        logger.warning("digital-twin profiles failed: %s", exc)
        return {
            "profiles": [],
            "count": 0,
            "control": "READ_ONLY",
            "source": "logs/twin/",
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/runs")
def get_digital_twin_runs(limit: int = 20, status: Optional[str] = None):
    """R3 Twin experiment run history (bounded, newest first)."""
    try:
        from twin.history import read_twin_runs

        if limit < 0 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be in [0, 100]")
        runs = read_twin_runs(str(TWIN_LOGS_DIR), limit=limit, status=status)
        return {
            "runs": runs,
            "count": len(runs),
            "control": "READ_ONLY",
            "source": "logs/twin/candidates/",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin runs failed: %s", exc)
        return {
            "runs": [],
            "count": 0,
            "control": "READ_ONLY",
            "source": "logs/twin/candidates/",
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/runs/{run_id}")
def get_digital_twin_run(run_id: str):
    """Single twin experiment run by run_id."""
    try:
        from twin.history import get_twin_run, twin_history_stats

        if not run_id or not str(run_id).strip():
            raise HTTPException(status_code=400, detail="run_id required")
        key = str(run_id).strip()
        if key.lower() == "stats":
            return twin_history_stats(str(TWIN_LOGS_DIR))
        rec = get_twin_run(str(TWIN_LOGS_DIR), key)
        if rec is None:
            raise HTTPException(status_code=404, detail="Twin run not found")
        return rec
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin run lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail=type(exc).__name__) from exc


@app.get("/api/digital-twin/validation")
def get_digital_twin_validation(limit: int = 20):
    """R3 ValidationResult summaries from twin run artifacts."""
    try:
        from twin.history import read_twin_validations

        if limit < 0 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be in [0, 100]")
        results = read_twin_validations(str(TWIN_LOGS_DIR), limit=limit)
        return {
            "results": results,
            "count": len(results),
            "control": "READ_ONLY",
            "source": "logs/twin/candidates/",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin validation failed: %s", exc)
        return {
            "results": [],
            "count": 0,
            "control": "READ_ONLY",
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/datasets")
def get_digital_twin_datasets(limit: int = 20):
    """R3 twin training datasets (manifest summaries)."""
    try:
        from twin.history import read_twin_datasets

        if limit < 0 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be in [0, 100]")
        datasets = read_twin_datasets(str(TWIN_LOGS_DIR), limit=limit)
        return {
            "datasets": datasets,
            "count": len(datasets),
            "control": "READ_ONLY",
            "source": "logs/twin/datasets/",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin datasets failed: %s", exc)
        return {
            "datasets": [],
            "count": 0,
            "control": "READ_ONLY",
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/stats")
def get_digital_twin_stats():
    """R3 twin bounded stats (runs / validations / datasets)."""
    try:
        from twin.history import twin_history_stats

        return twin_history_stats(str(TWIN_LOGS_DIR))
    except Exception as exc:
        logger.warning("digital-twin stats failed: %s", exc)
        return {
            "runs": 0,
            "validations": 0,
            "datasets": 0,
            "snapshots": 0,
            "replays": 0,
            "simulations": 0,
            "control": "READ_ONLY",
            "empty": True,
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/snapshots")
def get_digital_twin_snapshots(limit: int = 20):
    """R3 observational snapshots (read-only)."""
    try:
        from twin.history import read_twin_snapshots

        if limit < 0 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be in [0, 100]")
        rows = read_twin_snapshots(str(TWIN_LOGS_DIR), limit=limit)
        return {
            "snapshots": rows,
            "count": len(rows),
            "control": "READ_ONLY",
            "source": "logs/twin/snapshots/",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin snapshots failed: %s", exc)
        return {
            "snapshots": [],
            "count": 0,
            "control": "READ_ONLY",
            "source": "logs/twin/snapshots/",
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/snapshots/{snapshot_id}")
def get_digital_twin_snapshot(snapshot_id: str):
    """Single observational twin snapshot."""
    try:
        from twin.history import get_twin_snapshot, twin_history_stats

        if not snapshot_id or not str(snapshot_id).strip():
            raise HTTPException(status_code=400, detail="snapshot_id required")
        key = str(snapshot_id).strip()
        if key.lower() == "stats":
            return twin_history_stats(str(TWIN_LOGS_DIR))
        rec = get_twin_snapshot(str(TWIN_LOGS_DIR), key)
        if rec is None:
            raise HTTPException(status_code=404, detail="Twin snapshot not found")
        return rec
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin snapshot lookup failed: %s", exc)
        raise HTTPException(status_code=500, detail=type(exc).__name__) from exc


@app.get("/api/digital-twin/replays")
def get_digital_twin_replays(limit: int = 20):
    """R3 scenario replay results (read-only)."""
    try:
        from twin.history import read_twin_replays

        if limit < 0 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be in [0, 100]")
        rows = read_twin_replays(str(TWIN_LOGS_DIR), limit=limit)
        return {
            "replays": rows,
            "count": len(rows),
            "control": "READ_ONLY",
            "source": "logs/twin/replays/",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin replays failed: %s", exc)
        return {
            "replays": [],
            "count": 0,
            "control": "READ_ONLY",
            "error": type(exc).__name__,
        }


@app.get("/api/digital-twin/simulations")
def get_digital_twin_simulations(limit: int = 20):
    """R3 what-if simulations (read-only)."""
    try:
        from twin.history import read_twin_simulations

        if limit < 0 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be in [0, 100]")
        rows = read_twin_simulations(str(TWIN_LOGS_DIR), limit=limit)
        return {
            "simulations": rows,
            "count": len(rows),
            "control": "READ_ONLY",
            "source": "logs/twin/simulations/",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("digital-twin simulations failed: %s", exc)
        return {
            "simulations": [],
            "count": 0,
            "control": "READ_ONLY",
            "error": type(exc).__name__,
        }


@app.get("/api/blocklist")
def get_blocklist(n: int = 20):
    """Return recent mitigation block actions."""
    rows = read_csv_tail(MITIGATION_CSV, n=n)
    blocks = [
        {
            "timestamp"  : r.get("timestamp", ""),
            "action"     : r.get("action", "BLOCK"),
            "dpid"       : r.get("dpid", "?"),
            "src_mac"    : r.get("src_mac", ""),
            "dst_mac"    : r.get("dst_mac", ""),
            "block_type" : r.get("block_type", "SRC_MAC"),
            "attack_hint": r.get("attack_hint", "UNKNOWN"),
            "confidence" : safe_float(r.get("confidence", 0)),
            "timeout_sec": safe_float(r.get("timeout_sec", 60)),
            "status"     : r.get("status", "SUCCESS"),
        }
        for r in reversed(rows)
    ]
    summary = read_json_safe(MIT_SUMMARY)
    return {"blocks": blocks, "summary": summary}


@app.get("/api/rl")
def get_rl(n: int = 60):
    """Return RL adaptive threshold history."""
    rows = read_csv_tail(RL_CSV, n=n)
    if not rows:
        return {"points": [], "latest": None}

    points = [
        {
            "timestamp"     : r.get("timestamp", ""),
            "cycle"         : int(safe_float(r.get("cycle", 0))),
            "pkt_threshold" : safe_float(r.get("pkt_threshold", 500)),
            "byte_threshold": safe_float(r.get("byte_threshold", 500000)),
            "conf_threshold": safe_float(r.get("conf_threshold", 0.80)),
            "reward"        : safe_float(r.get("reward", 0)),
            "ml_label"      : r.get("ml_label", "NORMAL"),
            "pkt_rate_mean" : safe_float(r.get("pkt_rate_mean", 0)),
        }
        for r in rows
    ]

    return {"points": points, "latest": points[-1] if points else None}


@app.get("/api/drift")
def get_drift(n: int = 20):
    """Return recent ADWIN concept drift events."""
    rows = read_csv_tail(DRIFT_CSV, n=n)
    events = [
        {
            "timestamp" : r.get("timestamp", ""),
            "metric"    : r.get("metric_name", ""),
            "switch_id" : r.get("switch_id", "?"),
            "old_mean"  : safe_float(r.get("old_mean", 0)),
            "new_mean"  : safe_float(r.get("new_mean", 0)),
            "delta"     : safe_float(r.get("delta_mean", 0)),
            "total_seen": int(safe_float(r.get("total_seen", 0))),
        }
        for r in reversed(rows)
    ]
    return {"events": events, "total": len(events)}


@app.get("/api/ml")
def get_ml(n: int = 60):
    """Return recent ML prediction cycles."""
    rows = read_csv_tail(ML_PRED_CSV, n=n)
    points = [
        {
            "timestamp"     : r.get("timestamp", ""),
            "switch_id"     : r.get("switch_id", "?"),
            "status"        : r.get("status", "NORMAL"),
            "confidence"    : safe_float(r.get("confidence", 0)),
            "iso_score"     : safe_float(r.get("iso_score", 0)),
            "dt_label"      : r.get("dt_label", ""),
            "attack_hint"   : r.get("attack_type_hint", ""),
            "entropy_score" : safe_float(r.get("entropy_score", 1)),
            "packet_rate"   : safe_float(r.get("packet_rate_mean", 0)),
        }
        for r in rows
    ]
    return {"points": points, "latest": points[-1] if points else None}


@app.get("/api/metrics")
def get_metrics():
    """Return cached or freshly computed experiment metrics."""
    report_path = _LOGS / "metrics_report.json"
    if report_path.exists():
        return read_json_safe(report_path)
    try:
        import sys
        scripts_dir = str(_ROOT / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from compute_metrics import build_report
        return build_report(str(_LOGS))
    except Exception as e:
        logger.warning("Metrics unavailable: %s", e)
        return {"summary": {}, "runs": [], "error": str(e)}


@app.get("/api/summary")
def get_summary():
    """Single-call summary for the dashboard stat cards."""
    mit_summary = read_json_safe(MIT_SUMMARY)
    cluster     = read_json_safe(CLUSTER_SUMMARY)

    # Count Entropy Alerts
    try:
        with open(ALERTS_CSV, "r", encoding="utf-8") as f:
            total_alerts = max(0, sum(1 for _ in f) - 1)
    except Exception:
        total_alerts = 0

    # Count ML Attacks from predictions log
    try:
        ml_rows = read_csv_tail(ML_PRED_CSV, n=10000)
        total_attacks = sum(
            1 for r in ml_rows
            if str(r.get("status", "")).upper() == "ATTACK"
        )
    except Exception:
        total_attacks = 0

    # Extract latest stats from Mitigation summary sessions array
    mit_sessions = mit_summary.get("sessions", [])
    total_blocks  = mit_sessions[-1].get("total_blocks_ever", 0) if mit_sessions else 0
    active_blocks = mit_sessions[-1].get("currently_blocked", 0) if mit_sessions else 0

    ent_rows = read_csv_tail(ENTROPY_CSV, n=1)
    latest_entropy = safe_float(ent_rows[-1].get("entropy_score", 1.0)) if ent_rows else 1.0
    entropy_status = ent_rows[-1].get("status", "NORMAL") if ent_rows else "UNKNOWN"

    rl_rows = read_csv_tail(RL_CSV, n=1)
    pkt_thresh  = safe_float(rl_rows[-1].get("pkt_threshold",  500))    if rl_rows else 500
    byte_thresh = safe_float(rl_rows[-1].get("byte_threshold", 500000)) if rl_rows else 500000

    return {
        "total_alerts"  : total_alerts,
        "total_attacks" : total_attacks,
        "total_blocks"  : total_blocks,
        "active_blocks" : active_blocks,
        "entropy_score" : round(latest_entropy, 4),
        "entropy_status": entropy_status,
        "pkt_threshold" : pkt_thresh,
        "byte_threshold": byte_thresh,
        "cluster_count" : cluster.get("n_clusters", 0),
        # Dashboard display must be in IST (UTC+05:30)
        "server_time"   : datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Master Control API ────────────────────────────────────────────────────────

class BatchScenarioRequest(BaseModel):
    scenario_ids: List[str] = ["3", "4", "5"]
    archive_first: bool = True
    restart_controller: bool = True


@app.get("/api/control/status")
def control_status():
    """Controller + job runner status for the master control panel."""
    return panel.status()


@app.get("/api/control/jobs")
def control_jobs():
    return {"jobs": panel.list_jobs()}


@app.get("/api/control/jobs/{job_id}")
def control_job(job_id: str):
    job = panel.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job.to_dict(tail=200)


@app.post("/api/control/archive")
def control_archive():
    """Archive experiment CSV logs to logs/archive/<timestamp>/."""
    return panel.archive_logs()


@app.post("/api/control/controller/restart")
def control_restart_controller():
    job = panel.restart_controller()
    return {"ok": True, "job": job.to_dict()}


@app.post("/api/control/controller/stop")
def control_stop_controller():
    return panel.stop_controller()


@app.post("/api/control/scenario/{scenario_id}")
def control_run_scenario(scenario_id: str):
    try:
        job = panel.run_scenario(scenario_id)
        return {"ok": True, "job": job.to_dict()}
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/control/scenarios/batch")
def control_run_batch(body: BatchScenarioRequest):
    try:
        job = panel.run_scenario_batch(
            body.scenario_ids,
            archive_first=body.archive_first,
            restart_controller=body.restart_controller,
        )
        return {"ok": True, "job": job.to_dict()}
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/control/metrics")
def control_compute_metrics():
    job = panel.compute_metrics()
    return {"ok": True, "job": job.to_dict()}


@app.post("/api/control/bundle")
def control_bundle_experiment():
    job = panel.bundle_experiment()
    return {"ok": True, "job": job.to_dict()}


@app.post("/api/control/train")
def control_train_models():
    job = panel.train_models()
    return {"ok": True, "job": job.to_dict()}


# ── Online AutoML API Endpoints ───────────────────────────────────────────────

from online_automl.service import automl_service


@app.get("/api/automl/status")
def get_automl_status():
    """Return Online AutoML current status, champion model, candidates, and triggers."""
    return automl_service.get_status()


@app.post("/api/automl/run")
def run_automl():
    """Trigger an Online AutoML training, evaluation, and promotion pipeline run."""
    report = automl_service.run_automl_pipeline(force=True)
    return {"ok": True, "data": report}


@app.post("/api/automl/rollback")
def rollback_automl():
    """Rollback champion model to previous candidate."""
    restored, reason = automl_service.rollback()
    return {
        "ok": restored is not None,
        "reason": reason,
        "restored_champion": restored.algorithm_name if restored else None,
    }

# ── Email Alert Notification API Endpoints ────────────────────────────────────


def _client_ip(request: Request) -> str:
    """Best-effort client key for rate limiting (never a credential)."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    if request.client:
        return (request.client.host or "unknown")[:64]
    return "unknown"


async def _test_email_principal(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    is_session: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
):
    """
    Conditional authentication for the test-email endpoint.

    When authentication is configured (INTELLISHIELD_AUTH_* present), an
    authenticated principal is required (401 otherwise). When auth is not
    configured, the lab default remains open (matching /api/control/*).
    Client-supplied role/permission headers are never trusted.
    """
    cfg = load_auth_config()
    principal = resolve_principal(
        request, authorization=authorization, session_cookie=is_session
    )
    if cfg.configured and principal is None:
        raise authentication_required()
    return principal


@app.get("/api/alerts/email/status")
def get_email_alert_status():
    """Return current email alert configuration status (passwords omitted)."""
    from alerts import load_email_alert_config
    cfg = load_email_alert_config()
    return {
        "enabled": cfg.enabled,
        "is_configured": cfg.is_configured,
        "recipient": cfg.recipient if cfg.is_configured else "(unconfigured)",
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "smtp_user": cfg.smtp_user if cfg.is_configured else "(unconfigured)",
        "cooldown_seconds": cfg.cooldown_seconds,
        "recovery_enabled": cfg.recovery_enabled,
    }


class TestEmailRequest(BaseModel):
    """Optional label identifying which Control Lab action
    triggered the test email (e.g. "S2 SYN Flood")."""

    label: Optional[str] = Field(default=None, max_length=128)


@app.post("/api/alerts/test-email")
async def trigger_test_email(
    request: Request,
    body: Optional[TestEmailRequest] = None,
    principal=Depends(_test_email_principal),
):
    """
    Send a diagnostic test email to ALERT_EMAIL_TO using current .env config.

    Reuses the existing EmailNotificationAdapter + SMTP config. Waits for the
    actual terminal SMTP outcome (never reports success merely because a
    background thread started). Does not create or persist any security alert.

    An optional ``label`` (e.g. "S2 SYN Flood") is surfaced in the
    email's Detection Source field and message body.
    """
    from alerts.test_email import send_test_email

    label = body.label if body is not None else None
    result = send_test_email(client_key=_client_ip(request), label=label)
    status = result.get("status")
    if status == "RATE_LIMITED":
        return JSONResponse(status_code=429, content=result)
    # SENT / FAILED / UNCONFIGURED / SUPPRESSED / TIMEOUT / ERROR all return
    # HTTP 200 with a truthful "ok" flag and sanitized "status" + "message".
    return JSONResponse(status_code=200, content=result)


# Phase 1 SOC static assets (CSS/JS modules). Mounted after API routes.
_SOC_DIR = _STATIC / "soc"
if _SOC_DIR.is_dir():
    app.mount("/soc", StaticFiles(directory=str(_SOC_DIR)), name="soc_assets")


# ── Launch ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host      = "0.0.0.0",
        port      = 8080,
        reload    = False,
        log_level = "info",
        app_dir   = str(_HERE),
    )
