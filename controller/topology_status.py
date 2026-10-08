"""
Read-only topology snapshot helper (controller → dashboard bridge).

Writes a small JSON file the dashboard can serve via GET /api/topology.
Does NOT discover switch–switch links (LLDP remains unused/disabled).
Does NOT install OpenFlow rules or call mitigation.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

logger = logging.getLogger("intellishield.topology_status")

DEFAULT_FILENAME = "topology_status.json"
SCHEMA_VERSION = 1

# Multicast / special MACs that are not useful as "hosts" in the UI
_SKIP_MAC_PREFIXES = ("ff:ff:ff", "33:33:", "01:00:5e", "01:80:c2")
_SKIP_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def default_topology_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_FILENAME)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_dpid(dpid: int) -> str:
    try:
        return f"{int(dpid):016x}"
    except (TypeError, ValueError):
        return str(dpid)


def _is_display_host_mac(mac: str) -> bool:
    m = (mac or "").strip().lower()
    if not m or m in _SKIP_MACS:
        return False
    for prefix in _SKIP_MAC_PREFIXES:
        if m.startswith(prefix):
            return False
    return True


def build_topology_snapshot(
    *,
    datapath_ids: Iterable[int],
    mac_to_port: Optional[Mapping[Any, Mapping[str, Any]]] = None,
    poll_interval_sec: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Build a JSON-serializable topology snapshot from in-memory controller state.

    Args:
        datapath_ids: Connected switch IDs.
        mac_to_port: Optional {dpid → {mac → port}} learning table.
        poll_interval_sec: Optional monitor interval for clients.
    """
    switches = []
    for dpid in sorted({int(x) for x in datapath_ids}):
        switches.append(
            {
                "dpid": dpid,
                "dpid_hex": _fmt_dpid(dpid),
                "name": f"s{dpid}",
            }
        )

    hosts = []
    links = []
    seen_macs = set()
    if mac_to_port:
        # Collect all learning edges, then unique hosts (primary = first by dpid/port)
        edges = []
        for dpid_raw, table in mac_to_port.items():
            try:
                dpid = int(dpid_raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(table, Mapping):
                continue
            for mac, port in table.items():
                mac_s = str(mac).strip().lower()
                if not _is_display_host_mac(mac_s):
                    continue
                try:
                    port_i = int(port)
                except (TypeError, ValueError):
                    continue
                edges.append((dpid, port_i, mac_s))
        edges.sort(key=lambda e: (e[2], e[0], e[1]))
        for dpid, port_i, mac_s in edges:
            links.append(
                {
                    "src_type": "host",
                    "src": mac_s,
                    "dst_type": "switch",
                    "dst": _fmt_dpid(dpid),
                    "dst_name": f"s{dpid}",
                    "port": port_i,
                }
            )
            if mac_s in seen_macs:
                continue
            seen_macs.add(mac_s)
            hosts.append(
                {
                    "mac": mac_s,
                    "dpid": dpid,
                    "dpid_hex": _fmt_dpid(dpid),
                    "port": port_i,
                    "switch": f"s{dpid}",
                }
            )
        hosts.sort(key=lambda h: (h["dpid"], h["port"], h["mac"]))

    return {
        "schema_version": SCHEMA_VERSION,
        "updated_at": _utc_now_iso(),
        "updated_at_unix": time.time(),
        "controller_connected": True,
        "switch_count": len(switches),
        "host_count": len(hosts),
        "link_count": len(links),
        "switches": switches,
        "hosts": hosts,
        "links": links,
        "limitations": [
            "Host–switch attachments only (from L2 learning).",
            "Switch–switch links are not discovered (LLDP unused).",
            "Hosts appear after they generate traffic.",
            "host_count is unique MACs; links may include the same MAC on multiple switches.",
        ],
        "poll_interval_sec": poll_interval_sec,
        "source": "controller.topology_status",
        "note": "READ ONLY observational snapshot — not authoritative for mitigation.",
    }


def write_topology_snapshot(path: str, snapshot: Dict[str, Any]) -> bool:
    """
    Atomically write topology snapshot JSON.

    Returns True on success, False on failure (never raises to callers).
    """
    try:
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        payload = json.dumps(snapshot, separators=(",", ":"), sort_keys=True)
        fd, tmp = tempfile.mkstemp(prefix=".topology_", suffix=".json", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    except Exception as exc:  # noqa: BLE001 — best-effort boundary
        logger.warning(
            "[topology_status] write failed (%s): %s",
            type(exc).__name__,
            exc,
        )
        return False


def publish_topology_status(
    logs_dir: str,
    *,
    datapath_ids: Iterable[int],
    mac_to_port: Optional[Mapping[Any, Mapping[str, Any]]] = None,
    poll_interval_sec: Optional[float] = None,
    path: Optional[str] = None,
) -> bool:
    """Build + write topology snapshot under logs_dir (or explicit path)."""
    out = path or default_topology_path(logs_dir)
    snap = build_topology_snapshot(
        datapath_ids=datapath_ids,
        mac_to_port=mac_to_port,
        poll_interval_sec=poll_interval_sec,
    )
    # Preserve last-known inventory when live switches disconnect (scenario teardown).
    if snap["switch_count"] == 0 and os.path.isfile(out):
        try:
            with open(out, "r", encoding="utf-8") as fh:
                prev = json.load(fh)
            prev_switches = prev.get("switches") if isinstance(prev.get("switches"), list) else []
            if prev_switches:
                snap["last_known"] = {
                    "updated_at": prev.get("updated_at"),
                    "switch_count": prev.get("switch_count", len(prev_switches)),
                    "host_count": prev.get("host_count", 0),
                    "switches": prev_switches,
                    "hosts": prev.get("hosts") if isinstance(prev.get("hosts"), list) else [],
                    "links": prev.get("links") if isinstance(prev.get("links"), list) else [],
                    "note": "Last known while no switches are currently connected.",
                }
            elif isinstance(prev.get("last_known"), dict):
                snap["last_known"] = prev["last_known"]
        except Exception:
            pass
    snap["connection_state"] = (
        "CONNECTED" if snap["switch_count"] > 0 else "NO_SWITCHES"
    )
    return write_topology_snapshot(out, snap)
