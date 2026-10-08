"""
Attack-type hint classification for ML explanations and mitigation logging.

Uses feature/entropy patterns first. In the Mininet lab, optionally resolves
against active rows in logs/attack_logs.csv when a timestamp is provided.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ml_models.feature_builder import FEATURE_NAMES

_TS_FMT = "%Y-%m-%d %H:%M:%S"
_ACTIVE_ATTACK_STATUSES = {"LAUNCHED", "RUNNING"}
_SKIP_ATTACK_TYPES = {"ALL", ""}


def _parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime((value or "").strip(), _TS_FMT)
    except (TypeError, ValueError):
        return None


def _feat_dict(vector: List[float]) -> Dict[str, float]:
    return {name: float(vector[i]) for i, name in enumerate(FEATURE_NAMES)}


def _bytes_per_packet(pkt_rate: float, byte_rate: float) -> float:
    if pkt_rate <= 0:
        return 0.0
    return byte_rate / pkt_rate


def _dominant_flow_ratio(flow_features: Optional[List[dict]]) -> float:
    if not flow_features:
        return 0.0
    rates = sorted(
        (float(f.get("packet_rate", 0.0)) for f in flow_features),
        reverse=True,
    )
    if len(rates) < 2:
        return 0.0
    return rates[0] / max(rates[1], 0.001)


def resolve_attack_hint_from_lab_logs(
    timestamp: str,
    logs_dir: str = "logs",
    grace_sec: float = 2.0,
) -> Optional[str]:
    """
    Return the active attack_type from attack_logs.csv when the timestamp
    falls inside a launched attack window (lab ground truth).
    """
    path = os.path.join(logs_dir, "attack_logs.csv")
    if not timestamp or not os.path.exists(path):
        return None

    event_ts = _parse_ts(timestamp)
    if event_ts is None:
        return None

    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    rows.sort(key=lambda r: _parse_ts(r.get("timestamp", "")) or datetime.min)

    active: List[dict] = []
    for row in rows:
        row_ts = _parse_ts(row.get("timestamp", ""))
        if row_ts is None or row_ts > event_ts:
            continue

        attack_type = (row.get("attack_type") or "").strip()
        status = (row.get("status") or "").strip().upper()

        if status in _ACTIVE_ATTACK_STATUSES and attack_type not in _SKIP_ATTACK_TYPES:
            try:
                duration = max(1, int(float(row.get("duration") or 0)))
            except (TypeError, ValueError):
                duration = 30
            active = [a for a in active if a["type"] != attack_type]
            active.append({
                "type": attack_type,
                "start": row_ts,
                "end": row_ts + timedelta(seconds=duration + grace_sec),
            })
        elif status in {"STOPPED", "ERROR"}:
            if attack_type == "ALL":
                active.clear()
            else:
                active = [a for a in active if a["type"] != attack_type]

    matches = [
        a["type"] for a in active
        if a["start"] - timedelta(seconds=grace_sec) <= event_ts <= a["end"]
    ]
    if not matches:
        return None
    if "BURST" in matches:
        return "BURST"
    return matches[-1]


def classify_attack_type(
    vector: List[float],
    *,
    status: str = "ATTACK",
    entropy_metrics: Optional[dict] = None,
    flow_features: Optional[List[dict]] = None,
    timestamp: Optional[str] = None,
    logs_dir: Optional[str] = None,
) -> str:
    """
    Classify attack type from features/entropy. Lab logs override when active.
    """
    if status == "NORMAL":
        return "NORMAL"

    if timestamp and logs_dir:
        lab_hint = resolve_attack_hint_from_lab_logs(timestamp, logs_dir)
        if lab_hint:
            return lab_hint

    feat = _feat_dict(vector)
    ent = entropy_metrics or {}

    src_ent = float(feat.get("src_entropy", 1.0))
    dst_ent = float(feat.get("dst_entropy", 1.0))
    pkt_ent = float(feat.get("packet_entropy", ent.get("packet_entropy", 1.0)))
    byte_ent = float(feat.get("byte_entropy", ent.get("byte_entropy", 1.0)))
    pkt_rate = float(feat.get("packet_rate_mean", 0.0))
    pkt_max = float(feat.get("packet_rate_max", 0.0))
    byt_rate = float(feat.get("byte_rate_mean", 0.0))
    flow_count = float(feat.get("flow_count", 5.0))
    concentration = float(feat.get("flow_concentration", 0.0))
    bpp = _bytes_per_packet(pkt_rate, byt_rate)
    spike_ratio = (pkt_max / max(pkt_rate, 1.0)) if pkt_max > 0 else 0.0
    dom_ratio = _dominant_flow_ratio(flow_features)

    # Short high-rate burst (S4): peak >> mean, brief dominance
    if pkt_max > 2000 and spike_ratio >= 2.5 and flow_count <= 8:
        return "BURST"
    if dom_ratio >= 8.0 and pkt_max > 1500 and flow_count <= 5:
        return "BURST"

    # UDP flood: bandwidth-heavy, large payloads, byte entropy collapses first
    if (
        byt_rate >= 400_000
        and bpp >= 180
        and (byte_ent <= 0.35 or dst_ent <= 0.35 or pkt_ent <= 0.35)
    ):
        return "UDP_FLOOD"
    if byt_rate >= 800_000 and bpp >= 120:
        return "UDP_FLOOD"

    # ICMP flood: many small packets, moderate bytes/packet
    if (
        pkt_rate >= 1500
        and bpp <= 120
        and byt_rate <= 600_000
        and concentration >= 0.55
        and src_ent <= 0.4
    ):
        return "ICMP_FLOOD"

    # SYN flood: packet-heavy, small payloads, source/packet entropy collapse
    if (
        pkt_rate >= 800
        and bpp <= 180
        and src_ent <= 0.4
        and pkt_ent <= 0.35
        and flow_count <= 10
    ):
        return "SYN_FLOOD"
    if pkt_max > 500 and src_ent < 0.35 and flow_count <= 5 and bpp <= 200:
        return "SYN_FLOOD"

    if dst_ent <= 0.25 and pkt_rate >= 500 and bpp <= 150:
        return "SYN_FLOOD"

    # Distributed / multi-flow volumetric
    if concentration > 0.6 or (pkt_rate >= 500 and byte_ent <= 0.3):
        return "VOLUMETRIC_FLOOD"

    return "UNKNOWN_ANOMALY"
