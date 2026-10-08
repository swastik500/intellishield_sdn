"""
R4.1 — Audited signal inventory (repository ground truth).

Each descriptor documents a signal the correlator *may* consume when present.
No L7 / HTTP / DNS / host-kernel claims.
Normalization classes are design-only in R4.1 (no transforms applied).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from correlation.categories import CATEGORY_RATIONALE, SignalCategory
from correlation.normalization import NormalizationClass


@dataclass(frozen=True)
class SignalDescriptor:
    """Inventory entry — not a live reading."""

    signal_key: str
    category: SignalCategory
    source: str
    name: str
    producer: str
    unit: str
    value_range: str
    timestamp_source: str
    update_frequency: str
    identity_fields: Tuple[str, ...]
    persistence: str
    runtime_live: bool
    reliability: str
    correlation_use: str
    normalization: NormalizationClass
    notes: str = ""
    claimed_layer_forbidden: bool = False


def _d(
    key: str,
    cat: SignalCategory,
    source: str,
    name: str,
    producer: str,
    unit: str,
    value_range: str,
    ts: str,
    freq: str,
    identity: Tuple[str, ...],
    persistence: str,
    live: bool,
    reliability: str,
    use: str,
    norm: NormalizationClass,
    notes: str = "",
) -> SignalDescriptor:
    return SignalDescriptor(
        signal_key=key,
        category=cat,
        source=source,
        name=name,
        producer=producer,
        unit=unit,
        value_range=value_range,
        timestamp_source=ts,
        update_frequency=freq,
        identity_fields=identity,
        persistence=persistence,
        runtime_live=live,
        reliability=reliability,
        correlation_use=use,
        normalization=norm,
        notes=notes,
    )


# Audited 2026-07-27 against controller/flow_monitor, entropy_engine, ml_models,
# advanced_analytics, rl_engine, mitigation, verification, alerting, rca.
# monitoring/ directory: absent.
SIGNAL_INVENTORY: Tuple[SignalDescriptor, ...] = (
    # ── DATA PLANE ──────────────────────────────────────────────────────────
    _d(
        "flow_stats.packet_rate", SignalCategory.DATA_PLANE, "flow_stats", "packet_rate",
        "controller.flow_monitor._extract_flow_features",
        "pkt/s", "≥0", "local wall (cycle)", "~5s / flow",
        ("src_mac", "dst_mac", "switch_id", "in_port"), "logs/flow_stats.csv",
        True, "HIGH", "Volume anomaly co-evidence",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "flow_stats.byte_rate", SignalCategory.DATA_PLANE, "flow_stats", "byte_rate",
        "controller.flow_monitor._extract_flow_features",
        "B/s", "≥0", "local wall (cycle)", "~5s / flow",
        ("src_mac", "dst_mac", "switch_id", "in_port"), "logs/flow_stats.csv",
        True, "HIGH", "Volume anomaly co-evidence",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "flow_stats.packet_count", SignalCategory.DATA_PLANE, "flow_stats", "packet_count",
        "controller.flow_monitor._extract_flow_features",
        "packets", "≥0 cumulative", "local wall (cycle)", "~5s / flow",
        ("src_mac", "dst_mac", "switch_id"), "logs/flow_stats.csv",
        True, "HIGH", "Prefer rates over cumulative",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
        notes="Cumulative OF counter; use deltas/rates for correlation.",
    ),
    _d(
        "flow_stats.byte_count", SignalCategory.DATA_PLANE, "flow_stats", "byte_count",
        "controller.flow_monitor._extract_flow_features",
        "bytes", "≥0 cumulative", "local wall (cycle)", "~5s / flow",
        ("src_mac", "dst_mac", "switch_id"), "logs/flow_stats.csv",
        True, "HIGH", "Prefer rates over cumulative",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
    ),
    _d(
        "flow_stats.duration_sec", SignalCategory.DATA_PLANE, "flow_stats", "duration_sec",
        "controller.flow_monitor._extract_flow_features",
        "s", "≥0", "local wall (cycle)", "~5s / flow",
        ("src_mac", "dst_mac", "switch_id"), "logs/flow_stats.csv",
        True, "MEDIUM", "Flow longevity context",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "flow_stats.active_flow_count", SignalCategory.DATA_PLANE, "flow_stats", "active_flow_count",
        "controller.flow_monitor feature_batch length",
        "count", "≥0", "local wall (cycle)", "~5s / switch",
        ("switch_id",), "logs/ml_features.csv / rl_decisions.csv",
        True, "HIGH", "Flow growth / flash crowd co-evidence",
        NormalizationClass.REQUIRES_BASELINE,
        notes="Derived per cycle; not a dedicated CSV column.",
    ),
    _d(
        "port_stats.rx_packets", SignalCategory.DATA_PLANE, "port_stats", "rx_packets",
        "controller.flow_monitor._port_stats_reply_handler",
        "packets", "≥0 cumulative", "local wall (cycle)", "~5s / port",
        ("switch_id", "port_no"), "logs/port_stats.csv",
        True, "HIGH", "Port-level volume (via deltas)",
        NormalizationClass.REQUIRES_BASELINE,
        notes="Cumulative; deltas needed for rates.",
    ),
    _d(
        "port_stats.tx_packets", SignalCategory.DATA_PLANE, "port_stats", "tx_packets",
        "controller.flow_monitor._port_stats_reply_handler",
        "packets", "≥0 cumulative", "local wall (cycle)", "~5s / port",
        ("switch_id", "port_no"), "logs/port_stats.csv",
        True, "HIGH", "Port-level volume (via deltas)",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "port_stats.rx_bytes", SignalCategory.DATA_PLANE, "port_stats", "rx_bytes",
        "controller.flow_monitor._port_stats_reply_handler",
        "bytes", "≥0 cumulative", "local wall (cycle)", "~5s / port",
        ("switch_id", "port_no"), "logs/port_stats.csv",
        True, "HIGH", "Port-level volume (via deltas)",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "port_stats.tx_bytes", SignalCategory.DATA_PLANE, "port_stats", "tx_bytes",
        "controller.flow_monitor._port_stats_reply_handler",
        "bytes", "≥0 cumulative", "local wall (cycle)", "~5s / port",
        ("switch_id", "port_no"), "logs/port_stats.csv",
        True, "HIGH", "Port-level volume (via deltas)",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "port_stats.rx_errors", SignalCategory.DATA_PLANE, "port_stats", "rx_errors",
        "controller.flow_monitor._port_stats_reply_handler",
        "errors", "≥0 cumulative", "local wall (cycle)", "~5s / port",
        ("switch_id", "port_no"), "logs/port_stats.csv",
        True, "MEDIUM", "Loss / error co-evidence",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    _d(
        "port_stats.tx_errors", SignalCategory.DATA_PLANE, "port_stats", "tx_errors",
        "controller.flow_monitor._port_stats_reply_handler",
        "errors", "≥0 cumulative", "local wall (cycle)", "~5s / port",
        ("switch_id", "port_no"), "logs/port_stats.csv",
        True, "MEDIUM", "Loss / error co-evidence",
        NormalizationClass.REQUIRES_BASELINE,
    ),
    # ── CONTROL PLANE ───────────────────────────────────────────────────────
    _d(
        "controller_stats.cpu_percent", SignalCategory.CONTROL_PLANE, "controller_stats", "cpu_percent",
        "controller.flow_monitor._log_controller_stats",
        "percent", "0–100", "local wall (cycle)", "~5s",
        (), "logs/controller_stats.csv",
        True, "MEDIUM", "Controller stress co-evidence",
        NormalizationClass.UNIT_INTERVAL_FROM_PERCENT,
        notes="Optional psutil; ImportError → NOT_AVAILABLE.",
    ),
    _d(
        "controller_stats.memory_rss_mb", SignalCategory.CONTROL_PLANE, "controller_stats", "memory_rss_mb",
        "controller.flow_monitor._log_controller_stats",
        "MB", "≥0", "local wall (cycle)", "~5s",
        (), "logs/controller_stats.csv",
        True, "MEDIUM", "Controller memory pressure",
        NormalizationClass.REQUIRES_BASELINE,
        notes="Optional psutil.",
    ),
    _d(
        "controller_stats.memory_percent", SignalCategory.CONTROL_PLANE, "controller_stats", "memory_percent",
        "controller.flow_monitor._log_controller_stats",
        "percent", "0–100", "local wall (cycle)", "~5s",
        (), "logs/controller_stats.csv",
        True, "MEDIUM", "Controller memory pressure",
        NormalizationClass.UNIT_INTERVAL_FROM_PERCENT,
        notes="Optional psutil.",
    ),
    _d(
        "rl.thresholds", SignalCategory.CONTROL_PLANE, "rl", "thresholds",
        "rl_engine.ThresholdAdapter.apply_action / RLLogger.log_decision",
        "mixed", "pkt/byte/conf ranges per config", "ISO local", "~5s",
        ("switch_id",), "logs/rl_decisions.csv",
        True, "MEDIUM", "Policy-state context (not attack evidence alone)",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
        notes="Adapts warn/mitigation gates; treat as control policy state.",
    ),
    _d(
        "rl.action", SignalCategory.CONTROL_PLANE, "rl", "action",
        "rl_engine / RLLogger.log_decision",
        "vector", "action ∈ [-1,1]³", "ISO local", "~5s",
        ("switch_id",), "logs/rl_decisions.csv",
        True, "MEDIUM", "Policy change co-occurrence",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
    ),
    # ── DETECTION ───────────────────────────────────────────────────────────
    _d(
        "entropy.src_entropy", SignalCategory.DETECTION, "entropy", "src_entropy",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "nats_norm", "[0,1]", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Per-dimension collapse evidence",
        NormalizationClass.ALREADY_NORMALIZED,
        notes="Low value = anomalous; invert for 'attackness' in R4.2.",
    ),
    _d(
        "entropy.dst_entropy", SignalCategory.DETECTION, "entropy", "dst_entropy",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "nats_norm", "[0,1]", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Per-dimension collapse evidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "entropy.packet_entropy", SignalCategory.DETECTION, "entropy", "packet_entropy",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "nats_norm", "[0,1]", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Per-dimension collapse evidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "entropy.byte_entropy", SignalCategory.DETECTION, "entropy", "byte_entropy",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "nats_norm", "[0,1]", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Per-dimension collapse evidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "entropy.flow_entropy", SignalCategory.DETECTION, "entropy", "flow_entropy",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "nats_norm", "[0,1]", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Per-dimension collapse evidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "entropy.entropy_score", SignalCategory.DETECTION, "entropy", "entropy_score",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "nats_norm", "[0,1]", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Primary entropy detector evidence",
        NormalizationClass.ALREADY_NORMALIZED,
        notes="ALERT typically if score < 0.4 (threshold-relative status).",
    ),
    _d(
        "entropy.status", SignalCategory.DETECTION, "entropy", "status",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "enum", "NORMAL|WARNING|ALERT", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv / detection_alerts.csv",
        True, "HIGH", "Categorical detection agreement",
        NormalizationClass.BINARY_CATEGORICAL,
    ),
    _d(
        "entropy.confidence", SignalCategory.DETECTION, "entropy", "confidence",
        "entropy_engine.entropy_detector.EntropyDetector.analyze",
        "percent", "0–100", "local wall (cycle)", "~5s",
        ("switch_id",), "logs/entropy_logs.csv",
        True, "HIGH", "Detector confidence (P0.1 normalize)",
        NormalizationClass.UNIT_INTERVAL_FROM_PERCENT,
    ),
    _d(
        "ml.status", SignalCategory.DETECTION, "ml", "status",
        "ml_models.anomaly_detector.AnomalyDetector.predict",
        "enum", "NORMAL|SUSPICIOUS|ATTACK", "local wall (cycle)", "~5s post-warmup",
        ("switch_id",), "logs/ml_predictions.csv",
        True, "HIGH", "Primary ML detection agreement",
        NormalizationClass.BINARY_CATEGORICAL,
        notes="Requires trained models.",
    ),
    _d(
        "ml.confidence", SignalCategory.DETECTION, "ml", "confidence",
        "ml_models.anomaly_detector.AnomalyDetector.predict",
        "percent", "0–100", "local wall (cycle)", "~5s post-warmup",
        ("switch_id",), "logs/ml_predictions.csv",
        True, "HIGH", "ML confidence (P0.1 → [0,1])",
        NormalizationClass.UNIT_INTERVAL_FROM_PERCENT,
    ),
    _d(
        "ml.iso_score", SignalCategory.DETECTION, "ml", "iso_score",
        "ml_models.anomaly_detector.AnomalyDetector.predict",
        "score", "~[0,1]", "local wall (cycle)", "~5s post-warmup",
        ("switch_id",), "logs/ml_predictions.csv",
        True, "HIGH", "IsolationForest score evidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "ml.dt_confidence", SignalCategory.DETECTION, "ml", "dt_confidence",
        "ml_models.anomaly_detector.AnomalyDetector.predict",
        "unit", "[0,1]", "local wall (cycle)", "~5s post-warmup",
        ("switch_id",), "logs/ml_predictions.csv",
        True, "HIGH", "DecisionTree confidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "ml.attack_type_hint", SignalCategory.DETECTION, "ml", "attack_type_hint",
        "ml_models.attack_type_classifier / Explainer",
        "enum", "string hint", "local wall", "~5s / on alert",
        ("switch_id",), "logs/ml_predictions.csv / ml_alerts.csv",
        True, "MEDIUM", "Label evidence only (not numeric fusion)",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
        notes="Heuristic — correlation ≠ causation.",
    ),
    _d(
        "ml.feature_vector", SignalCategory.DETECTION, "ml", "feature_vector",
        "ml_models.feature_builder.FeatureBuilder.build",
        "vector", "15 floats", "local wall (cycle)", "~5s post-warmup",
        ("switch_id",), "logs/ml_features.csv",
        True, "HIGH", "Do not average raw features into score",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
    ),
    # ── DRIFT / CLUSTERING (observational) ──────────────────────────────────
    _d(
        "adwin.drift", SignalCategory.DRIFT_CLUSTERING, "adwin", "drift_alert",
        "advanced_analytics.adwin_detector.ADWINManager.update_all",
        "bool+means", "drifted T/F + means", "local wall", "~5s; log on drift",
        ("switch_id", "metric_name"), "logs/drift_alerts.csv",
        True, "MEDIUM", "Concept-drift co-occurrence",
        NormalizationClass.BINARY_CATEGORICAL,
        notes="Observational; does not drive mitigation today.",
    ),
    _d(
        "hdbscan.cluster_label", SignalCategory.DRIFT_CLUSTERING, "hdbscan", "cluster_label",
        "advanced_analytics.hdbscan_clusterer.ClusterManager",
        "enum", "NORMAL|ATTACK|SUSPICIOUS|NOISE", "vector timestamp", "every ~10 cycles (~50s)",
        ("switch_id", "cluster_id"), "logs/cluster_labels.csv",
        True, "MEDIUM", "Cluster outlier co-evidence",
        NormalizationClass.BINARY_CATEGORICAL,
        notes="Observational only.",
    ),
    _d(
        "hdbscan.confidence", SignalCategory.DRIFT_CLUSTERING, "hdbscan", "confidence",
        "advanced_analytics.hdbscan_clusterer._label_cluster",
        "unit", "[0,1]", "vector timestamp", "every ~10 cycles",
        ("switch_id", "cluster_id"), "logs/cluster_labels.csv",
        True, "MEDIUM", "Cluster label confidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    # ── SECURITY RESPONSE ───────────────────────────────────────────────────
    _d(
        "verification.status", SignalCategory.SECURITY_RESPONSE, "verification", "status",
        "verification.engine.VerificationEngine",
        "enum", "PENDING|VERIFIED|REJECTED|INELIGIBLE", "UTC ISO-Z", "on mitigate path",
        ("event_id", "attacker_mac", "victim_mac"), "logs/verification_trace.jsonl",
        True, "HIGH", "R7 outcome co-evidence",
        NormalizationClass.BINARY_CATEGORICAL,
    ),
    _d(
        "verification.mitigation_eligible", SignalCategory.SECURITY_RESPONSE, "verification", "mitigation_eligible",
        "verification.engine.VerificationEngine",
        "bool", "T/F", "UTC ISO-Z", "on mitigate path",
        ("event_id",), "logs/verification_trace.jsonl",
        True, "HIGH", "Eligibility flag",
        NormalizationClass.BINARY_CATEGORICAL,
    ),
    _d(
        "verification.confidence", SignalCategory.SECURITY_RESPONSE, "verification", "confidence",
        "verification.engine.VerificationEngine",
        "unit", "[0,1] optional", "UTC ISO-Z", "on mitigate path",
        ("event_id",), "logs/verification_trace.jsonl",
        True, "HIGH", "Verification confidence",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    _d(
        "alert.severity", SignalCategory.SECURITY_RESPONSE, "alerting", "severity",
        "alerting.manager.AlertManager",
        "enum", "INFO…CRITICAL", "UTC ISO-Z", "on verified path",
        ("alert_id", "event_id"), "logs/alerts.jsonl",
        True, "HIGH", "Optional R8 severity context",
        NormalizationClass.BINARY_CATEGORICAL,
    ),
    _d(
        "alert.type", SignalCategory.SECURITY_RESPONSE, "alerting", "type",
        "alerting.manager.AlertManager",
        "enum", "DETECTION|MITIGATION|…", "UTC ISO-Z", "on verified path",
        ("alert_id", "event_id"), "logs/alerts.jsonl",
        True, "HIGH", "Alert class label",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
    ),
    _d(
        "mitigation.action", SignalCategory.SECURITY_RESPONSE, "mitigation", "block_action",
        "mitigation.mitigation_engine.MitigationEngine",
        "enum", "BLOCK|UNBLOCK|…", "local wall", "event-driven",
        ("dpid", "src_mac", "dst_mac"), "logs/mitigation_actions.csv",
        True, "HIGH", "Mitigation history (response plane)",
        NormalizationClass.BINARY_CATEGORICAL,
    ),
    _d(
        "rca.confidence", SignalCategory.SECURITY_RESPONSE, "rca", "rca_confidence",
        "rca.engine.RootCauseEngine",
        "unit", "[0,1]", "UTC ISO-Z", "on verified enrich",
        ("report_id", "event_id"), "logs/root_cause_reports.jsonl",
        True, "MEDIUM", "Optional RCA ref — R4 must not generate RCA",
        NormalizationClass.ALREADY_NORMALIZED,
    ),
    # ── LAB GT (offline / not controller live correlation input) ────────────
    _d(
        "gt.attack_event", SignalCategory.UNKNOWN, "gt", "attack_event",
        "traffic_logger / scenario scripts",
        "mixed", "type,rate,duration", "local wall", "scenario-driven",
        ("source_host", "target_host"), "logs/attack_logs.csv",
        False, "HIGH (lab)", "Evaluation only — not live correlation input",
        NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION,
        notes="Ground truth for metrics; exclude from live R4.2 fusion by default.",
    ),
)


FORBIDDEN_CLAIMS: Tuple[str, ...] = (
    "application_layer",
    "L7",
    "HTTP",
    "DNS",
    "TLS_SNI",
    "host_kernel",
    "endpoint_EDR",
    "packet_payload",
    "IP_5tuple_in_OF_match",
)


def list_available_signals(
    *,
    runtime_live_only: bool = False,
    category: Optional[SignalCategory] = None,
) -> List[SignalDescriptor]:
    out = []
    for d in SIGNAL_INVENTORY:
        if runtime_live_only and not d.runtime_live:
            continue
        if category is not None and d.category != category:
            continue
        out.append(d)
    return out


def inventory_by_category() -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for d in SIGNAL_INVENTORY:
        grouped.setdefault(d.category.value, []).append(d.signal_key)
    return grouped


def inventory_summary() -> Dict[str, object]:
    return {
        "total_signals": len(SIGNAL_INVENTORY),
        "by_category": {k: len(v) for k, v in inventory_by_category().items()},
        "runtime_live": sum(1 for d in SIGNAL_INVENTORY if d.runtime_live),
        "category_rationale": dict(CATEGORY_RATIONALE),
        "forbidden_claims": list(FORBIDDEN_CLAIMS),
        "output_contract": "shared_contracts.CorrelationResult",
        "input_contracts": ["SignalEvent", "CorrelationWindow", "EntityIdentity"],
        "correlation_engine": "CorrelationEngine (R4.2+)",
        "foundation_correlation_result": "UNCHANGED",
        "production_integration": "R4.3_ADVISORY",
    }
