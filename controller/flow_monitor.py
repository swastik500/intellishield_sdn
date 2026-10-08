"""
================================================================================
IntelliShield SDN — Phase 1: Flow Statistics Monitoring Engine
================================================================================

File        : controller/flow_monitor.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 1 — OpenFlow Flow Statistics Monitoring

Description:
    This OsKen SDN controller continuously polls OpenFlow flow and port
    statistics from all connected switches, extracts per-flow traffic
    features, and logs them to both console and CSV for research analysis.

Architecture Notes:
    - Extends OsKen AppManager as a proper SDN application
    - Uses OpenFlow 1.3 (ofproto_v1_3) for standard statistics requests
    - Background monitoring thread polls all registered datapaths every 5s
    - Stateless flow tracking: each poll computes instantaneous metrics

Future Integration Points:
    - [HOOK] entropy_engine/entropy_calculator.py  → Shannon entropy on IPs
    - [HOOK] ml_models/hdbscan_profiler.py         → Cluster traffic profiles
    - [HOOK] rl_engine/ppo_threshold.py            → Adaptive thresholds
    - [HOOK] mitigation/flow_blocker.py            → Block malicious flows
    - [HOOK] monitoring/adwin_detector.py          → Concept drift detection

IEEE Relevance:
    Implements continuous OpenFlow-based telemetry — the observable
    foundation layer of any SDN anomaly detection research pipeline.

Usage:
    osken-manager ~/intellishield-sdn/controller/flow_monitor.py

================================================================================
"""

# ─── Standard Library ────────────────────────────────────────────────────────
import os
import sys
import csv
import time
import traceback
import numpy as np                        # required by Phase 7 RL hook (np.mean)
from datetime import datetime
from collections import defaultdict

# ─── Path Fix ────────────────────────────────────────────────────────────────
# Ensures sibling packages (entropy_engine, ml_models, mitigation,
# advanced_analytics) are importable whether osken-manager is invoked from
# ~/intellishield-sdn/ or ~/intellishield-sdn/controller/.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ─── OsKen SDN Framework ─────────────────────────────────────────────────────
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ipv4, arp

# ─── Phase 2: Entropy Detection Engine ───────────────────────────────────────
# [HOOK] entropy_engine — integrated from Phase 2
try:
    from entropy_engine import EntropyDetector
    from entropy_engine.entropy_detector import (
        SRC_ENTROPY_THRESHOLD,
        DST_ENTROPY_THRESHOLD,
        PACKET_ENTROPY_THRESHOLD,
        BYTE_ENTROPY_THRESHOLD,
    )
    _ENTROPY_AVAILABLE = True
except ImportError:
    _ENTROPY_AVAILABLE = False

# ─── Phase 4: ML Anomaly Detection Engine ────────────────────────────────────
# [HOOK] ml_models — integrated from Phase 4
try:
    from ml_models.anomaly_detector import AnomalyDetector
    from ml_models.feature_builder  import FeatureBuilder, FEATURE_NAMES
    from ml_models.explainer        import Explainer
    from ml_models.attack_type_classifier import classify_attack_type
    from ml_models.ml_logger        import (
        init_ml_logs, log_prediction, log_ml_alert, print_ml_result
    )
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

# ─── Phase 5: Automated Mitigation Engine ─────────────────────────────────
# [HOOK] mitigation — integrated from Phase 5
try:
    from mitigation.mitigation_engine import (
        MitigationEngine,
        ATTACK_RATE_THRESHOLD,
        RATE_DOMINANCE_RATIO,
        _collapse_flow_pairs,
    )
    from mitigation.flow_blocker import BLOCK_PRIORITY
    _MITIGATION_AVAILABLE = True
except ImportError:
    _MITIGATION_AVAILABLE = False
    BLOCK_PRIORITY = 200
    ATTACK_RATE_THRESHOLD = 1000.0
    RATE_DOMINANCE_RATIO = 5.0

    def _collapse_flow_pairs(flow_features):
        pairs = {}
        for flow in flow_features:
            src = flow.get("src_mac", "")
            dst = flow.get("dst_mac", "")
            if not src or not dst:
                continue
            key = (src, dst)
            rate = float(flow.get("packet_rate", 0))
            if key not in pairs or rate > float(pairs[key].get("packet_rate", 0)):
                pairs[key] = {**flow, "packet_rate": rate}
        return list(pairs.values())

# ─── Read-only topology status (dashboard GET /api/topology) ───────────────
try:
    from controller.topology_status import publish_topology_status
    _TOPOLOGY_STATUS_AVAILABLE = True
except ImportError:
    try:
        from topology_status import publish_topology_status  # type: ignore
        _TOPOLOGY_STATUS_AVAILABLE = True
    except ImportError:
        _TOPOLOGY_STATUS_AVAILABLE = False
        publish_topology_status = None  # type: ignore

# ─── Requirement R7: Multi-stage VerificationEngine (runtime gate) ────────
# [HOOK] verification — R7.3; detectors + MitigationEngine unchanged
try:
    from verification.config import VerificationConfig
    from verification.engine import VerificationEngine
    from verification.runtime import run_verified_mitigation
    from verification.trace import default_trace_path
    _VERIFICATION_AVAILABLE = True
except ImportError:
    _VERIFICATION_AVAILABLE = False

# ─── Requirement R8: AlertManager (post-verify notify; independent of mitigate)
try:
    from alerting import AlertManager, AlertingConfig, LoggingNotificationAdapter
    from alerting.runtime import (
        build_runtime_alert_context,
        safe_emit_verification_alert,
    )
    _ALERTING_AVAILABLE = True
except ImportError:
    _ALERTING_AVAILABLE = False

# ─── Requirement R5: XAI + RCA enrichment (post-verify; fail-isolated) ────
try:
    from rca import (
        JsonlRCAStore,
        RCAConfig,
        default_rca_jsonl_path,
        safe_enrich_verified_event,
    )
    _RCA_AVAILABLE = True
except ImportError:
    _RCA_AVAILABLE = False

# ─── Requirement R4: Cross-Layer Correlation (advisory; fail-isolated) ────
try:
    from correlation import (
        CorrelationEngine,
        CorrelationRuntimeConfig,
        JsonlCorrelationStore,
        default_correlation_jsonl_path,
        safe_correlate_cycle,
    )
    _CORRELATION_AVAILABLE = True
except ImportError:
    _CORRELATION_AVAILABLE = False

# ─── Requirement R6: Collaborative Fusion → R7 (fail-isolated) ───────────
try:
    from fusion.runtime import (
        prepare_collaborative_cycle,
        r6_fusion_enabled_from_env,
        link_verification_to_fusion_trace,
    )
    from fusion.trace import default_fusion_trace_path
    from fusion.engine import CollaborativeFusionEngine
    _FUSION_AVAILABLE = True
except ImportError:
    _FUSION_AVAILABLE = False

# ─── Phase 6: HDBSCAN Clustering + ADWIN Drift Detection ────────────────────────
# [HOOK] advanced_analytics — integrated from Phase 6
try:
    from advanced_analytics.adwin_detector    import ADWINManager
    from advanced_analytics.hdbscan_clusterer import ClusterManager
    _ANALYTICS_AVAILABLE = True
except ImportError:
    _ANALYTICS_AVAILABLE = False

# ─── Phase 7: PPO Reinforcement Learning Threshold Adapter ─────────────────────
# [HOOK] rl_engine — integrated from Phase 7
try:
    from rl_engine.ppo_agent         import PPOAgent
    from rl_engine.rl_env            import SDNEnvironment
    from rl_engine.threshold_adapter import ThresholdAdapter
    from rl_engine.rl_logger         import RLLogger
    _RL_AVAILABLE = True
except ImportError:
    _RL_AVAILABLE = False

# ─── Configuration Constants ─────────────────────────────────────────────────

# Monitoring poll interval in seconds (configurable for experiments)
MONITOR_INTERVAL = 5

# Train on synthetic data only when explicitly enabled (dev/demo mode).
# Production/paper runs: train offline with `python3 -m ml_models.model_trainer --from-csv`
AUTO_TRAIN_SYNTHETIC_ML = os.environ.get(
    "INTELLISHIELD_AUTO_TRAIN_SYNTHETIC", "0"
).strip().lower() in ("1", "true", "yes")

# CSV output path — relative to project root when launched from ~/intellishield-sdn
CSV_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "logs", "flow_stats.csv"
)

PORT_CSV_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "logs", "port_stats.csv"
)

CONTROLLER_STATS_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "logs", "controller_stats.csv"
)

# Warning thresholds — placeholder values for future entropy/RL integration
# [HOOK] PPO RL will dynamically adjust these in Phase 7
PACKET_RATE_WARN_THRESHOLD   = 500    # packets/sec
BYTE_RATE_WARN_THRESHOLD     = 500000 # bytes/sec  (~500 KB/s)
FLOW_COUNT_WARN_THRESHOLD    = 50     # simultaneous flows per switch

# Ethertypes to fully drop in the forwarding path (LLDP only)
# NOTE: ff:ff:ff:ff:ff:ff is ARP broadcast — must NOT be dropped here!
#       It is only excluded from *flow stats reporting* (see _flow_stats_reply_handler)
IGNORED_ETHTYPE = {0x88CC}   # LLDP — drop discovery frames entirely

# MACs excluded only from flow-stats CSV/console reporting (not from forwarding)
# These are multicast/LLDP addrs that clutter the stats output
IGNORED_STATS_MACS = {"ff:ff:ff:ff:ff:ff", "33:33:00:00:00:02", "01:80:c2:00:00:0e"}

# CSV column headers
FLOW_CSV_HEADERS = [
    "timestamp", "switch_id", "src_mac", "dst_mac",
    "in_port", "priority",
    "packet_count", "byte_count",
    "packet_rate", "byte_rate",
    "duration_sec",
]

PORT_CSV_HEADERS = [
    "timestamp", "switch_id", "port_no",
    "rx_packets", "tx_packets",
    "rx_bytes", "tx_bytes",
    "rx_errors", "tx_errors",
]

CONTROLLER_STATS_HEADERS = [
    "timestamp", "cpu_percent", "memory_rss_mb", "memory_percent",
]

# ─── Helper Utilities ─────────────────────────────────────────────────────────

def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Safely divide two numbers, returning `default` if denominator is zero.

    Args:
        numerator   : Top value.
        denominator : Bottom value (may be zero).
        default     : Return value when denominator == 0.

    Returns:
        float: Result of division or default.
    """
    if denominator == 0:
        return default
    return numerator / denominator


def now_str() -> str:
    """Return current timestamp as ISO-8601 string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mean_flow_rates(feature_batch: list) -> tuple:
    """Return (packet_rate_mean, byte_rate_mean) for a cycle's flow features."""
    if not feature_batch:
        return 0.0, 0.0
    n = len(feature_batch)
    pkt_mean = sum(f.get("packet_rate", 0.0) for f in feature_batch) / n
    byte_mean = sum(f.get("byte_rate", 0.0) for f in feature_batch) / n
    return float(pkt_mean), float(byte_mean)


def ensure_csv(filepath: str, headers: list) -> None:
    """
    Create CSV file with header row if it does not already exist.

    Args:
        filepath : Absolute or relative path to the CSV file.
        headers  : List of column header strings.
    """
    if _PROJECT_ROOT not in sys.path:
        sys.path.insert(0, _PROJECT_ROOT)
    from evaluation.csv_log_io import ensure_csv_header
    ensure_csv_header(filepath, headers)


# ─── Main Controller Application ─────────────────────────────────────────────

class IntelliShieldFlowMonitor(app_manager.OSKenApp):
    """
    IntelliShield SDN — Phase 1 Flow Statistics Monitoring Controller.

    This OsKen application:
      1. Acts as a learning L2 switch (installs forwarding rules)
      2. Registers/unregisters connected switches (datapaths)
      3. Spawns a background thread that periodically requests flow & port stats
      4. Processes statistics replies and logs structured feature dictionaries
      5. Emits early warning signals when traffic thresholds are exceeded

    The feature dictionaries produced here are the primary input for:
      - Phase 2 : Entropy Detection Engine
      - Phase 4 : HDBSCAN Traffic Profiler
      - Phase 5 : ADWIN Concept Drift Detector
      - Phase 7 : PPO Reinforcement Learning Threshold Adapter
      - Phase 5 : Automated Mitigation Engine
    """

    # Declare OpenFlow protocol version
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IntelliShieldFlowMonitor, self).__init__(*args, **kwargs)

        self._logs_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "logs",
        )

        # ── Switch Registry ───────────────────────────────────────────────────
        # Maps datapath_id (int) → datapath object
        self.datapaths: dict = {}

        # ── MAC-to-Port Table (L2 Learning) ───────────────────────────────────
        # Maps dpid → {mac → port}
        self.mac_to_port: dict = defaultdict(dict)

        # ── Per-switch flow counter for spike detection ───────────────────────
        # [HOOK] This counter feeds ADWIN drift detector in Phase 6
        self.flow_count_per_switch: dict = defaultdict(int)

        # ── Warm-up grace period ──────────────────────────────────────────────
        # Skip ML/Mitigation for the first N cycles per switch after connect.
        # Prevents false positives caused by empty entropy window on cycle 1.
        self._warmup_cycles:    dict = defaultdict(int)   # dpid → cycles seen
        self._warmup_threshold: int  = 3                  # skip first 3 cycles (~15s)

        # Consecutive ATTACK confirmation gate (prevents single-cycle false positives)
        self._attack_streak:    dict = defaultdict(int)   # dpid → consecutive ML ATTACK count
        self._entropy_attack_streak: dict = defaultdict(int)  # dpid → consecutive entropy ALERT
        self._attack_confirm:   int  = 2                  # need 2 in a row to trigger blocker

        # ── Initialise CSV log files ──────────────────────────────────────────
        ensure_csv(CSV_LOG_PATH, FLOW_CSV_HEADERS)
        ensure_csv(PORT_CSV_LOG_PATH, PORT_CSV_HEADERS)
        ensure_csv(CONTROLLER_STATS_LOG_PATH, CONTROLLER_STATS_HEADERS)

        # ── Phase 2: Entropy Detector instance ───────────────────────────────
        # [HOOK] entropy_engine/entropy_detector.py — Phase 2 integration
        if _ENTROPY_AVAILABLE:
            self._entropy_detector = EntropyDetector()
            self.logger.info("[ENTROPY] Phase 2 Entropy Detector: ACTIVE")
        else:
            self._entropy_detector = None
            self.logger.warning("[ENTROPY] entropy_engine not found — entropy analysis DISABLED")

        # ── Phase 4: ML Anomaly Detector instance ────────────────────────────
        # [HOOK] ml_models — integrated from Phase 4
        if _ML_AVAILABLE:
            try:
                init_ml_logs()
                self._feature_builder = FeatureBuilder()
                self._ml_detector     = AnomalyDetector(auto_load=True)
                self._ml_explainer    = Explainer()
                self._last_entropy    = {}   # stores latest entropy metrics per dpid
                if not self._ml_detector.is_ready:
                    from ml_models.model_trainer import ModelTrainer
                    trainer = ModelTrainer()
                    self.logger.info(
                        "[ML] No saved model — training from labelled ml_features.csv..."
                    )
                    trainer.train_all(use_synthetic=False)
                    self._ml_detector = AnomalyDetector(auto_load=True)
                    if not self._ml_detector.is_ready and AUTO_TRAIN_SYNTHETIC_ML:
                        self.logger.warning(
                            "[ML] No labelled CSV data — synthetic training enabled "
                            "(INTELLISHIELD_AUTO_TRAIN_SYNTHETIC=1)"
                        )
                        trainer.train_all(use_synthetic=True)
                        self._ml_detector = AnomalyDetector(auto_load=True)
                    elif not self._ml_detector.is_ready:
                        self.logger.warning(
                            "[ML] No model loaded. Train with: "
                            "python3 -m ml_models.model_trainer --from-csv "
                            "or set INTELLISHIELD_AUTO_TRAIN_SYNTHETIC=1 for demo mode"
                        )
                self.logger.info("[ML] Phase 4 ML Detector: ACTIVE  (trained=%s)",
                                  self._ml_detector.is_ready)
            except Exception as e:
                self.logger.error("[ML] Init error: %s", e)
                self._ml_detector = None
        else:
            self._ml_detector = None
            self.logger.warning("[ML] ml_models not found — ML detection DISABLED")

        # ── Phase 5: Mitigation Engine ────────────────────────────────────
        # [HOOK] mitigation — integrated from Phase 5
        if _MITIGATION_AVAILABLE:
            try:
                self._mitigation = MitigationEngine(auto_mitigate=True)
                # Share our datapaths dict so the engine can reach switches
                self._mitigation.set_datapaths(self.datapaths)
                self.logger.info("[MITIGATION] Phase 5 Mitigation Engine: ACTIVE")
            except Exception as e:
                self.logger.error("[MITIGATION] Init error: %s", e)
                self._mitigation = None
        else:
            self._mitigation = None
            self.logger.warning("[MITIGATION] mitigation module not found — DISABLED")

        # ── Requirement R7: VerificationEngine (pre-mitigation gate) ───────
        # Detectors still produce evidence; MitigationEngine still actuates.
        self._verification = None
        self._verification_trace_path = default_trace_path(self._logs_dir) if _VERIFICATION_AVAILABLE else None
        if _VERIFICATION_AVAILABLE and self._mitigation is not None:
            try:
                self._verification = VerificationEngine(
                    config=VerificationConfig(
                        warmup_threshold=self._warmup_threshold,
                        attack_confirm=self._attack_confirm,
                    ),
                    identify_attackers=self._mitigation._identify_attackers,
                    select_strategy=self._mitigation._select_block_strategy,
                )
                self.logger.info(
                    "[VERIFICATION] R7 VerificationEngine: ACTIVE  trace=%s",
                    self._verification_trace_path,
                )
            except Exception as e:
                self.logger.error("[VERIFICATION] Init error: %s", e)
                self._verification = None
        elif not _VERIFICATION_AVAILABLE:
            self.logger.warning(
                "[VERIFICATION] verification package not found — "
                "using legacy handle_alert path"
            )

        # ── Requirement R6: CollaborativeFusion → R7 (optional; fail-safe) ─
        self._r6_fusion_enabled = False
        self._fusion_engine = None
        self._fusion_trace_path = None
        if _FUSION_AVAILABLE:
            try:
                self._r6_fusion_enabled = bool(r6_fusion_enabled_from_env())
            except Exception:
                self._r6_fusion_enabled = False
        if self._r6_fusion_enabled:
            try:
                self._fusion_engine = CollaborativeFusionEngine()
                self._fusion_trace_path = default_fusion_trace_path(self._logs_dir)
                self.logger.info(
                    "[FUSION] R6 CollaborativeFusion: ACTIVE  trace=%s",
                    self._fusion_trace_path,
                )
            except Exception as e:
                self.logger.error("[FUSION] Init error — legacy dual-path: %s", e)
                self._r6_fusion_enabled = False
                self._fusion_engine = None
        elif not _FUSION_AVAILABLE:
            self.logger.warning(
                "[FUSION] fusion package not found — legacy ML/entropy paths"
            )
        else:
            self.logger.info(
                "[FUSION] R6 disabled via INTELLISHIELD_R6_FUSION — legacy paths"
            )

        # ── Requirement R8: AlertManager (independent of mitigation) ──────
        self._alert_manager = None
        if _ALERTING_AVAILABLE:
            try:
                from alerting.persistence import (
                    JsonlAlertStore,
                    default_alerts_jsonl_path,
                )

                _alert_store = JsonlAlertStore(
                    default_alerts_jsonl_path(self._logs_dir)
                )
                self._alert_manager = AlertManager(
                    config=AlertingConfig(
                        enabled=True,
                        alert_on_pending=False,
                        alert_on_ineligible=False,
                        alert_on_rejected=False,
                    ),
                    adapters=[LoggingNotificationAdapter()],
                    store=_alert_store,
                )
                self.logger.info(
                    "[ALERTING] R8 AlertManager: ACTIVE  store=%s",
                    _alert_store.path,
                )
            except Exception as e:
                self.logger.error("[ALERTING] Init error: %s", e)
                self._alert_manager = None
        else:
            self.logger.warning(
                "[ALERTING] alerting package not found — R8 notify DISABLED"
            )

        # ── Requirement R5.3: RCA store (enrichment only; non-fatal) ──────
        self._rca_store = None
        self._rca_config = None
        if _RCA_AVAILABLE:
            try:
                self._rca_config = RCAConfig(
                    enabled=True,
                    run_on_verified=True,
                    run_on_pending=False,
                    run_on_ineligible=False,
                    run_on_rejected=False,
                )
                self._rca_store = JsonlRCAStore(
                    default_rca_jsonl_path(self._logs_dir)
                )
                self.logger.info(
                    "[RCA] R5 RootCause enrichment: ACTIVE  store=%s",
                    self._rca_store.path,
                )
            except Exception as e:
                self.logger.error("[RCA] Init error: %s", e)
                self._rca_store = None
                self._rca_config = None
        else:
            self.logger.warning(
                "[RCA] rca package not found — R5 enrichment DISABLED"
            )

        # ── Requirement R4.3: CorrelationEngine (advisory only; non-fatal) ─
        self._correlation_engine = None
        self._correlation_store = None
        self._correlation_runtime_config = None
        self._last_controller_stats = None
        self._last_correlation = {}  # dpid → CorrelationResult (advisory)
        self._last_fused = {}  # dpid → FusedDecision (R6 collaborative; optional)
        if _CORRELATION_AVAILABLE:
            try:
                self._correlation_engine = CorrelationEngine()
                self._correlation_store = JsonlCorrelationStore(
                    default_correlation_jsonl_path(self._logs_dir)
                )
                self._correlation_runtime_config = CorrelationRuntimeConfig(
                    enabled=True,
                    persist=True,
                )
                self.logger.info(
                    "[CORRELATION] R4 CorrelationEngine: ACTIVE (advisory)  store=%s",
                    self._correlation_store.path,
                )
            except Exception as e:
                self.logger.error("[CORRELATION] Init error: %s", e)
                self._correlation_engine = None
                self._correlation_store = None
                self._correlation_runtime_config = None
        else:
            self.logger.warning(
                "[CORRELATION] correlation package not found — R4 DISABLED"
            )

        # ── Phase 6: ADWIN + HDBSCAN Advanced Analytics ────────────────────────
        # [HOOK] advanced_analytics — integrated from Phase 6
        if _ANALYTICS_AVAILABLE:
            try:
                self._adwin   = ADWINManager(delta=0.002, max_window=150)
                self._cluster = ClusterManager(min_cluster_size=5, cycle_count=10)
                self.logger.info("[ANALYTICS] Phase 6 ADWIN + HDBSCAN: ACTIVE")
            except Exception as e:
                self.logger.error("[ANALYTICS] Init error: %s", e)
                self._adwin   = None
                self._cluster = None
        else:
            self._adwin   = None
            self._cluster = None
            self.logger.warning("[ANALYTICS] advanced_analytics not found — DISABLED")

        # ── Phase 7: PPO RL Threshold Adapter ──────────────────────────────────
        # [HOOK] rl_engine — integrated from Phase 7
        if _RL_AVAILABLE:
            try:
                _logs_dir = self._logs_dir
                _weights   = os.path.join(_logs_dir, "ppo_weights.pkl")
                self._rl_adapter = ThresholdAdapter()
                self._ppo_agent  = PPOAgent(
                    save_path    = _weights,
                    update_every = 20,
                )
                self._rl_env    = SDNEnvironment()
                self._rl_logger = RLLogger(logs_dir=_logs_dir)
                # Per-switch state: last ML label + confidence
                self._rl_last   = {}   # dpid → {label, conf, pkt_rate, entropy}
                try:
                    from shared_contracts.ops_profile import get_ops_policy
                    _ops = get_ops_policy()
                    self.logger.info(
                        "[RL] Ops profile=%s freeze_conf_gate=%s",
                        _ops.profile.value,
                        _ops.freeze_rl_confidence_gate,
                    )
                except Exception:
                    pass
                self.logger.info("[RL] Phase 7 PPO Threshold Adapter: ACTIVE")
                self.logger.info(
                    "[RL] Initial thresholds — pkt=%d  byte=%d  conf=%.2f",
                    self._rl_adapter.pkt_threshold,
                    self._rl_adapter.byte_threshold,
                    self._rl_adapter.conf_threshold,
                )
            except Exception as e:
                self.logger.error("[RL] Init error: %s", e)
                self._rl_adapter = None
                self._ppo_agent  = None
                self._rl_env     = None
                self._rl_logger  = None
        else:
            self._rl_adapter = None
            self._ppo_agent  = None
            self._rl_env     = None
            self._rl_logger  = None
            self.logger.warning("[RL] rl_engine not found — DISABLED")

        # Wire PPO confidence gate into mitigation (Phase 7 → Phase 5)
        if self._mitigation is not None and self._rl_adapter is not None:
            self._mitigation.set_threshold_adapter(self._rl_adapter)

        # ── Start background monitoring thread ────────────────────────────────
        # hub.spawn creates a cooperative greenlet — lightweight on CPU
        self._monitor_thread = hub.spawn(self._monitor)

        self.logger.info("=" * 60)
        self.logger.info("  IntelliShield SDN — Flow Monitor Controller v1.0")
        self.logger.info("  Phase 1: Flow Statistics Monitoring Engine")
        self.logger.info("  Poll interval : %d seconds", MONITOR_INTERVAL)
        self.logger.info("  Flow CSV      : %s", os.path.abspath(CSV_LOG_PATH))
        self.logger.info("  Port CSV      : %s", os.path.abspath(PORT_CSV_LOG_PATH))
        self.logger.info("=" * 60)

    # =========================================================================
    # SECTION 1 — Switch Lifecycle Handlers
    # =========================================================================

    def _register_datapath(self, datapath) -> None:
        """
        Register a newly connected switch datapath.

        Called when EventOFPStateChange fires with MAIN_DISPATCHER state.

        Args:
            datapath: OsKen datapath object representing a connected switch.
        """
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self._warmup_cycles[dpid] = 0       # reset warm-up counter on (re)connect
        self._attack_streak[dpid] = 0       # reset ML attack confirmation on (re)connect
        self._entropy_attack_streak[dpid] = 0
        self.logger.info("[SWITCH CONNECTED]  Switch DPID: %016x", dpid)
        self.logger.info("[WARMUP] Switch %d — warm-up started (%d cycles / ~%ds before ML active)",
                         dpid, self._warmup_threshold,
                         self._warmup_threshold * 5)
        self._publish_topology_status()

    def _unregister_datapath(self, datapath) -> None:
        """
        Unregister a disconnected switch datapath.

        Called when EventOFPStateChange fires with DEAD_DISPATCHER state.

        Args:
            datapath: OsKen datapath object for the disconnecting switch.
        """
        dpid = datapath.id
        if dpid in self.datapaths:
            del self.datapaths[dpid]
            self.logger.warning("[SWITCH DISCONNECTED]  Switch DPID: %016x", dpid)
        self._publish_topology_status()

    def _publish_topology_status(self) -> None:
        """Best-effort write of read-only topology snapshot for the dashboard."""
        if not _TOPOLOGY_STATUS_AVAILABLE or publish_topology_status is None:
            return
        try:
            publish_topology_status(
                self._logs_dir,
                datapath_ids=list(self.datapaths.keys()),
                mac_to_port=self.mac_to_port,
                poll_interval_sec=float(MONITOR_INTERVAL),
            )
        except Exception:
            self.logger.debug(
                "[topology_status] publish failed:\n%s",
                traceback.format_exc(),
            )

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev) -> None:
        """
        Sync blocklist when a mitigation DROP rule expires on the switch.

        flow_blocker installs rules with OFPFF_SEND_FLOW_REM so the switch
        notifies the controller when hard_timeout elapses.
        """
        try:
            msg = ev.msg
            if msg.priority != BLOCK_PRIORITY:
                return

            src_mac = msg.match.get("eth_src")
            if not src_mac or self._mitigation is None:
                return

            dpid    = msg.datapath.id
            dst_mac = msg.match.get("eth_dst", "")
            self._mitigation.on_flow_removed(dpid, src_mac, dst_mac=dst_mac)
        except Exception:
            self.logger.error(
                "[flow_removed] Error processing FlowRemoved:\n%s",
                traceback.format_exc(),
            )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev) -> None:
        """
        Handle switch state changes (connect / disconnect).

        OsKen fires this event whenever a datapath transitions between
        connection states. We use it to maintain the live datapath registry.

        Args:
            ev: OsKen EventOFPStateChange event object.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self._register_datapath(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self._unregister_datapath(datapath)

    # =========================================================================
    # SECTION 2 — Default Flow Installation (Table-Miss)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev) -> None:
        """
        Install table-miss flow entry when a switch connects.

        The table-miss rule (priority=0, match-all) forwards unmatched packets
        to the controller so we can perform L2 learning and install flows.

        Args:
            ev: EventOFPSwitchFeatures event from OsKen.
        """
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        # Match-all with lowest priority → send to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("[SETUP] Table-miss flow installed on DPID %016x", datapath.id)

    def _add_flow(self, datapath, priority: int, match, actions,
                  idle_timeout: int = 0, hard_timeout: int = 0) -> None:
        """
        Install a flow entry on a switch.

        Args:
            datapath     : Target switch datapath.
            priority     : OpenFlow flow priority.
            match        : OFPMatch object.
            actions      : List of OFPAction objects.
            idle_timeout : Remove flow after N seconds of inactivity (0 = never).
            hard_timeout : Remove flow after N seconds regardless (0 = never).
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    # =========================================================================
    # SECTION 3 — Packet-In Handler (L2 Learning Switch)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev) -> None:
        """
        Handle incoming packets for L2 MAC learning and forwarding.

        This handler:
          - Learns source MAC → ingress port mappings
          - Installs unicast forwarding rules (or floods if unknown)
          - ONLY drops pure LLDP frames (ethertype 0x88CC)
          - ARP broadcasts (ff:ff:ff:ff:ff:ff) are FLOODED, not dropped

        Bug fix note:
            Broadcasts must NOT be filtered here. ARP uses broadcast dst MAC
            (ff:ff:ff:ff:ff:ff). If ARP is dropped, hosts cannot resolve IPs
            and all pings will fail with 'Destination Host Unreachable'.
            Broadcast MAC filtering is only applied to flow-stats reporting.

        Args:
            ev: EventOFPPacketIn event from OsKen.
        """
        try:
            msg      = ev.msg
            datapath = msg.datapath
            ofproto  = datapath.ofproto
            parser   = datapath.ofproto_parser
            dpid     = datapath.id
            in_port  = msg.match["in_port"]

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)

            if eth is None:
                return  # Not an Ethernet frame — skip

            dst = eth.dst
            src = eth.src

            # ── Drop LLDP frames ONLY (link-layer discovery, not real traffic) ─
            # Do NOT drop broadcasts here — ARP needs ff:ff:ff:ff:ff:ff to work!
            if eth.ethertype in IGNORED_ETHTYPE:
                return

            # ── MAC Learning ──────────────────────────────────────────────────
            # Always learn the source MAC regardless of dst type
            self.mac_to_port[dpid][src] = in_port

            # ── Forwarding Decision ───────────────────────────────────────────
            # Unicast: known dst → forward to learned port
            # Broadcast / Unknown unicast: flood to all ports
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # ── Install Unicast Flow Rule ─────────────────────────────────────
            # Only install rules for known unicast destinations.
            # Broadcasts are always flooded via PacketOut — no flow entry needed.
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # idle_timeout=30s: keeps the flow table clean between experiments
                self._add_flow(
                    datapath, priority=1, match=match, actions=actions,
                    idle_timeout=30, hard_timeout=120,
                )

            # ── Send Packet Out ───────────────────────────────────────────────
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data,
            )
            datapath.send_msg(out)

        except Exception:
            self.logger.error("[packet_in_handler] Unexpected error:\n%s", traceback.format_exc())

    # =========================================================================
    # SECTION 4 — Background Monitoring Thread
    # =========================================================================

    def _monitor(self) -> None:
        """
        Background greenlet: polls flow and port statistics every MONITOR_INTERVAL.

        This cooperative thread runs forever, iterating through all registered
        datapaths and issuing OpenFlow statistics requests. The controller
        processes replies asynchronously via the event handlers below.

        Design Note:
            hub.sleep() yields the greenlet cooperatively — it does NOT block
            the entire OsKen event loop. This keeps CPU usage minimal.
        """
        self.logger.info("[MONITOR] Background monitoring thread started.")
        while True:
            try:
                if not self.datapaths:
                    self.logger.debug("[MONITOR] No switches connected yet. Waiting...")
                else:
                    for dpid, datapath in list(self.datapaths.items()):
                        self._request_stats(datapath)
                    self._log_controller_stats()
                # Refresh observational topology snapshot each poll cycle
                self._publish_topology_status()

            except Exception:
                self.logger.error("[MONITOR] Error in monitoring loop:\n%s", traceback.format_exc())

            hub.sleep(MONITOR_INTERVAL)

    def _log_controller_stats(self) -> None:
        """Append controller CPU/memory sample for IEEE system metrics (optional psutil)."""
        try:
            import psutil
            proc = psutil.Process()
            mem = proc.memory_info()
            row = {
                "timestamp"      : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "cpu_percent"    : round(proc.cpu_percent(interval=None), 2),
                "memory_rss_mb"  : round(mem.rss / (1024 * 1024), 2),
                "memory_percent" : round(proc.memory_percent(), 2),
            }
            self._last_controller_stats = row
            self.log_to_csv(row, CONTROLLER_STATS_LOG_PATH, CONTROLLER_STATS_HEADERS)
        except ImportError:
            pass
        except Exception:
            self.logger.debug(
                "[_log_controller_stats] skipped:\n%s", traceback.format_exc(),
            )

    def _request_stats(self, datapath) -> None:
        """
        Issue OpenFlow flow and port statistics requests to a switch.

        Sends two asynchronous requests:
          1. OFPFlowStatsRequest  → triggers _flow_stats_reply_handler
          2. OFPPortStatsRequest  → triggers _port_stats_reply_handler

        Args:
            datapath: Target switch datapath object.
        """
        try:
            ofproto = datapath.ofproto
            parser  = datapath.ofproto_parser

            # ── Flow Statistics Request ───────────────────────────────────────
            # table_id=OFPTT_ALL : query all flow tables
            # out_port=OFPP_ANY  : match flows going to any port
            flow_req = parser.OFPFlowStatsRequest(
                datapath,
                table_id=ofproto.OFPTT_ALL,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(),
            )
            datapath.send_msg(flow_req)

            # ── Port Statistics Request ───────────────────────────────────────
            # port_no=OFPP_ANY : query statistics for all ports
            port_req = parser.OFPPortStatsRequest(
                datapath,
                port_no=ofproto.OFPP_ANY,
            )
            datapath.send_msg(port_req)

        except Exception:
            self.logger.error(
                "[_request_stats] Failed to send stats request to DPID %016x:\n%s",
                datapath.id, traceback.format_exc(),
            )

    # =========================================================================
    # SECTION 5 — Flow Statistics Reply Handler
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev) -> None:
        """
        Process incoming OpenFlow flow statistics replies.

        For each flow entry received:
          - Extracts match fields (src/dst MAC, in_port, priority)
          - Calculates packet_rate and byte_rate
          - Builds a reusable feature dictionary
          - Logs to console and CSV
          - Checks warning thresholds

        The feature dictionaries are designed to be consumed by:
          [HOOK] Phase 2  → entropy_engine/entropy_calculator.py
          [HOOK] Phase 6  → ml_models/hdbscan_profiler.py
          [HOOK] Phase 6  → monitoring/adwin_detector.py
          [HOOK] Phase 7  → rl_engine/ppo_threshold.py
          [HOOK] Phase 5  → mitigation/flow_blocker.py

        Args:
            ev: EventOFPFlowStatsReply event from OsKen.
        """
        try:
            body     = ev.msg.body
            datapath = ev.msg.datapath
            dpid     = datapath.id

            # Filter out table-miss / internal controller entries
            # These have priority=0 and empty matches — not real traffic
            # Also filter broadcast/multicast dst MACs from stats reporting
            # (IGNORED_STATS_MACS — separate from forwarding path)
            active_flows = [
                stat for stat in body
                if stat.priority > 0
                   and stat.match.get("eth_dst") not in IGNORED_STATS_MACS
            ]

            flow_count = len(active_flows)
            self.flow_count_per_switch[dpid] = flow_count

            # Extract flow features once per cycle (shared by Phases 2–7)
            feature_batch = []
            for stat in active_flows:
                feat = self._extract_flow_features(dpid, stat)
                if feat is not None:
                    feature_batch.append(feat)

            pkt_mean, byte_mean = mean_flow_rates(feature_batch)

            # ── [HOOK] Phase 2: Feed flow features to Entropy Detector ────────
            if self._entropy_detector is not None:
                try:
                    if feature_batch:
                        self._entropy_detector.add_flows(dpid, feature_batch)
                        entropy_result = self._entropy_detector.analyze(dpid)
                        # Store latest entropy metrics for Phase 4 ML hook
                        if entropy_result and hasattr(self, "_last_entropy"):
                            self._last_entropy[dpid] = entropy_result
                except Exception:
                    self.logger.error(
                        "[entropy hook] Error in entropy analysis:\n%s",
                        traceback.format_exc(),
                    )

            # ── [HOOK] Phase 4: ML Anomaly Detection ─────────────────────────
            # Skip ML/mitigation/RL during warm-up so the entropy window can fill
            self._warmup_cycles[dpid] += 1
            _cycles_done = self._warmup_cycles[dpid]
            in_warmup = _cycles_done <= self._warmup_threshold
            if in_warmup:
                _remaining = self._warmup_threshold - _cycles_done + 1
                print(
                    f"  ⏳ [WARMUP] Switch {dpid} — cycle {_cycles_done}/{self._warmup_threshold} "
                    f"({_remaining} more cycle(s) until ML & Mitigation are active)"
                )

            ml_attack_mitigated = False
            cycle_prediction = None
            cycle_explanation = None
            cycle_feature_vector = None
            r6_owned_cycle = False
            use_r6 = bool(getattr(self, "_r6_fusion_enabled", False))

            if not in_warmup and self._ml_detector is not None:
                try:
                    if feature_batch:
                        entropy_for_ml = getattr(self, "_last_entropy", {}).get(dpid, {})
                        vec, meta = self._feature_builder.build(
                            flow_features   = feature_batch,
                            entropy_metrics = entropy_for_ml,
                            switch_id       = dpid,
                        )
                        prediction  = self._ml_detector.predict(vec)
                        explanation = self._ml_explainer.explain(vec, prediction)
                        cycle_prediction = prediction
                        cycle_explanation = explanation
                        cycle_feature_vector = vec
                        cycle_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        explanation["attack_type_hint"] = classify_attack_type(
                            vec,
                            status=prediction.get("status", "NORMAL"),
                            entropy_metrics=entropy_for_ml,
                            flow_features=feature_batch,
                            timestamp=cycle_ts,
                            logs_dir=self._logs_dir,
                        )

                        # Console output
                        print_ml_result(prediction, explanation)

                        # Log prediction to CSV
                        log_prediction(dpid, prediction, explanation,
                                       vec, FEATURE_NAMES)

                        ml_status = prediction.get("status", "NORMAL")
                        if ml_status in ("SUSPICIOUS", "ATTACK"):
                            log_ml_alert(dpid, prediction, explanation)
                            self._ml_explainer.print_explanation(explanation)

                            # R6.3: when collaborative fusion owns the cycle,
                            # defer streak + R7 dispatch to the fused path
                            # (prevents ML→R7 and R6→R7 double verification).
                            if use_r6:
                                pass
                            else:
                                if ml_status in ("ATTACK", "SUSPICIOUS"):
                                    self._attack_streak[dpid] += 1

                                if self._mitigation is not None:
                                    attack_confirmed = (
                                        self._attack_streak[dpid] >= self._attack_confirm
                                    )
                                    if ml_status == "ATTACK" and not attack_confirmed:
                                        print(
                                            f"  🛡️ [MITIGATION] ATTACK pending confirmation "
                                            f"({self._attack_streak[dpid]}/"
                                            f"{self._attack_confirm} consecutive cycles)"
                                        )
                                    try:
                                        self._dispatch_verified_mitigation(
                                            dpid=dpid,
                                            prediction=prediction,
                                            explanation=explanation,
                                            flow_features=feature_batch,
                                            attack_streak=self._attack_streak[dpid],
                                            warmup_cycles_done=_cycles_done,
                                            source_tag="ml",
                                            feature_vector=vec,
                                        )
                                        if ml_status == "ATTACK" and attack_confirmed:
                                            ml_attack_mitigated = True
                                    except Exception:
                                        self.logger.error(
                                            "[mitigation hook] Error:\n%s",
                                            traceback.format_exc(),
                                        )
                        else:
                            if not use_r6:
                                self._attack_streak[dpid] = 0

                        # ── [HOOK] Phase 6: HDBSCAN Clustering ────────────────
                        # Buffer this feature vector; auto-clusters every 10 cycles
                        if self._cluster is not None:
                            try:
                                self._cluster.add_vector(dpid, vec, FEATURE_NAMES)
                            except Exception:
                                self.logger.error(
                                    "[hdbscan hook] Error:\n%s",
                                    traceback.format_exc(),
                                )

                        # ── [HOOK] Phase 7: PPO RL Adaptive Thresholds ────────
                        # Each cycle: observe → act → reward → remember → update
                        if self._ppo_agent is not None:
                            try:
                                ml_label = prediction.get("status", "NORMAL")
                                ml_conf  = float(prediction.get("confidence", 0.0))

                                ent_score = float(
                                    entropy_for_ml.get("entropy_score", 1.0)
                                )
                                ent_status = entropy_for_ml.get("status", "NORMAL")
                                max_pkt = max(
                                    (float(f.get("packet_rate", 0.0)) for f in feature_batch),
                                    default=0.0,
                                )
                                pkt_ent = float(
                                    entropy_for_ml.get("packet_entropy", 1.0)
                                )

                                # Build normalised state vector (10 dims)
                                state = self._rl_env.build_state(
                                    packet_rate_mean  = pkt_mean,
                                    byte_rate_mean    = byte_mean,
                                    entropy_score     = ent_score,
                                    flow_count        = flow_count,
                                    ml_confidence     = ml_conf,
                                    pkt_threshold     = self._rl_adapter.pkt_threshold,
                                    byte_threshold    = self._rl_adapter.byte_threshold,
                                    conf_threshold    = self._rl_adapter.conf_threshold,
                                    recent_attack_cnt = self._rl_adapter.recent_attack_count,
                                    recent_fp_cnt     = self._rl_adapter.recent_fp_count,
                                )

                                # Sample action from PPO Gaussian policy
                                action, lp, val = self._ppo_agent.step(state)

                                # Apply threshold deltas → new bounded thresholds
                                new_thresh = self._rl_adapter.apply_action(action)

                                # Compute reward signal
                                reward = self._rl_adapter.compute_reward(
                                    ml_label        = ml_label,
                                    ml_confidence   = ml_conf,
                                    packet_rate     = pkt_mean,
                                    entropy_score   = ent_score,
                                    entropy_status  = ent_status,
                                    max_pkt_rate    = max_pkt,
                                    packet_entropy  = pkt_ent,
                                )

                                # Store transition in PPO replay buffer
                                self._ppo_agent.remember(
                                    state, action, lp, reward, val
                                )

                                # Console: show updated thresholds + reward
                                print(
                                    f"  \U0001f9e0 [RL] "
                                    f"pkt\u2264{new_thresh['pkt_threshold']:.0f}  "
                                    f"byte\u2264{new_thresh['byte_threshold']:.0f}  "
                                    f"conf\u2265{new_thresh['conf_threshold']:.2f}  "
                                    f"reward={reward:+.1f}"
                                )

                                # Log decision to rl_decisions.csv
                                self._rl_logger.log_decision(
                                    switch_id  = dpid,
                                    pkt_rate   = pkt_mean,
                                    byte_rate  = byte_mean,
                                    entropy    = ent_score,
                                    flow_count = flow_count,
                                    ml_label   = ml_label,
                                    ml_conf    = ml_conf,
                                    action     = action,
                                    thresholds = new_thresh,
                                    reward     = reward,
                                )

                                # PPO weight update every 20 cycles
                                losses = self._ppo_agent.update_if_ready()
                                if losses:
                                    print(
                                        f"  \U0001f4ca [RL] PPO Update "
                                        f"#{self._ppo_agent._total_updates}  "
                                        f"actor_loss={losses['actor_loss']:.4f}  "
                                        f"critic_loss={losses['critic_loss']:.4f}"
                                    )
                                    self._rl_logger.log_training(
                                        update_number = self._ppo_agent._total_updates,
                                        actor_loss    = losses["actor_loss"],
                                        critic_loss    = losses["critic_loss"],
                                        buffer_size   = 20,
                                    )

                            except Exception:
                                self.logger.error(
                                    "[rl hook] Error:\n%s",
                                    traceback.format_exc(),
                                )

                except Exception:
                    self.logger.error(
                        "[ml hook] Error in ML detection:\n%s",
                        traceback.format_exc(),
                    )

            # ── [HOOK] Phase 6: ADWIN Drift Detection (before R6/R7) ─────────
            drift_alerts = []
            if not in_warmup and self._adwin is not None:
                try:
                    adwin_metrics = {
                        "flow_count"      : float(flow_count),
                        "packet_rate_mean": pkt_mean,
                        "byte_rate_mean"  : byte_mean,
                        "entropy_score"   : getattr(
                            self, "_last_entropy", {}
                        ).get(dpid, {}).get("entropy_score", 1.0),
                    }
                    drift_alerts = self._adwin.update_all(dpid, adwin_metrics) or []
                    if drift_alerts:
                        self.logger.warning(
                            "[ADWIN] %d drift alert(s) on dpid=%d",
                            len(drift_alerts), dpid,
                        )
                except Exception:
                    self.logger.error(
                        "[adwin hook] Error:\n%s", traceback.format_exc()
                    )
                    drift_alerts = []
            elif not in_warmup and flow_count >= FLOW_COUNT_WARN_THRESHOLD:
                self._print_warning(
                    dpid,
                    f"HIGH FLOW COUNT: {flow_count} concurrent flows "
                    f"(threshold={FLOW_COUNT_WARN_THRESHOLD})"
                )

            # ── [HOOK] R4.3: Advisory Cross-Layer Correlation (before R6) ───
            if (
                not in_warmup
                and _CORRELATION_AVAILABLE
                and self._correlation_engine is not None
            ):
                try:
                    cluster_summary = None
                    if self._cluster is not None:
                        try:
                            cluster_summary = self._cluster.get_last_summary(dpid)
                        except Exception:
                            cluster_summary = None
                    corr_out = safe_correlate_cycle(
                        engine=self._correlation_engine,
                        store=self._correlation_store,
                        config=self._correlation_runtime_config,
                        switch_id=dpid,
                        feature_batch=feature_batch,
                        entropy=getattr(self, "_last_entropy", {}).get(dpid),
                        prediction=cycle_prediction,
                        explanation=cycle_explanation,
                        controller_stats=getattr(
                            self, "_last_controller_stats", None
                        ),
                        drift_alerts=drift_alerts,
                        cluster_summary=cluster_summary,
                    )
                    if corr_out is not None and getattr(corr_out, "result", None) is not None:
                        self._last_correlation[dpid] = corr_out.result
                except Exception:
                    self.logger.error(
                        "[correlation hook] Error (isolated):\n%s",
                        traceback.format_exc(),
                    )

            # ── [HOOK] R6.3: Collaborative fusion → single R7 path ─────────
            if (
                not in_warmup
                and use_r6
                and self._mitigation is not None
                and feature_batch
            ):
                try:
                    r6_owned_cycle = self._run_r6_collaborative_cycle(
                        dpid=dpid,
                        feature_batch=feature_batch,
                        cycle_prediction=cycle_prediction,
                        cycle_explanation=cycle_explanation,
                        feature_vector=cycle_feature_vector,
                        drift_alerts=drift_alerts,
                        warmup_cycles_done=_cycles_done,
                    )
                    if r6_owned_cycle:
                        ml_attack_mitigated = True  # suppress entropy dual-path
                except Exception:
                    self.logger.error(
                        "[fusion hook] Error — legacy fallback:\n%s",
                        traceback.format_exc(),
                    )
                    r6_owned_cycle = False

            # Legacy ML→R7 when R6 did not own the cycle (fallback / disabled)
            if (
                not in_warmup
                and not r6_owned_cycle
                and use_r6
                and self._mitigation is not None
                and isinstance(cycle_prediction, dict)
            ):
                ml_status = str(cycle_prediction.get("status", "NORMAL")).upper()
                if ml_status in ("ATTACK", "SUSPICIOUS"):
                    self._attack_streak[dpid] += 1
                    attack_confirmed = (
                        self._attack_streak[dpid] >= self._attack_confirm
                    )
                    try:
                        self._dispatch_verified_mitigation(
                            dpid=dpid,
                            prediction=cycle_prediction,
                            explanation=cycle_explanation or {},
                            flow_features=feature_batch,
                            attack_streak=self._attack_streak[dpid],
                            warmup_cycles_done=_cycles_done,
                            source_tag="ml",
                            feature_vector=cycle_feature_vector,
                        )
                        if ml_status == "ATTACK" and attack_confirmed:
                            ml_attack_mitigated = True
                    except Exception:
                        self.logger.error(
                            "[mitigation hook] legacy fallback error:\n%s",
                            traceback.format_exc(),
                        )
                else:
                    self._attack_streak[dpid] = 0

            # ── [HOOK] Phase 5: Entropy-gated mitigation (legacy dual-trigger)
            # Skipped when R6 owned the cycle (duplicate prevention).
            if not in_warmup and not r6_owned_cycle:
                self._try_entropy_mitigation(
                    dpid,
                    feature_batch,
                    skip_if_ml_blocked=ml_attack_mitigated,
                )

            if not active_flows:
                return  # Nothing meaningful to process this cycle

            print("\n" + "=" * 58)
            print(f"  [FLOW STATISTICS]  Switch DPID: {dpid}  |  "
                  f"{now_str()}")
            print(f"  Active flows: {flow_count}")
            print("=" * 58)

            for feature in feature_batch:
                self.print_flow_statistics(feature)
                self.log_to_csv(feature, CSV_LOG_PATH, FLOW_CSV_HEADERS)
                self._check_flow_thresholds(feature)

            print("=" * 58 + "\n")

        except Exception:
            self.logger.error(
                "[_flow_stats_reply_handler] Error processing flow stats:\n%s",
                traceback.format_exc(),
            )

    def _run_r6_collaborative_cycle(
        self,
        *,
        dpid: int,
        feature_batch: list,
        cycle_prediction: dict | None,
        cycle_explanation: dict | None,
        feature_vector: list | None,
        drift_alerts: list,
        warmup_cycles_done: int,
    ) -> bool:
        """
        R6.3: fuse cycle evidence → at most one R7 verification dispatch.

        Returns True when R6 owned the cycle (suppress legacy ML+entropy paths).
        Never installs OpenFlow itself — always goes through R7 → MitigationEngine.
        Fail-safe: exceptions → False (legacy fallback).
        """
        if not _FUSION_AVAILABLE or not getattr(self, "_r6_fusion_enabled", False):
            return False
        if self._mitigation is None:
            return False

        cluster_summary = None
        if self._cluster is not None:
            try:
                cluster_summary = self._cluster.get_last_summary(dpid)
            except Exception:
                cluster_summary = None

        corr = getattr(self, "_last_correlation", {}).get(dpid)
        entropy_metrics = getattr(self, "_last_entropy", {}).get(dpid)

        # Dominant flow identity for entity alignment (best-effort)
        src_mac = None
        dst_mac = None
        try:
            if feature_batch:
                top = max(
                    feature_batch,
                    key=lambda f: float(f.get("packet_rate", 0.0) or 0.0),
                )
                src_mac = top.get("src_mac")
                dst_mac = top.get("dst_mac")
        except Exception:
            src_mac = None
            dst_mac = None

        outcome = prepare_collaborative_cycle(
            switch_id=dpid,
            ml_prediction=cycle_prediction,
            ml_explanation=cycle_explanation,
            entropy_metrics=entropy_metrics,
            correlation=corr,
            adwin_alerts=drift_alerts,
            hdbscan_summary=cluster_summary,
            src_mac=src_mac,
            dst_mac=dst_mac,
            engine=getattr(self, "_fusion_engine", None),
            trace_path=getattr(self, "_fusion_trace_path", None),
            persist_trace=True,
        )

        if not outcome.owned:
            return False

        if outcome.fused is not None:
            self._last_fused[dpid] = outcome.fused

        # Collaborative streak (replaces separate ML/entropy streaks this cycle)
        if outcome.should_dispatch_r7:
            self._attack_streak[dpid] += 1
            attack_confirmed = self._attack_streak[dpid] >= self._attack_confirm
            status = str((outcome.prediction or {}).get("status", "")).upper()
            if status == "ATTACK" and not attack_confirmed:
                print(
                    f"  🛡️ [FUSION] ATTACK pending confirmation "
                    f"({self._attack_streak[dpid]}/{self._attack_confirm} "
                    f"consecutive cycles)"
                )
            try:
                self._dispatch_verified_mitigation(
                    dpid=dpid,
                    prediction=outcome.prediction or {},
                    explanation=outcome.explanation or {},
                    flow_features=feature_batch,
                    attack_streak=self._attack_streak[dpid],
                    warmup_cycles_done=warmup_cycles_done,
                    source_tag="r6_fusion",
                    feature_vector=feature_vector,
                )
                last = getattr(self, "_last_verification_outcome", None)
                if last is not None and outcome.fused is not None:
                    try:
                        link_verification_to_fusion_trace(
                            fused=outcome.fused,
                            trace_path=getattr(self, "_fusion_trace_path", None),
                            verification_id=getattr(
                                last.result, "verification_id", None
                            ),
                            dpid=dpid,
                        )
                    except Exception:
                        pass
            except Exception:
                self.logger.error(
                    "[fusion→R7] dispatch error:\n%s",
                    traceback.format_exc(),
                )
        else:
            self._attack_streak[dpid] = 0
            # Reset entropy streak too — collaborative NORMAL supersedes it
            self._entropy_attack_streak[dpid] = 0

        return True

    def _map_entropy_attack_hint(self,
                                  entropy_metrics: dict,
                                  feature_batch: list = None,
                                  timestamp: str = None) -> str:
        """Map collapsed entropy dimensions to a mitigation attack-type hint."""
        if feature_batch and self._feature_builder is not None:
            vec, _ = self._feature_builder.build(
                flow_features=feature_batch,
                entropy_metrics=entropy_metrics or {},
                switch_id=0,
                persist=False,
            )
            return classify_attack_type(
                vec,
                status="ATTACK",
                entropy_metrics=entropy_metrics,
                flow_features=feature_batch,
                timestamp=timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                logs_dir=self._logs_dir,
            )

        src  = float(entropy_metrics.get("src_entropy",    1.0))
        dst  = float(entropy_metrics.get("dst_entropy",    1.0))
        pkt  = float(entropy_metrics.get("packet_entropy", 1.0))
        byte = float(entropy_metrics.get("byte_entropy",   1.0))

        if feature_batch:
            collapsed = _collapse_flow_pairs(feature_batch)
            rates = sorted(
                (float(f.get("packet_rate", 0.0)) for f in collapsed),
                reverse=True,
            )
            if len(rates) >= 2 and rates[0] > ATTACK_RATE_THRESHOLD:
                ratio = rates[0] / max(rates[1], 0.001)
                if ratio >= RATE_DOMINANCE_RATIO and pkt <= PACKET_ENTROPY_THRESHOLD:
                    return "BURST"

        if dst <= DST_ENTROPY_THRESHOLD and byte <= BYTE_ENTROPY_THRESHOLD:
            return "UDP_FLOOD"
        if src <= SRC_ENTROPY_THRESHOLD and pkt <= PACKET_ENTROPY_THRESHOLD:
            return "SYN_FLOOD"
        if pkt <= PACKET_ENTROPY_THRESHOLD or byte <= BYTE_ENTROPY_THRESHOLD:
            return "VOLUMETRIC_FLOOD"
        return "UNKNOWN"

    def _build_entropy_mitigation_payload(self,
                                           entropy_metrics: dict,
                                           feature_batch: list) -> tuple:
        """Build ML-compatible prediction/explanation dicts from an entropy ALERT."""
        attack_hint  = self._map_entropy_attack_hint(
            entropy_metrics, feature_batch,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        entropy_conf = float(entropy_metrics.get("confidence", 0.0))
        collapsed    = _collapse_flow_pairs(feature_batch)
        max_pkt      = max(
            (float(f.get("packet_rate", 0.0)) for f in collapsed),
            default=0.0,
        )
        # Boost with observed peak rate — 500 pkt/s → 100%, caps at 100%
        rate_conf  = min(100.0, (max_pkt / 500.0) * 100.0)
        confidence = max(entropy_conf, rate_conf)
        score      = entropy_metrics.get("entropy_score")
        score_str  = f"{float(score):.4f}" if isinstance(score, (int, float)) else "?"
        prediction = {
            "status"     : "ATTACK",
            "confidence" : confidence,
            "source"     : "entropy",
        }
        explanation = {
            "attack_type_hint": attack_hint,
            "source"          : "entropy",
            "entropy_score"   : score,
            "entropy_conf"    : entropy_conf,
            "rate_conf"       : rate_conf,
            "max_packet_rate" : max_pkt,
            "summary"         : (
                f"Entropy ALERT — {attack_hint} (score={score_str}, "
                f"conf={confidence:.1f}% from entropy={entropy_conf:.1f}% "
                f"rate={rate_conf:.1f}%)"
            ),
        }
        return prediction, explanation

    def _try_entropy_mitigation(self,
                                 dpid: int,
                                 feature_batch: list,
                                 skip_if_ml_blocked: bool = False) -> None:
        """
        Trigger Phase 5 mitigation from a Phase 2 entropy ALERT.

        Skipped when ML already installed a block this cycle, during warm-up
        (caller responsibility), or when entropy status is not ALERT.
        """
        if skip_if_ml_blocked or self._mitigation is None or not feature_batch:
            return

        entropy_metrics = getattr(self, "_last_entropy", {}).get(dpid, {})
        ent_status = entropy_metrics.get("status", "NORMAL")

        if ent_status != "ALERT":
            self._entropy_attack_streak[dpid] = 0
            return

        self._entropy_attack_streak[dpid] += 1
        if self._entropy_attack_streak[dpid] < self._attack_confirm:
            print(
                f"  🛡️ [MITIGATION] Entropy ALERT pending confirmation "
                f"({self._entropy_attack_streak[dpid]}/"
                f"{self._attack_confirm} consecutive cycles)"
            )
            # Trace PENDING via verification; do not actuate.
            prediction, explanation = self._build_entropy_mitigation_payload(
                entropy_metrics, feature_batch,
            )
            try:
                self._dispatch_verified_mitigation(
                    dpid=dpid,
                    prediction=prediction,
                    explanation=explanation,
                    flow_features=feature_batch,
                    attack_streak=self._entropy_attack_streak[dpid],
                    warmup_cycles_done=self._warmup_cycles.get(dpid, 0),
                    source_tag="entropy",
                )
            except Exception:
                self.logger.error(
                    "[entropy mitigation hook] Error:\n%s",
                    traceback.format_exc(),
                )
            return

        prediction, explanation = self._build_entropy_mitigation_payload(
            entropy_metrics, feature_batch,
        )
        print(
            f"  🔀 [MITIGATION] Entropy ALERT confirmed — "
            f"hint={explanation['attack_type_hint']}  "
            f"conf={prediction['confidence']:.1f}% "
            f"(entropy={explanation['entropy_conf']:.1f}% "
            f"rate={explanation['rate_conf']:.1f}% "
            f"max_pkt={explanation['max_packet_rate']:.0f}/s)"
        )
        try:
            self._dispatch_verified_mitigation(
                dpid=dpid,
                prediction=prediction,
                explanation=explanation,
                flow_features=feature_batch,
                attack_streak=self._entropy_attack_streak[dpid],
                warmup_cycles_done=self._warmup_cycles.get(dpid, 0),
                source_tag="entropy",
            )
        except Exception:
            self.logger.error(
                "[entropy mitigation hook] Error:\n%s",
                traceback.format_exc(),
            )

    def _dispatch_verified_mitigation(
        self,
        *,
        dpid: int,
        prediction: dict,
        explanation: dict,
        flow_features: list,
        attack_streak: int,
        warmup_cycles_done: int,
        source_tag: str = "ml",
        feature_vector: list | None = None,
    ) -> bool:
        """
        R7+R8(+R5) orchestration:

          VerificationResult
                 │
        ┌────────┴────────┐
        ↓                 ↓
   XAI/RCA→Alert      MitigationEngine

        Alerting/R5 and mitigation are fail-isolated from each other.
        Returns True if handle_alert was invoked.
        """
        if self._mitigation is None:
            return False

        if self._verification is None or not _VERIFICATION_AVAILABLE:
            status = str(prediction.get("status", "NORMAL")).upper()
            if status == "ATTACK" and attack_streak < self._attack_confirm:
                return False
            self._mitigation.handle_alert(
                dpid=dpid,
                prediction=prediction,
                explanation=explanation,
                flow_features=flow_features,
            )
            return True

        min_conf = None
        if str(prediction.get("source", "")).lower() != "entropy":
            try:
                min_conf = float(
                    self._mitigation._min_confidence_to_block(prediction)
                )
            except Exception:
                min_conf = None

        def _on_verified(result):
            if self._alert_manager is None or not _ALERTING_AVAILABLE:
                return
            rca_report_id = None
            extra = {}
            correlation_id = None
            fusion_id = None
            fused = None
            # Only attach last fused decision when this verify came from R6
            if str(source_tag) == "r6_fusion" or (
                isinstance(prediction, dict)
                and prediction.get("source") == "r6_fusion"
            ):
                fused = getattr(self, "_last_fused", {}).get(dpid)
                if isinstance(prediction, dict) and prediction.get("fusion_id"):
                    fusion_id = prediction.get("fusion_id")
                if fused is not None:
                    fusion_id = getattr(fused, "fusion_id", None) or fusion_id
            if _RCA_AVAILABLE:
                try:
                    corr = getattr(self, "_last_correlation", {}).get(dpid)
                    enrichment = safe_enrich_verified_event(
                        result=result,
                        prediction=prediction,
                        explanation=explanation,
                        feature_vector=feature_vector,
                        detector=getattr(self, "_ml_detector", None),
                        store=getattr(self, "_rca_store", None),
                        config=getattr(self, "_rca_config", None),
                        correlation=corr,
                        fused_decision=fused,
                    )
                    rca_report_id = enrichment.rca_report_id
                    extra = dict(enrichment.extra_evidence or {})
                    correlation_id = extra.get("correlation_id") or (
                        getattr(corr, "correlation_id", None) if corr else None
                    )
                    fusion_id = extra.get("fusion_id") or fusion_id
                except Exception:
                    # Belt-and-suspenders: enrichment helper is already fail-safe
                    self.logger.error(
                        "[RCA] enrich failed (isolated):\n%s",
                        traceback.format_exc(),
                    )
                    extra = {"rca_status": "ERROR", "xai_status": "ERROR"}
            else:
                if getattr(self, "_last_correlation", {}).get(dpid) is not None:
                    # R5 package unavailable — still attach compact R4 refs to alerts
                    corr = self._last_correlation.get(dpid)
                    try:
                        ev = getattr(corr, "evidence", None) or {}
                        summary = str(ev.get("summary") or ev.get("reason") or "")[:160]
                        extra.update(
                            {
                                "correlation_linked": True,
                                "correlation_id": corr.correlation_id,
                                "correlation_score": corr.score,
                                "correlation_summary": summary,
                            }
                        )
                        correlation_id = corr.correlation_id
                    except Exception:
                        pass
                if fused is not None:
                    try:
                        from rca.fusion_evidence import fusion_alert_refs

                        extra.update(fusion_alert_refs(fused))
                        fusion_id = fused.fusion_id
                    except Exception:
                        if fusion_id:
                            extra.setdefault("fusion_linked", True)
                            extra.setdefault("fusion_id", fusion_id)
            ctx = build_runtime_alert_context(
                dpid=dpid,
                prediction=prediction,
                explanation=explanation,
                detector_path=source_tag,
                event_id=getattr(result, "event_id", None),
                rca_report_id=rca_report_id,
                correlation_id=correlation_id,
                fusion_id=fusion_id,
                extra_evidence=extra,
            )
            safe_emit_verification_alert(self._alert_manager, result, ctx)

        outcome = run_verified_mitigation(
            engine=self._verification,
            mitigation=self._mitigation,
            dpid=dpid,
            prediction=prediction,
            explanation=explanation,
            flow_features=flow_features,
            warmup_cycles_done=warmup_cycles_done,
            attack_streak=attack_streak,
            min_confidence_percent=min_conf,
            trace_path=self._verification_trace_path,
            source_tag=source_tag,
            on_verified=_on_verified,
        )
        self._last_verification_outcome = outcome
        return bool(outcome.handle_alert_called)

    def _extract_flow_features(self, dpid: int, stat) -> dict | None:
        """
        Extract a structured feature dictionary from a single flow stat entry.

        This is the core feature extraction function — its output is the
        canonical data format passed to all subsequent processing modules.

        Feature Dictionary Schema:
            timestamp     (str)   : ISO-8601 collection time
            switch_id     (int)   : OpenFlow datapath ID
            src_mac       (str)   : Source MAC address
            dst_mac       (str)   : Destination MAC address
            in_port       (int)   : Ingress switch port
            priority      (int)   : Flow rule priority
            packet_count  (int)   : Cumulative packets matched
            byte_count    (int)   : Cumulative bytes matched
            packet_rate   (float) : Packets per second
            byte_rate     (float) : Bytes per second
            duration_sec  (float) : Flow active duration in seconds

        Args:
            dpid : Switch datapath ID.
            stat : OFPFlowStats entry.

        Returns:
            dict | None: Feature dictionary, or None if extraction fails.
        """
        try:
            match        = stat.match
            packet_count = stat.packet_count
            byte_count   = stat.byte_count
            duration     = stat.duration_sec + (stat.duration_nsec / 1_000_000_000)

            # ── Safely extract match fields (may be absent for some flows) ────
            src_mac  = match.get("eth_src",  "unknown")
            dst_mac  = match.get("eth_dst",  "unknown")
            in_port  = match.get("in_port",  0)
            priority = stat.priority

            # ── Traffic Rate Calculation ──────────────────────────────────────
            packet_rate = self.calculate_packet_rate(packet_count, duration)
            byte_rate   = self.calculate_byte_rate(byte_count, duration)

            return {
                "timestamp"    : now_str(),
                "switch_id"    : dpid,
                "src_mac"      : src_mac,
                "dst_mac"      : dst_mac,
                "in_port"      : in_port,
                "priority"     : priority,
                "packet_count" : packet_count,
                "byte_count"   : byte_count,
                "packet_rate"  : round(packet_rate, 4),
                "byte_rate"    : round(byte_rate, 4),
                "duration_sec" : round(duration, 4),
            }

        except Exception:
            self.logger.error(
                "[_extract_flow_features] Feature extraction failed:\n%s",
                traceback.format_exc(),
            )
            return None

    # =========================================================================
    # SECTION 6 — Port Statistics Reply Handler
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev) -> None:
        """
        Process incoming OpenFlow port statistics replies.

        Collects per-port traffic counters from each switch:
          - rx/tx packet counts
          - rx/tx byte totals
          - rx/tx error counts

        Port statistics give a macro-level view of switch load, complementing
        the per-flow granularity from flow stats.

        [HOOK] Phase 2 entropy engine uses per-port byte deltas for
               Shannon entropy calculation on destination IP distributions.

        Args:
            ev: EventOFPPortStatsReply event from OsKen.
        """
        try:
            body     = ev.msg.body
            datapath = ev.msg.datapath
            dpid     = datapath.id

            print("\n" + "-" * 58)
            print(f"  [PORT STATISTICS]  Switch DPID: {dpid}  |  {now_str()}")
            print("-" * 58)

            for stat in body:
                port_no    = stat.port_no
                rx_packets = stat.rx_packets
                tx_packets = stat.tx_packets
                rx_bytes   = stat.rx_bytes
                tx_bytes   = stat.tx_bytes
                rx_errors  = stat.rx_errors
                tx_errors  = stat.tx_errors

                # Skip local/internal pseudo-ports (port 0xFFFFFFFE = LOCAL)
                if port_no == 0xFFFFFFFE:
                    continue

                port_feature = {
                    "timestamp"  : now_str(),
                    "switch_id"  : dpid,
                    "port_no"    : port_no,
                    "rx_packets" : rx_packets,
                    "tx_packets" : tx_packets,
                    "rx_bytes"   : rx_bytes,
                    "tx_bytes"   : tx_bytes,
                    "rx_errors"  : rx_errors,
                    "tx_errors"  : tx_errors,
                }

                self.print_port_statistics(port_feature)
                self.log_to_csv(port_feature, PORT_CSV_LOG_PATH, PORT_CSV_HEADERS)

            print("-" * 58 + "\n")

        except Exception:
            self.logger.error(
                "[_port_stats_reply_handler] Error processing port stats:\n%s",
                traceback.format_exc(),
            )

    # =========================================================================
    # SECTION 7 — Metric Calculation Methods
    # =========================================================================

    def calculate_packet_rate(self, packet_count: int, duration: float) -> float:
        """
        Calculate packets per second for a flow.

        Formula: packet_count / duration_sec

        Args:
            packet_count : Total packets matched by this flow rule.
            duration     : Flow active duration in seconds.

        Returns:
            float: Packet rate in packets/second. Returns 0.0 for zero duration.
        """
        return safe_divide(packet_count, duration)

    def calculate_byte_rate(self, byte_count: int, duration: float) -> float:
        """
        Calculate bytes per second for a flow.

        Formula: byte_count / duration_sec

        Args:
            byte_count : Total bytes matched by this flow rule.
            duration   : Flow active duration in seconds.

        Returns:
            float: Byte rate in bytes/second. Returns 0.0 for zero duration.
        """
        return safe_divide(byte_count, duration)

    # =========================================================================
    # SECTION 8 — Logging & Output Methods
    # =========================================================================

    def print_flow_statistics(self, feature: dict) -> None:
        """
        Print a formatted flow statistics block to console.

        Provides human-readable, research-grade output for each flow entry.
        Format is designed for easy visual inspection during experiments.

        Args:
            feature: Flow feature dictionary from _extract_flow_features().
        """
        print(f"  Switch ID      : {feature['switch_id']}")
        print(f"  Source MAC     : {feature['src_mac']}")
        print(f"  Destination MAC: {feature['dst_mac']}")
        print(f"  In Port        : {feature['in_port']}")
        print(f"  Priority       : {feature['priority']}")
        print(f"  Packets        : {feature['packet_count']}")
        print(f"  Bytes          : {feature['byte_count']}")
        print(f"  Packet Rate    : {feature['packet_rate']:.4f} pkt/s")
        print(f"  Byte Rate      : {feature['byte_rate']:.4f} B/s")
        print(f"  Duration       : {feature['duration_sec']:.4f} sec")
        print("  " + "─" * 48)

    def print_port_statistics(self, port_feature: dict) -> None:
        """
        Print a formatted port statistics block to console.

        Args:
            port_feature: Port feature dictionary from _port_stats_reply_handler().
        """
        print(f"  Port {port_feature['port_no']:>3}  |  "
              f"RX pkt: {port_feature['rx_packets']:>8}  "
              f"TX pkt: {port_feature['tx_packets']:>8}  |  "
              f"RX bytes: {port_feature['rx_bytes']:>10}  "
              f"TX bytes: {port_feature['tx_bytes']:>10}  |  "
              f"Errors: rx={port_feature['rx_errors']} tx={port_feature['tx_errors']}")

    def log_to_csv(self, feature: dict, filepath: str, headers: list) -> None:
        """
        Append a feature dictionary as a row to a CSV log file.

        The CSV is opened in append mode so existing data is never overwritten.
        This is critical for long-running experiment sessions where continuity
        of the time series matters for research analysis.

        Args:
            feature  : Dictionary whose keys match the CSV headers.
            filepath : Path to the target CSV file.
            headers  : Ordered list of column names defining row structure.
        """
        try:
            ensure_csv(filepath, headers)
            with open(filepath, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                # Write only the fields matching our defined headers
                row = {h: feature.get(h, "") for h in headers}
                writer.writerow(row)

        except Exception:
            self.logger.error(
                "[log_to_csv] Failed to write to %s:\n%s",
                filepath, traceback.format_exc(),
            )

    # =========================================================================
    # SECTION 9 — Warning / Anomaly Placeholder Logic
    # =========================================================================

    def _check_flow_thresholds(self, feature: dict) -> None:
        """
        Compare flow metrics against static thresholds and emit warnings.

        IMPORTANT:
            This is a PLACEHOLDER for demonstration purposes only.
            These static thresholds will be replaced in:
              [HOOK] Phase 7 — PPO Reinforcement Learning adaptive thresholds
              [HOOK] Phase 6 — ADWIN-driven dynamic baseline adjustment

        Args:
            feature: Flow feature dictionary.
        """
        dpid        = feature["switch_id"]
        packet_rate = feature["packet_rate"]
        byte_rate   = feature["byte_rate"]

        if packet_rate > (self._rl_adapter.pkt_threshold
                          if self._rl_adapter is not None
                          else PACKET_RATE_WARN_THRESHOLD):
            _pkt_limit = (self._rl_adapter.pkt_threshold
                          if self._rl_adapter is not None
                          else PACKET_RATE_WARN_THRESHOLD)
            self._print_warning(
                dpid,
                f"HIGH PACKET RATE: {packet_rate:.2f} pkt/s "
                f"(threshold={_pkt_limit:.0f}) | "
                f"src={feature['src_mac']} → dst={feature['dst_mac']}"
            )

        if byte_rate > (self._rl_adapter.byte_threshold
                        if self._rl_adapter is not None
                        else BYTE_RATE_WARN_THRESHOLD):
            _byte_limit = (self._rl_adapter.byte_threshold
                           if self._rl_adapter is not None
                           else BYTE_RATE_WARN_THRESHOLD)
            self._print_warning(
                dpid,
                f"HIGH BYTE RATE: {byte_rate:.2f} B/s "
                f"(threshold={_byte_limit:.0f}) | "
                f"src={feature['src_mac']} → dst={feature['dst_mac']}"
            )

    def _print_warning(self, dpid: int, message: str) -> None:
        """
        Print a formatted WARNING alert to the console.

        Args:
            dpid    : Switch datapath ID triggering the warning.
            message : Warning message text.
        """
        print(f"\n  ⚠️  [WARNING] Switch {dpid} — {message}")
        self.logger.warning("[THRESHOLD ALERT] DPID %d — %s", dpid, message)
