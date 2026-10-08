"""
================================================================================
IntelliShield SDN — Phase 5: Automated Mitigation Engine
================================================================================

File        : mitigation/mitigation_engine.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 5 — Automated DDoS Mitigation

Description:
    Main mitigation orchestrator. Receives Phase 4 ML detection results
    and decides whether to block, how long, and which strategy to use.

    Decision pipeline:
        Phase 4 ATTACK alert
            ↓
        MitigationEngine.handle_alert(dpid, prediction, explanation, flow_features)
            ├─ Extract attacker MAC from flow features
            ├─ Query BlocklistManager.should_block()
            ├─ Select strategy (SRC_MAC or FLOW_PAIR)
            ├─ Calculate timeout (based on confidence)
            ├─ Call flow_blocker.block_src_mac() → install OpenFlow DROP rule
            ├─ Call BlocklistManager.record_block()
            └─ Call MitigationLogger.log_block_action()

    Mitigation strategies:
        AUTO     — system selects best strategy based on attack type
        SRC_MAC  — block all traffic from attacker MAC (aggressive)
        FLOW_PAIR — block only the attack-specific src→dst flow (surgical)

    Confidence-based timeout:
        confidence ≥ 90% → 120s block
        confidence ≥ 75% → 60s block
        confidence ≥ 60% → 30s block
        confidence < 60% → WARNING only (no block)

    [HOOK] Phase 7 → PPO RL replaces confidence thresholds and timeout
                     calculation with a learned policy.

IEEE Relevance:
    Automated reactive mitigation is the primary SDN security capability
    being evaluated. The latency between attack onset and first DROP rule
    installation is a key research metric (typically 5–10 seconds in this
    implementation, driven by the MONITOR_INTERVAL).

================================================================================
"""

import logging
import traceback
from typing import Optional, List, Dict

from mitigation.flow_blocker import (
    block_src_mac,
    block_flow_pair,
    unblock_src_mac,
    unblock_all,
    PROTECTED_MACS,
    BLOCK_PRIORITY,
)
from mitigation.blocklist_manager import BlocklistManager
from mitigation.mitigation_logger import (
    init_mitigation_logs,
    log_block_action,
    log_unblock_action,
    log_skipped,
    update_mitigation_summary,
)

logger = logging.getLogger("intellishield.mitigation_engine")

# ─── Mitigation Thresholds ────────────────────────────────────────────────────
# [HOOK] Phase 7 → PPO RL replaces these with adaptive learned thresholds

MIN_CONFIDENCE_TO_BLOCK = 60.0   # Don't block below this confidence (%)
HIGH_CONFIDENCE         = 90.0   # High confidence → longer block
MED_CONFIDENCE          = 75.0   # Med confidence → standard block
LOW_CONFIDENCE          = 60.0   # Low confidence → short block

# Hard ceiling for RL-adapted mitigation gate (%). Prevents actuation starvation
# when PPO pushes conf_threshold toward 1.0. Ops profile may freeze/lower further.
MAX_RL_CONFIDENCE_GATE_PERCENT = 75.0

TIMEOUT_HIGH    = 120   # seconds
TIMEOUT_MED     = 60
TIMEOUT_LOW     = 30
TIMEOUT_DEFAULT = 60

# Status values that trigger mitigation evaluation
MITIGATE_ON_STATUS = {"ATTACK", "SUSPICIOUS"}

# Only auto-mitigate on ATTACK (not SUSPICIOUS) by default
AUTO_MITIGATE_STATUS = {"ATTACK"}

# Surgical FLOW_PAIR for targeted floods; SRC_MAC for volumetric floods
# (unknown hints default to FLOW_PAIR when the victim MAC is known)
FLOW_PAIR_ATTACK_HINTS = {"SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "BURST"}
SRC_MAC_ATTACK_HINTS = {"VOLUMETRIC_FLOOD"}

# Attacker identification — block only the dominant anomalous flow per alert
ATTACK_RATE_THRESHOLD = 1000.0   # pkt/s minimum to consider a flow malicious
RATE_DOMINANCE_RATIO  = 5.0      # top flow must be N× the second-highest rate
MAX_BLOCKS_PER_ALERT  = 1        # surgical: one DROP rule per alert cycle


def _collapse_flow_pairs(flow_features: List[dict]) -> List[dict]:
    """
    Merge duplicate OpenFlow stats for the same src→dst MAC pair.

    After a FLOW_PAIR DROP rule is installed, OVS may report two entries
    (priority 1 forwarding + priority 200 DROP) for the same flow. Collapsing
    by max packet_rate avoids treating one attack flow as two competitors.
    """
    pairs: Dict[tuple, dict] = {}
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


class MitigationEngine:
    """
    IntelliShield SDN — Automated Mitigation Orchestrator.

    Receives Phase 4 detection results and installs OpenFlow DROP rules
    on the appropriate switch to stop malicious traffic.

    Usage (from flow_monitor.py):
        engine = MitigationEngine()
        engine.set_datapaths(self.datapaths)   # pass controller's datapath dict

        # Called on each monitoring cycle with an ATTACK prediction:
        engine.handle_alert(
            dpid         = dpid,
            prediction   = prediction,      # from AnomalyDetector
            explanation  = explanation,     # from Explainer
            flow_features= feature_batch,   # list of flow dicts
        )
    """

    def __init__(self, auto_mitigate: bool = True):
        """
        Args:
            auto_mitigate: If True, automatically install DROP rules on ATTACK.
                           If False, log alerts only (manual mode).
        """
        self.auto_mitigate = auto_mitigate
        self._datapaths: dict = {}
        self._blocklist = BlocklistManager()
        self._threshold_adapter = None   # [HOOK] Phase 7 — PPO conf_threshold
        self._alert_count = 0
        self._block_count = 0

        init_mitigation_logs()
        logger.info("[MitigationEngine] Initialised.  auto_mitigate=%s", auto_mitigate)

    def set_datapaths(self, datapaths: dict) -> None:
        """
        Inject the controller's datapaths dict reference.

        Called once from flow_monitor.__init__() so the mitigation engine
        always has access to the latest set of connected switches.

        Args:
            datapaths: Dict {dpid: datapath_obj} from IntelliShieldController.
        """
        self._datapaths = datapaths

    def add_whitelist(self, macs: List[str]) -> None:
        """Add MACs to the permanent whitelist (never block)."""
        self._blocklist.add_whitelist(macs)

    def set_threshold_adapter(self, adapter) -> None:
        """
        Inject Phase 7 PPO ThresholdAdapter for adaptive confidence gating.

        When set, MIN_CONFIDENCE_TO_BLOCK is replaced by
        adapter.conf_threshold * 100 (adapter uses 0–1 scale; ML uses 0–100%).
        """
        self._threshold_adapter = adapter
        logger.info(
            "[MitigationEngine] RL confidence gate active — min=%.1f%%",
            self._min_confidence_to_block(),
        )

    def _min_confidence_to_block(self, prediction: dict = None) -> float:
        """
        Minimum confidence (%) required before installing a DROP rule.

        ML / fusion alerts use the PPO adaptive gate (bounded). Entropy-sourced
        alerts use the static floor so RL cannot block mitigation when ML is a
        false negative. Lab ops profile freezes the adaptive gate at the floor.
        """
        if prediction and prediction.get("source") == "entropy":
            return MIN_CONFIDENCE_TO_BLOCK
        if self._threshold_adapter is not None:
            try:
                from shared_contracts.ops_profile import get_ops_policy
                policy = get_ops_policy()
                if policy.freeze_rl_confidence_gate:
                    return MIN_CONFIDENCE_TO_BLOCK
                adapted = float(self._threshold_adapter.conf_threshold) * 100.0
                return min(adapted, MAX_RL_CONFIDENCE_GATE_PERCENT)
            except Exception:
                adapted = float(self._threshold_adapter.conf_threshold) * 100.0
                return min(adapted, MAX_RL_CONFIDENCE_GATE_PERCENT)
        return MIN_CONFIDENCE_TO_BLOCK

    # ─── Main Alert Handler ───────────────────────────────────────────────────

    def handle_alert(self,
                      dpid          : int,
                      prediction    : dict,
                      explanation   : dict,
                      flow_features : List[dict]) -> None:
        """
        Primary entry point called from flow_monitor.py after Phase 4 detection.

        Inspects the prediction result and decides whether to block traffic.

        Args:
            dpid         : Switch datapath ID where traffic was observed.
            prediction   : Dict from AnomalyDetector.predict().
            explanation  : Dict from Explainer.explain().
            flow_features: List of flow feature dicts from Phase 1.
        """
        status     = prediction.get("status",     "NORMAL")
        confidence = prediction.get("confidence", 0.0)
        attack_hint = explanation.get("attack_type_hint", "UNKNOWN")

        self._alert_count += 1

        # Only act on ATTACK or SUSPICIOUS
        if status not in MITIGATE_ON_STATUS:
            return

        # SUSPICIOUS is logged but only ATTACK triggers auto DROP rules
        if self.auto_mitigate and status not in AUTO_MITIGATE_STATUS:
            logger.info(
                "[handle_alert] %s logged — auto-mitigate limited to %s",
                status, sorted(AUTO_MITIGATE_STATUS),
            )
            return

        min_conf = self._min_confidence_to_block(prediction)
        if confidence < min_conf:
            logger.info(
                "[handle_alert] %s but confidence %.1f%% < %.1f%% threshold — no block.",
                status, confidence, min_conf,
            )
            return

        logger.info("[handle_alert] %s detected!  confidence=%.1f%%  hint=%s  dpid=%d",
                    status, confidence, attack_hint, dpid)

        # Extract attacker MACs from flow features
        attacker_macs = self._identify_attackers(flow_features, explanation)

        if not attacker_macs:
            logger.warning("[handle_alert] Could not identify attacker MAC — no block.")
            return

        # Get datapath
        datapath = self._datapaths.get(dpid)
        if datapath is None:
            logger.error("[handle_alert] Datapath not found for dpid=%d", dpid)
            return

        # Block each identified attacker
        timeout = self._calculate_timeout(confidence)

        for src_mac, dst_mac in attacker_macs:
            self._execute_block(
                datapath    = datapath,
                dpid        = dpid,
                src_mac     = src_mac,
                dst_mac     = dst_mac,
                attack_hint = attack_hint,
                confidence  = confidence,
                timeout     = timeout,
            )

        # Update summary stats
        update_mitigation_summary(self._blocklist.get_stats())
        self._blocklist.print_status()

    # ─── Attacker Identification ──────────────────────────────────────────────

    def _identify_attackers(self,
                             flow_features: List[dict],
                             explanation  : dict) -> List[tuple]:
        """
        Identify the single most likely attack flow (src_mac, dst_mac).

        Returns at most one pair: the highest packet-rate flow that clearly
        dominates all other flows. Avoids blocking victims (h2) or bystanders
        (h3) when one attacker flow (h1→h2) carries the flood.
        """
        if not flow_features:
            return []

        collapsed = _collapse_flow_pairs(flow_features)
        candidates = [
            f for f in collapsed
            if f.get("src_mac") not in PROTECTED_MACS
            and f.get("dst_mac")
            and str(f.get("dst_mac", "")).lower() not in ("unknown", "")
            and int(f.get("priority", 1)) < BLOCK_PRIORITY
        ]
        if not candidates:
            return []

        sorted_flows = sorted(
            candidates,
            key=lambda f: float(f.get("packet_rate", 0)),
            reverse=True,
        )
        top       = sorted_flows[0]
        top_rate  = float(top.get("packet_rate", 0))
        src_mac   = top.get("src_mac", "")
        dst_mac   = top.get("dst_mac", "")

        if top_rate < ATTACK_RATE_THRESHOLD:
            return []

        # Highest INDEPENDENT competing flow. The victim's reverse response
        # (dst→src of the top flow) mirrors the attack rate for non-spoofed
        # SYN and burst floods; counting it here would mask dominance and skip
        # the block. It is part of the same attack conversation, not a
        # separate legitimate flow, so it is excluded from the comparison.
        second_rate = 0.0
        for flow in sorted_flows[1:]:
            is_victim_reverse = (
                flow.get("src_mac") == dst_mac
                and flow.get("dst_mac") == src_mac
            )
            if is_victim_reverse:
                continue
            second_rate = float(flow.get("packet_rate", 0))
            break

        if second_rate > 0 and (top_rate / second_rate) < RATE_DOMINANCE_RATIO:
            logger.info(
                "[identify_attackers] Top flow %.0f pkt/s not dominant enough "
                "over second %.0f pkt/s (need %.1f×) — skip.",
                top_rate, second_rate, RATE_DOMINANCE_RATIO,
            )
            return []

        logger.info(
            "[identify_attackers] Dominant attack flow: %s → %s  %.0f pkt/s",
            src_mac, dst_mac, top_rate,
        )
        return [(src_mac, dst_mac)]

    def _calculate_timeout(self, confidence: float) -> int:
        """
        Calculate block duration based on detection confidence.

        Higher confidence → longer block (more certain it's a real attack).
        [HOOK] Phase 7 → PPO RL replaces this mapping with a learned policy.

        Args:
            confidence: Detection confidence (0–100).

        Returns:
            int: Block timeout in seconds.
        """
        if confidence >= HIGH_CONFIDENCE:
            return TIMEOUT_HIGH
        elif confidence >= MED_CONFIDENCE:
            return TIMEOUT_MED
        elif confidence >= LOW_CONFIDENCE:
            return TIMEOUT_LOW
        return TIMEOUT_DEFAULT

    def _select_block_strategy(self, attack_hint: str, dst_mac: str) -> str:
        """
        Choose SRC_MAC (aggressive) vs FLOW_PAIR (surgical) blocking.

        Targeted floods (SYN/UDP/ICMP/BURST) use FLOW_PAIR when the victim
        MAC is known. Volumetric floods use SRC_MAC: the attacker saturates
        bandwidth across destinations, and the blocklist is keyed by src_mac,
        so a single FLOW_PAIR rule would leave other victim flows unblocked.
        """
        if not dst_mac:
            return "SRC_MAC"
        if attack_hint in FLOW_PAIR_ATTACK_HINTS:
            return "FLOW_PAIR"
        if attack_hint in SRC_MAC_ATTACK_HINTS:
            return "SRC_MAC"
        # ML explainer uses UNKNOWN_ANOMALY; entropy may use UNKNOWN —
        # surgical pair is the safe default when the victim MAC is known
        if attack_hint in ("UNKNOWN", "UNKNOWN_ANOMALY"):
            return "FLOW_PAIR"
        return "FLOW_PAIR"

    def on_flow_removed(self, dpid: int, src_mac: str,
                        dst_mac: str = "", reason: str = "rule_expired") -> None:
        """
        Sync blocklist when an OpenFlow DROP rule expires (FlowRemoved event).

        Called from flow_monitor.py when a high-priority mitigation rule
        is removed by the switch after hard_timeout.
        """
        if not src_mac:
            return
        if self._blocklist.record_unblock(dpid, src_mac):
            log_unblock_action(
                dpid, src_mac,
                reason=reason,
                status="EXPIRED",
            )
            logger.info(
                "[on_flow_removed] Block expired: dpid=%d  mac=%s  reason=%s",
                dpid, src_mac, reason,
            )

    # ─── Block Execution ──────────────────────────────────────────────────────

    def _execute_block(self,
                        datapath   ,
                        dpid       : int,
                        src_mac    : str,
                        dst_mac    : str,
                        attack_hint: str,
                        confidence : float,
                        timeout    : int) -> None:
        """Install a DROP rule and record the block."""
        if not self._blocklist.should_block(dpid, src_mac):
            log_skipped(dpid, src_mac,
                        "already_blocked" if self._blocklist.is_blocked(dpid, src_mac)
                        else "whitelisted")
            return

        if not self.auto_mitigate:
            logger.info("[execute_block] Manual mode — alert logged, no DROP rule installed.")
            log_block_action(dpid, src_mac, attack_hint, confidence, timeout,
                             status="SKIPPED", reason="manual_mode")
            return

        try:
            strategy = self._select_block_strategy(attack_hint, dst_mac)
            if strategy == "FLOW_PAIR" and dst_mac:
                success = block_flow_pair(datapath, src_mac, dst_mac, timeout=timeout)
                block_type = "FLOW_PAIR"
            else:
                success = block_src_mac(datapath, src_mac, timeout=timeout)
                block_type = "SRC_MAC"

            if success:
                self._block_count += 1
                self._blocklist.record_block(
                    dpid        = dpid,
                    mac         = src_mac,
                    timeout_sec = timeout,
                    block_type  = block_type,
                    attack_hint = attack_hint,
                    confidence  = confidence,
                    dst_mac     = dst_mac,
                )
                log_block_action(
                    dpid        = dpid,
                    src_mac     = src_mac,
                    attack_hint = attack_hint,
                    confidence  = confidence,
                    timeout_sec = timeout,
                    status      = "SUCCESS",
                    block_type  = block_type,
                    dst_mac     = dst_mac,
                )
            else:
                log_block_action(
                    dpid        = dpid,
                    src_mac     = src_mac,
                    attack_hint = attack_hint,
                    confidence  = confidence,
                    timeout_sec = timeout,
                    status      = "FAILED",
                    reason      = "ofp_flowmod_error",
                )

        except Exception:
            logger.error("[_execute_block] %s", traceback.format_exc())

    # ─── Manual Unblock ───────────────────────────────────────────────────────

    def unblock_mac(self, dpid: int, mac: str, reason: str = "MANUAL") -> bool:
        """
        Manually unblock a MAC on a switch before its timeout expires.

        Args:
            dpid  : Switch datapath ID.
            mac   : MAC to unblock.
            reason: Reason string for logging.

        Returns:
            bool: True if unblock succeeded.
        """
        datapath = self._datapaths.get(dpid)
        if datapath is None:
            logger.error("[unblock_mac] Datapath not found: dpid=%d", dpid)
            return False

        ok = unblock_src_mac(datapath, mac)
        self._blocklist.record_unblock(dpid, mac)
        log_unblock_action(dpid, mac, reason=reason,
                           status="SUCCESS" if ok else "FAILED")
        return ok

    def unblock_all_on_switch(self, dpid: int) -> bool:
        """Emergency: remove all DROP rules from a switch."""
        datapath = self._datapaths.get(dpid)
        if datapath is None:
            return False
        return unblock_all(datapath)

    # ─── Stats ────────────────────────────────────────────────────────────────

    def get_session_stats(self) -> dict:
        """Return session-level mitigation statistics."""
        return {
            "total_alerts"  : self._alert_count,
            "total_blocks"  : self._block_count,
            "active_blocks" : len(self._blocklist.active_blocks()),
            **self._blocklist.get_stats(),
        }

    def print_session_summary(self) -> None:
        """Print end-of-session mitigation summary."""
        stats = self.get_session_stats()
        print("\n" + "=" * 56)
        print("  [MITIGATION SESSION SUMMARY]")
        print("=" * 56)
        print(f"  Total alerts received : {stats['total_alerts']}")
        print(f"  Total blocks installed: {stats['total_blocks']}")
        print(f"  Currently active      : {stats['active_blocks']}")
        print(f"  Auto-mitigate mode    : {self.auto_mitigate}")
        print("=" * 56 + "\n")
