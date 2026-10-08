#!/usr/bin/env python3
"""
P0.4 — Mitigation strategy selection tests.

Verifies FLOW_PAIR vs SRC_MAC selection matches the documented policy:
  - Targeted floods (SYN/UDP/ICMP/BURST) with known victim → FLOW_PAIR
  - VOLUMETRIC_FLOOD → SRC_MAC
  - Unknown hint with known victim → FLOW_PAIR (surgical default)
  - No victim MAC → SRC_MAC
Plus end-to-end checks that the correct OpenFlow primitive is invoked
and block_type is logged correctly for low/high-volume and hybrid attacks.
"""

import os
import sys
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import mitigation.mitigation_engine as me
from mitigation.mitigation_engine import MitigationEngine

ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"


class _FakeOfproto:
    OFPFC_ADD = 0
    OFPFF_SEND_FLOW_REM = 1
    OFPP_ANY = 0xFFFFFFFF
    OFPG_ANY = 0xFFFFFFFF


class _FakeParser:
    @staticmethod
    def OFPMatch(**kwargs):
        return dict(kwargs)

    @staticmethod
    def OFPFlowMod(**kwargs):
        return dict(kwargs)


class _FakeDatapath:
    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = _FakeOfproto()
        self.ofproto_parser = _FakeParser()
        self.sent = []

    def send_msg(self, mod):
        self.sent.append(mod)


def _flow(src, dst, rate, priority=1):
    return {"src_mac": src, "dst_mac": dst, "packet_rate": rate, "priority": priority}


def _prediction(confidence=95.0, status="ATTACK"):
    return {"status": status, "confidence": confidence}


def _explanation(hint):
    return {"attack_type_hint": hint}


def _engine_with_dp():
    engine = MitigationEngine(auto_mitigate=True)
    dp = _FakeDatapath(dpid=1)
    engine.set_datapaths({1: dp})
    return engine, dp


# ─── Unit: strategy selection matrix ─────────────────────────────────────────

def test_targeted_floods_use_flow_pair():
    engine = MitigationEngine(auto_mitigate=True)
    for hint in ("SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "BURST"):
        assert engine._select_block_strategy(hint, VICTIM) == "FLOW_PAIR", hint


def test_volumetric_flood_uses_src_mac():
    engine = MitigationEngine(auto_mitigate=True)
    assert engine._select_block_strategy("VOLUMETRIC_FLOOD", VICTIM) == "SRC_MAC"


def test_unknown_hint_defaults_to_flow_pair():
    engine = MitigationEngine(auto_mitigate=True)
    assert engine._select_block_strategy("UNKNOWN", VICTIM) == "FLOW_PAIR"
    assert engine._select_block_strategy("UNKNOWN_ANOMALY", VICTIM) == "FLOW_PAIR"


def test_missing_victim_mac_uses_src_mac():
    engine = MitigationEngine(auto_mitigate=True)
    assert engine._select_block_strategy("SYN_FLOOD", "") == "SRC_MAC"
    assert engine._select_block_strategy("VOLUMETRIC_FLOOD", "") == "SRC_MAC"


# ─── E2E: low-volume attack → no block ───────────────────────────────────────

def test_low_volume_attack_no_block():
    """Flow below ATTACK_RATE_THRESHOLD must not trigger any DROP rule."""
    engine, _dp = _engine_with_dp()
    flows = [_flow(ATTACKER, VICTIM, rate=200.0)]  # < 1000 pkt/s
    with mock.patch.object(me, "log_block_action") as log_mock, \
         mock.patch.object(me, "block_flow_pair") as fp_mock, \
         mock.patch.object(me, "block_src_mac") as sm_mock:
        engine.handle_alert(1, _prediction(95.0), _explanation("SYN_FLOOD"), flows)
        assert not fp_mock.called
        assert not sm_mock.called
        assert not log_mock.called


def test_low_confidence_attack_no_block():
    """Confidence below the gate must not trigger any DROP rule."""
    engine, _dp = _engine_with_dp()
    flows = [_flow(ATTACKER, VICTIM, rate=8000.0)]
    with mock.patch.object(me, "block_flow_pair") as fp_mock, \
         mock.patch.object(me, "block_src_mac") as sm_mock:
        engine.handle_alert(1, _prediction(40.0), _explanation("SYN_FLOOD"), flows)
        assert not fp_mock.called
        assert not sm_mock.called


# ─── E2E: high-volume targeted attack → FLOW_PAIR ────────────────────────────

def test_high_volume_syn_flood_flow_pair_block():
    engine, _dp = _engine_with_dp()
    flows = [
        _flow(ATTACKER, VICTIM, rate=9000.0),
        _flow("02:cc:cc:cc:cc:03", VICTIM, rate=50.0),  # bystander
    ]
    logged = []
    with mock.patch.object(me, "log_block_action",
                           side_effect=lambda **kw: logged.append(kw)), \
         mock.patch.object(me, "block_flow_pair", return_value=True) as fp_mock, \
         mock.patch.object(me, "block_src_mac", return_value=True) as sm_mock, \
         mock.patch.object(me, "update_mitigation_summary"):
        engine.handle_alert(1, _prediction(95.0), _explanation("SYN_FLOOD"), flows)

        assert fp_mock.called
        assert not sm_mock.called
        args, kwargs = fp_mock.call_args
        assert args[1] == ATTACKER and args[2] == VICTIM
        assert logged and logged[0]["block_type"] == "FLOW_PAIR"
        assert logged[0]["status"] == "SUCCESS"


# ─── E2E: bidirectional flood (victim reply) → still blocks attacker ─────────

def test_bidirectional_flood_ignores_victim_reverse_flow():
    """
    Non-spoofed SYN / burst floods produce a victim reply flow (h2→h1) at
    nearly the same rate as the attack flow (h1→h2). The reverse flow must
    not mask attacker dominance, otherwise no block is installed.
    """
    engine, _dp = _engine_with_dp()
    flows = [
        _flow(ATTACKER, VICTIM, rate=14223.0),   # h1 → h2 attack
        _flow(VICTIM, ATTACKER, rate=14220.0),   # h2 → h1 victim reply
        _flow("02:cc:cc:cc:cc:03", ATTACKER, rate=5.0),  # background
    ]
    logged = []
    with mock.patch.object(me, "log_block_action",
                           side_effect=lambda **kw: logged.append(kw)), \
         mock.patch.object(me, "block_flow_pair", return_value=True) as fp_mock, \
         mock.patch.object(me, "block_src_mac", return_value=True) as sm_mock, \
         mock.patch.object(me, "update_mitigation_summary"):
        engine.handle_alert(1, _prediction(95.0), _explanation("BURST"), flows)

        assert fp_mock.called, "attacker must be blocked despite victim reply flow"
        assert not sm_mock.called
        args, _kwargs = fp_mock.call_args
        assert args[1] == ATTACKER and args[2] == VICTIM


# ─── E2E: volumetric attack → SRC_MAC ────────────────────────────────────────

def test_volumetric_flood_src_mac_block():
    engine, _dp = _engine_with_dp()
    flows = [
        _flow(ATTACKER, VICTIM, rate=20000.0),
        _flow("02:cc:cc:cc:cc:03", "02:dd:dd:dd:dd:04", rate=100.0),
    ]
    logged = []
    with mock.patch.object(me, "log_block_action",
                           side_effect=lambda **kw: logged.append(kw)), \
         mock.patch.object(me, "block_flow_pair", return_value=True) as fp_mock, \
         mock.patch.object(me, "block_src_mac", return_value=True) as sm_mock, \
         mock.patch.object(me, "update_mitigation_summary"):
        engine.handle_alert(
            1, _prediction(92.0), _explanation("VOLUMETRIC_FLOOD"), flows)

        assert sm_mock.called
        assert not fp_mock.called
        args, kwargs = sm_mock.call_args
        assert args[1] == ATTACKER
        assert logged and logged[0]["block_type"] == "SRC_MAC"
        assert logged[0]["status"] == "SUCCESS"


# ─── E2E: hybrid attack (unknown signature) → FLOW_PAIR surgical default ─────

def test_hybrid_attack_unknown_anomaly_flow_pair():
    engine, _dp = _engine_with_dp()
    flows = [_flow(ATTACKER, VICTIM, rate=6000.0)]
    logged = []
    with mock.patch.object(me, "log_block_action",
                           side_effect=lambda **kw: logged.append(kw)), \
         mock.patch.object(me, "block_flow_pair", return_value=True) as fp_mock, \
         mock.patch.object(me, "block_src_mac", return_value=True) as sm_mock, \
         mock.patch.object(me, "update_mitigation_summary"):
        engine.handle_alert(
            1, _prediction(85.0), _explanation("UNKNOWN_ANOMALY"), flows)

        assert fp_mock.called
        assert not sm_mock.called
        assert logged and logged[0]["block_type"] == "FLOW_PAIR"


# ─── Regression: logging schema unchanged ────────────────────────────────────

def test_block_record_keeps_src_mac_key():
    """SRC_MAC blocks must still be tracked by attacker MAC in blocklist."""
    engine, _dp = _engine_with_dp()
    flows = [_flow(ATTACKER, VICTIM, rate=20000.0)]
    with mock.patch.object(me, "log_block_action"), \
         mock.patch.object(me, "block_src_mac", return_value=True), \
         mock.patch.object(me, "update_mitigation_summary"):
        engine.handle_alert(
            1, _prediction(92.0), _explanation("VOLUMETRIC_FLOOD"), flows)

    assert engine._blocklist.is_blocked(1, ATTACKER)
    record = engine._blocklist.active_blocks()[0]
    assert record.block_type == "SRC_MAC"
    assert record.attack_hint == "VOLUMETRIC_FLOOD"


if __name__ == "__main__":
    tests = [
        test_targeted_floods_use_flow_pair,
        test_volumetric_flood_uses_src_mac,
        test_unknown_hint_defaults_to_flow_pair,
        test_missing_victim_mac_uses_src_mac,
        test_low_volume_attack_no_block,
        test_low_confidence_attack_no_block,
        test_high_volume_syn_flood_flow_pair_block,
        test_volumetric_flood_src_mac_block,
        test_hybrid_attack_unknown_anomaly_flow_pair,
        test_block_record_keeps_src_mac_key,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
