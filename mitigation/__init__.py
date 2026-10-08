"""
IntelliShield SDN — mitigation package
Phase 5: Automated Mitigation Engine

Public API:
    from mitigation.mitigation_engine  import MitigationEngine
    from mitigation.flow_blocker       import block_src_mac, unblock_src_mac
    from mitigation.blocklist_manager  import BlocklistManager
    from mitigation.mitigation_logger  import init_mitigation_logs

Integration with flow_monitor.py:
    engine = MitigationEngine(auto_mitigate=True)
    engine.set_datapaths(self.datapaths)
    engine.handle_alert(dpid, prediction, explanation, flow_features)
"""

from mitigation.mitigation_engine  import MitigationEngine
from mitigation.flow_blocker       import (
    block_src_mac, block_flow_pair,
    unblock_src_mac, unblock_all,
    BLOCK_PRIORITY, DEFAULT_BLOCK_TIMEOUT,
)
from mitigation.blocklist_manager  import BlocklistManager, BlockRecord
from mitigation.mitigation_logger  import (
    init_mitigation_logs,
    log_block_action,
    log_unblock_action,
)

__all__ = [
    "MitigationEngine",
    "BlocklistManager",
    "BlockRecord",
    "block_src_mac",
    "block_flow_pair",
    "unblock_src_mac",
    "unblock_all",
    "BLOCK_PRIORITY",
    "DEFAULT_BLOCK_TIMEOUT",
    "init_mitigation_logs",
    "log_block_action",
    "log_unblock_action",
]
