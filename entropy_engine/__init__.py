"""
IntelliShield SDN — entropy_engine package
Phase 2: Entropy-Based DDoS Detection Engine

Public API:
    from entropy_engine.entropy_detector   import EntropyDetector, analyze_flow_batch
    from entropy_engine.entropy_calculator import calculate_all_entropy
    from entropy_engine.entropy_utils      import calculate_shannon_entropy
    from entropy_engine.entropy_logger     import init_log_files, log_entropy_metrics
"""

from entropy_engine.entropy_detector   import EntropyDetector, analyze_flow_batch
from entropy_engine.entropy_calculator import (
    calculate_shannon_entropy,
    calculate_all_entropy,
    calculate_src_entropy,
    calculate_dst_entropy,
    calculate_packet_entropy,
    calculate_byte_entropy,
    calculate_flow_entropy,
)
from entropy_engine.entropy_logger import (
    init_log_files,
    log_entropy_metrics,
    log_alert,
    update_baseline,
    read_baseline,
    print_entropy_report,
    print_alert_banner,
)

__all__ = [
    "EntropyDetector",
    "analyze_flow_batch",
    "calculate_shannon_entropy",
    "calculate_all_entropy",
    "calculate_src_entropy",
    "calculate_dst_entropy",
    "calculate_packet_entropy",
    "calculate_byte_entropy",
    "calculate_flow_entropy",
    "init_log_files",
    "log_entropy_metrics",
    "log_alert",
    "update_baseline",
    "read_baseline",
    "print_entropy_report",
    "print_alert_banner",
]
