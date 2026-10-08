"""
IntelliShield SDN — traffic_generator package
Phase 3: Traffic Generation & Attack Simulation Engine

Public API:
    from traffic_generator.normal_traffic    import NormalTrafficGenerator
    from traffic_generator.attack_generator  import AttackGenerator
    from traffic_generator.attack_scenarios  import run_scenario, SCENARIO_REGISTRY
    from traffic_generator.traffic_scheduler import TrafficScheduler
    from traffic_generator.traffic_profiles  import ATTACK_PROFILES, NORMAL_PROFILES
    from traffic_generator.traffic_logger    import init_traffic_logs

Standalone usage:
    sudo python3 -m traffic_generator.traffic_scheduler --scenario 2
"""

from traffic_generator.normal_traffic    import NormalTrafficGenerator
from traffic_generator.attack_generator  import AttackGenerator
from traffic_generator.attack_scenarios  import run_scenario, SCENARIO_REGISTRY
from traffic_generator.traffic_scheduler import TrafficScheduler
from traffic_generator.traffic_profiles  import (
    ATTACK_PROFILES, NORMAL_PROFILES, SCENARIO_TEMPLATES,
    AttackProfile, NormalTrafficProfile,
)
from traffic_generator.traffic_logger    import (
    init_traffic_logs,
    log_traffic_event,
    log_attack_event,
    log_scenario_event,
)

__all__ = [
    "NormalTrafficGenerator",
    "AttackGenerator",
    "TrafficScheduler",
    "run_scenario",
    "SCENARIO_REGISTRY",
    "ATTACK_PROFILES",
    "NORMAL_PROFILES",
    "SCENARIO_TEMPLATES",
    "AttackProfile",
    "NormalTrafficProfile",
    "init_traffic_logs",
    "log_traffic_event",
    "log_attack_event",
    "log_scenario_event",
]
