"""
================================================================================
IntelliShield SDN — Phase 7: PPO RL Engine Package
================================================================================
Adaptive threshold control via Proximal Policy Optimization.

Exports:
    PPOAgent          — Core PPO with NumPy MLP + Adam optimizer
    SDNEnvironment    — State builder and reward function
    ThresholdAdapter  — Manages and applies adaptive thresholds
    RLLogger          — CSV logging for RL decisions and training
================================================================================
"""

try:
    from .ppo_agent         import PPOAgent
    from .rl_env            import SDNEnvironment
    from .threshold_adapter import ThresholdAdapter
    from .rl_logger         import RLLogger

    _RL_ENGINE_AVAILABLE = True
    __all__ = ["PPOAgent", "SDNEnvironment", "ThresholdAdapter",
               "RLLogger", "_RL_ENGINE_AVAILABLE"]
except ImportError as _e:
    _RL_ENGINE_AVAILABLE = False
    __all__ = ["_RL_ENGINE_AVAILABLE"]
