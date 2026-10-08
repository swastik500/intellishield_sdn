"""
IntelliShield SDN — ml_models package
Phase 4: ML-Based Anomaly Detection

Public API:
    from ml_models.anomaly_detector import AnomalyDetector
    from ml_models.feature_builder  import FeatureBuilder, FEATURE_NAMES
    from ml_models.model_trainer    import ModelTrainer
    from ml_models.explainer        import Explainer
    from ml_models.ml_logger        import init_ml_logs, log_prediction

Standalone training:
    python3 -m ml_models.model_trainer --synthetic
"""

from ml_models.anomaly_detector import AnomalyDetector
from ml_models.feature_builder  import FeatureBuilder, FEATURE_NAMES
from ml_models.model_trainer    import ModelTrainer
from ml_models.explainer        import Explainer
from ml_models.ml_logger        import (
    init_ml_logs,
    log_prediction,
    log_ml_alert,
    print_ml_result,
)

__all__ = [
    "AnomalyDetector",
    "FeatureBuilder",
    "FEATURE_NAMES",
    "ModelTrainer",
    "Explainer",
    "init_ml_logs",
    "log_prediction",
    "log_ml_alert",
    "print_ml_result",
]
