"""
SSL Zero-Day (Self-Supervised Learning) Anomaly Detection Package for IntelliShield SDN.

Provides zero-day DDoS anomaly detection using a lightweight MLPRegressor autoencoder
reconstruction pipeline trained strictly on normal traffic baseline features.
"""

from ssl_zero_day.autoencoder import SSLAutoencoder
from ssl_zero_day.detector import SSLZeroDayDetector
from ssl_zero_day.feature_window import (
    FEATURE_NAMES,
    N_FEATURES,
    FeatureWindow,
    sanitize_15d_vector,
    validate_15d_vector,
)
from ssl_zero_day.logger import SSLLogger
from ssl_zero_day.scorer import SSLScorer
from ssl_zero_day.threshold import SSLThresholdCalibrator
from ssl_zero_day.trainer import SSLTrainer

__all__ = [
    "FEATURE_NAMES",
    "N_FEATURES",
    "FeatureWindow",
    "validate_15d_vector",
    "sanitize_15d_vector",
    "SSLAutoencoder",
    "SSLTrainer",
    "SSLScorer",
    "SSLThresholdCalibrator",
    "SSLZeroDayDetector",
    "SSLLogger",
]
