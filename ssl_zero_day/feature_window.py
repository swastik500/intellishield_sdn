"""
Feature window and 15-dimensional vector validation for SSL Zero-Day detector.

Uses the repository's 15-feature schema exactly as-is without altering order or dimensions:
 1. packet_rate_mean
 2. packet_rate_max
 3. byte_rate_mean
 4. byte_rate_max
 5. flow_count
 6. duration_mean
 7. unique_src_count
 8. unique_dst_count
 9. src_entropy
10. dst_entropy
11. packet_entropy
12. byte_entropy
13. flow_entropy
14. entropy_score
15. flow_concentration
"""

from __future__ import annotations

import math
from collections import deque
from typing import List, Sequence, Tuple

import numpy as np

# Standard 15-D feature schema matching ml_models.feature_builder.FEATURE_NAMES
FEATURE_NAMES: List[str] = [
    "packet_rate_mean",
    "packet_rate_max",
    "byte_rate_mean",
    "byte_rate_max",
    "flow_count",
    "duration_mean",
    "unique_src_count",
    "unique_dst_count",
    "src_entropy",
    "dst_entropy",
    "packet_entropy",
    "byte_entropy",
    "flow_entropy",
    "entropy_score",
    "flow_concentration",
]

N_FEATURES = len(FEATURE_NAMES)  # 15


def validate_15d_vector(vec: Sequence[float]) -> bool:
    """Check if input vector is a valid 15-dimensional numerical sequence."""
    if vec is None or not isinstance(vec, (list, tuple, np.ndarray)):
        return False
    if len(vec) != N_FEATURES:
        return False
    for val in vec:
        try:
            fval = float(val)
            if not math.isfinite(fval):
                return False
        except (TypeError, ValueError):
            return False
    return True


def sanitize_15d_vector(vec: Sequence[float]) -> List[float]:
    """Sanitize a 15-dimensional vector, replacing non-finite values with 0.0."""
    if vec is None:
        return [0.0] * N_FEATURES
    
    out: List[float] = []
    for i in range(N_FEATURES):
        if i < len(vec):
            try:
                fval = float(vec[i])
                out.append(fval if math.isfinite(fval) else 0.0)
            except (TypeError, ValueError):
                out.append(0.0)
        else:
            out.append(0.0)
    return out


class FeatureWindow:
    """Sliding window buffer for 15-dimensional feature vectors."""

    def __init__(self, window_size: int = 10) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self.window_size = window_size
        self._buffer: deque[List[float]] = deque(maxlen=window_size)

    def add_vector(self, vec: Sequence[float]) -> List[float]:
        """Sanitize and append a 15-D feature vector to the window."""
        sanitized = sanitize_15d_vector(vec)
        self._buffer.append(sanitized)
        return sanitized

    def clear(self) -> None:
        """Clear the window buffer."""
        self._buffer.clear()

    def get_matrix(self) -> np.ndarray:
        """Return array of shape (N, 15) for accumulated window samples."""
        if not self._buffer:
            return np.zeros((0, N_FEATURES), dtype=float)
        return np.array(list(self._buffer), dtype=float)

    def get_latest(self) -> List[float]:
        """Get the most recently added vector or zero vector if empty."""
        if not self._buffer:
            return [0.0] * N_FEATURES
        return list(self._buffer[-1])

    @property
    def current_size(self) -> int:
        return len(self._buffer)

    @property
    def is_full(self) -> bool:
        return len(self._buffer) == self.window_size
