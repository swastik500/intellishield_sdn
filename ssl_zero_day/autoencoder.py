"""
SSL Autoencoder using scikit-learn MLPRegressor for 15-D feature reconstruction.

Architecture:
  Input (15-D) → StandardScaler → MLPRegressor (Autoencoder bottleneck X → X)
  Reconstruction MSE = mean((X_scaled - X_reconstructed_scaled)^2, axis=1)

No PyTorch dependency; pure scikit-learn + numpy.
"""

from __future__ import annotations

import logging
import os
import pickle
import numpy as np
from typing import List, Optional, Sequence, Tuple, Union

from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ssl_zero_day.feature_window import N_FEATURES, sanitize_15d_vector

logger = logging.getLogger("intellishield.ssl_zero_day.autoencoder")


class SSLAutoencoder:
    """
    Self-Supervised Autoencoder model for 15-D feature vector reconstruction.

    Learns normal baseline traffic patterns by training to reconstruct normal vectors (X -> X).
    """

    def __init__(
        self,
        hidden_layer_sizes: Tuple[int, ...] = (12, 6, 12),
        max_iter: int = 500,
        random_state: int = 42,
        alpha: float = 0.0001,
        learning_rate_init: float = 0.001,
        early_stopping: bool = True,
        n_iter_no_change: int = 15,
    ) -> None:
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter
        self.random_state = random_state
        self.alpha = alpha
        self.learning_rate_init = learning_rate_init
        self.early_stopping = early_stopping
        self.n_iter_no_change = n_iter_no_change

        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[MLPRegressor] = None
        self.is_fitted: bool = False

    def _init_components(self) -> None:
        self.scaler = StandardScaler()
        self.model = MLPRegressor(
            hidden_layer_sizes=self.hidden_layer_sizes,
            activation="relu",
            solver="adam",
            alpha=self.alpha,
            learning_rate_init=self.learning_rate_init,
            max_iter=self.max_iter,
            random_state=self.random_state,
            early_stopping=False,
            tol=1e-3,
            warm_start=False,
        )

    def fit(self, X: Union[List[List[float]], np.ndarray]) -> SSLAutoencoder:
        """
        Fit scaler and MLPRegressor autoencoder on normal-only 15-D samples (X -> X).

        Args:
            X: Array/list of 15-D feature vectors (normal training data).

        Returns:
            self
        """
        if X is None or len(X) == 0:
            raise ValueError("Training data X cannot be empty")

        X_clean = np.array([sanitize_15d_vector(v) for v in X], dtype=float)
        if X_clean.shape[1] != N_FEATURES:
            raise ValueError(f"Expected {N_FEATURES} features, got {X_clean.shape[1]}")

        self._init_components()
        assert self.scaler is not None and self.model is not None

        # Fit standard scaler on normal inputs
        X_scaled = self.scaler.fit_transform(X_clean)

        # Train MLPRegressor autoencoder: target is the scaled input itself (X -> X)
        self.model.fit(X_scaled, X_scaled)
        self.is_fitted = True

        logger.info(
            "[SSLAutoencoder] Trained autoencoder on %d samples (loss: %.6f, n_iter: %d)",
            len(X_clean),
            float(self.model.loss_),
            int(self.model.n_iter_),
        )
        return self

    def reconstruct(self, X: Union[Sequence[float], List[List[float]], np.ndarray]) -> np.ndarray:
        """
        Reconstruct 15-D feature vectors in original feature space.

        Args:
            X: Single vector or 2D array of vectors.

        Returns:
            2D numpy array of reconstructed vectors.
        """
        if not self.is_fitted or self.scaler is None or self.model is None:
            raise RuntimeError("SSLAutoencoder is not fitted yet")

        arr = np.array(X, dtype=float)
        if arr.ndim == 1:
            arr = np.array([sanitize_15d_vector(arr)], dtype=float)
        else:
            arr = np.array([sanitize_15d_vector(v) for v in arr], dtype=float)

        X_scaled = self.scaler.transform(arr)
        recon_scaled = self.model.predict(X_scaled)
        if recon_scaled.ndim == 1:
            recon_scaled = recon_scaled.reshape(1, -1)

        # Inverse transform back to original feature scale
        recon_original = self.scaler.inverse_transform(recon_scaled)
        return recon_original

    def compute_mse(self, X: Union[Sequence[float], List[List[float]], np.ndarray]) -> np.ndarray:
        """
        Compute reconstruction Mean Squared Error (MSE) in normalized feature space.

        Args:
            X: Single vector or 2D array of 15-D feature vectors.

        Returns:
            1D numpy array of MSE scores for each sample.
        """
        if not self.is_fitted or self.scaler is None or self.model is None:
            raise RuntimeError("SSLAutoencoder is not fitted yet")

        arr = np.array(X, dtype=float)
        if arr.ndim == 1:
            arr = np.array([sanitize_15d_vector(arr)], dtype=float)
        else:
            arr = np.array([sanitize_15d_vector(v) for v in arr], dtype=float)

        X_scaled = self.scaler.transform(arr)
        recon_scaled = self.model.predict(X_scaled)
        if recon_scaled.ndim == 1:
            recon_scaled = recon_scaled.reshape(1, -1)

        # MSE calculated per sample across all 15 normalized dimensions
        mse = np.mean((X_scaled - recon_scaled) ** 2, axis=1)
        return mse

    def save(self, filepath: str) -> None:
        """Save fitted autoencoder and scaler to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        state = {
            "hidden_layer_sizes": self.hidden_layer_sizes,
            "max_iter": self.max_iter,
            "random_state": self.random_state,
            "alpha": self.alpha,
            "learning_rate_init": self.learning_rate_init,
            "scaler": self.scaler,
            "model": self.model,
            "is_fitted": self.is_fitted,
        }
        with open(filepath, "wb") as f:
            pickle.dump(state, f)
        logger.info("[SSLAutoencoder] Saved autoencoder state to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> SSLAutoencoder:
        """Load autoencoder instance from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")

        with open(filepath, "rb") as f:
            state = pickle.load(f)

        instance = cls(
            hidden_layer_sizes=state.get("hidden_layer_sizes", (10, 5, 10)),
            max_iter=state.get("max_iter", 300),
            random_state=state.get("random_state", 42),
            alpha=state.get("alpha", 0.0001),
            learning_rate_init=state.get("learning_rate_init", 0.001),
        )
        instance.scaler = state.get("scaler")
        instance.model = state.get("model")
        instance.is_fitted = state.get("is_fitted", False)
        return instance
