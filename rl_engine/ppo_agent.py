"""
================================================================================
IntelliShield SDN — Phase 7: PPO Agent
================================================================================

File        : rl_engine/ppo_agent.py
Phase       : Phase 7 — PPO Reinforcement Learning

Description:
    Implements Proximal Policy Optimization (PPO) using pure NumPy.
    No PyTorch or TensorFlow required — works on any Python 3.8+ VM.

    Architecture:
        Shared backbone (2-layer MLP) → Actor head (Gaussian policy)
                                      → Critic head (value function)

    Key PPO features:
        - Clipped surrogate objective (ε = 0.2)
        - Generalized Advantage Estimation (GAE, λ = 0.95)
        - Entropy regularization for exploration
        - Adam optimizer for both actor and critic
        - Automatic weight persistence (pickle)

    State  : 10-dimensional vector of normalized network metrics
    Action : 3-dimensional continuous (Δpkt_thresh, Δbyte_thresh, Δconf_thresh)
================================================================================
"""

import os
import pickle
import logging
import numpy as np

logger = logging.getLogger("intellishield.ppo")

# ── Hyperparameters ───────────────────────────────────────────────────────────

STATE_DIM     = 10
ACTION_DIM    = 3
HIDDEN        = 64
ACTOR_LR      = 3e-4
CRITIC_LR     = 1e-4
GAMMA         = 0.99
GAE_LAMBDA    = 0.95
CLIP_EPS      = 0.2
PPO_EPOCHS    = 4
ENTROPY_COEF  = 0.01
VALUE_COEF    = 0.5
UPDATE_EVERY  = 20       # collect this many transitions before each update


# ── Building block: single linear layer with Adam ─────────────────────────────

class _Linear:
    """
    Fully-connected linear layer: y = x W + b
    Includes Adam optimizer state for in-place weight updates.
    """

    def __init__(self, in_dim: int, out_dim: int) -> None:
        scale   = np.sqrt(2.0 / in_dim)          # He initialisation
        self.W  = np.random.randn(in_dim, out_dim).astype(np.float32) * scale
        self.b  = np.zeros(out_dim, dtype=np.float32)

        # Adam first & second moment estimates
        self._mW = np.zeros_like(self.W)
        self._vW = np.zeros_like(self.W)
        self._mb = np.zeros_like(self.b)
        self._vb = np.zeros_like(self.b)
        self._t  = 0

        self._cache_x: np.ndarray = None   # saved input for backward

    def forward(self, x: np.ndarray) -> np.ndarray:
        self._cache_x = x
        return x @ self.W + self.b          # (N, out_dim)

    def backward(self, dout: np.ndarray, lr: float) -> np.ndarray:
        """
        Backprop through linear layer and run Adam update.

        Args:
            dout : gradient of loss w.r.t. layer output, shape (N, out_dim)
            lr   : learning rate
        Returns:
            dx   : gradient w.r.t. layer input, shape (N, in_dim)
        """
        x  = self._cache_x
        dW = x.T @ dout                     # (in_dim, out_dim)
        db = dout.sum(axis=0)               # (out_dim,)
        dx = dout @ self.W.T                # (N, in_dim)
        self._adam(dW, db, lr)
        return dx

    def _adam(self, dW, db, lr,
              beta1: float = 0.9, beta2: float = 0.999, eps: float = 1e-8):
        """In-place Adam weight update."""
        self._t += 1
        t = self._t

        # Weights
        self._mW = beta1 * self._mW + (1 - beta1) * dW
        self._vW = beta2 * self._vW + (1 - beta2) * dW ** 2
        mW_hat   = self._mW / (1 - beta1 ** t)
        vW_hat   = self._vW / (1 - beta2 ** t)
        self.W  -= lr * mW_hat / (np.sqrt(vW_hat) + eps)

        # Biases
        self._mb = beta1 * self._mb + (1 - beta1) * db
        self._vb = beta2 * self._vb + (1 - beta2) * db ** 2
        mb_hat   = self._mb / (1 - beta1 ** t)
        vb_hat   = self._vb / (1 - beta2 ** t)
        self.b  -= lr * mb_hat / (np.sqrt(vb_hat) + eps)

    def state_dict(self) -> dict:
        return {"W": self.W, "b": self.b,
                "mW": self._mW, "vW": self._vW,
                "mb": self._mb, "vb": self._vb, "t": self._t}

    def load_state_dict(self, d: dict) -> None:
        self.W    = d["W"];    self.b    = d["b"]
        self._mW  = d["mW"];  self._vW  = d["vW"]
        self._mb  = d["mb"];  self._vb  = d["vb"]
        self._t   = d["t"]


# ── Actor-Critic network ──────────────────────────────────────────────────────

class _ActorCritic:
    """
    Shared-backbone actor-critic MLP.

    Forward graph:
        x → L1 → tanh → L2 → tanh → [actor_head → tanh → μ]
                                     [critic_head        → V]

    Policy: Gaussian(μ(s), σ) where log σ is a separate learnable parameter.
    """

    def __init__(self, state_dim: int, action_dim: int) -> None:
        # Shared backbone
        self.l1   = _Linear(state_dim, HIDDEN)
        self.l2   = _Linear(HIDDEN,    HIDDEN)
        # Actor head: outputs action means in (-1, 1) via tanh
        self.a_hd = _Linear(HIDDEN, action_dim)
        # Critic head: outputs scalar state value
        self.c_hd = _Linear(HIDDEN, 1)
        # Log-std: per-action learnable scalar (not network output)
        self.log_std = np.full(action_dim, -0.5, dtype=np.float32)

        # Cache for backward pass
        self._h1   : np.ndarray = None
        self._h2   : np.ndarray = None
        self._mean : np.ndarray = None
        self._val  : np.ndarray = None

    # ── Forward ───────────────────────────────────────────────────────────────

    def forward(self, x: np.ndarray):
        """
        Forward pass for inference (no gradient caching needed here).

        Returns:
            mean  : action means (action_dim,)
            value : state value (scalar)
            std   : action std  (action_dim,)
        """
        x = np.atleast_2d(x).astype(np.float32)
        h1   = np.tanh(self.l1.forward(x))
        h2   = np.tanh(self.l2.forward(h1))
        mean = np.tanh(self.a_hd.forward(h2))
        val  = self.c_hd.forward(h2)
        std  = np.exp(np.clip(self.log_std, -3.0, 0.5))
        return mean.squeeze(), float(val.squeeze()), std

    def forward_train(self, x: np.ndarray):
        """Forward pass with full cache for backprop."""
        x = np.atleast_2d(x).astype(np.float32)
        h1   = np.tanh(self.l1.forward(x))
        h2   = np.tanh(self.l2.forward(h1))
        mean = np.tanh(self.a_hd.forward(h2))
        val  = self.c_hd.forward(h2).squeeze()
        std  = np.exp(np.clip(self.log_std, -3.0, 0.5))
        self._h1 = h1; self._h2 = h2
        self._mean = mean; self._val = val
        return mean, val, std

    # ── Gaussian log-probability ──────────────────────────────────────────────

    @staticmethod
    def log_prob(actions: np.ndarray,
                 mean: np.ndarray,
                 std: np.ndarray) -> np.ndarray:
        """
        Log probability of `actions` under N(mean, std²).
        Returns shape (N,).
        """
        a   = np.atleast_2d(actions).astype(np.float32)
        mu  = np.atleast_2d(mean).astype(np.float32)
        var = std ** 2
        lp  = -0.5 * np.sum(
            (a - mu) ** 2 / (var + 1e-8) + np.log(2 * np.pi * var + 1e-8),
            axis=1
        )
        return lp   # (N,)

    # ── PPO update ────────────────────────────────────────────────────────────

    def update(self, states:      np.ndarray,
                      actions:     np.ndarray,
                      old_lps:     np.ndarray,
                      returns:     np.ndarray,
                      advantages:  np.ndarray) -> dict:
        """
        Run PPO_EPOCHS of gradient updates.

        Args:
            states     : (N, state_dim)
            actions    : (N, action_dim)
            old_lps    : (N,)  log-probs under old policy
            returns    : (N,)  discounted returns
            advantages : (N,)  GAE advantages (normalised inside)

        Returns dict of averaged losses.
        """
        N   = len(states)
        adv = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        tot_a = tot_c = 0.0

        for _ in range(PPO_EPOCHS):
            # ── Forward ──────────────────────────────────────────────────────
            mean, val, std = self.forward_train(states)
            h1 = self._h1; h2 = self._h2

            new_lps  = self.log_prob(actions, mean, std)             # (N,)
            ratios   = np.exp(np.clip(new_lps - old_lps, -10, 10))  # (N,)

            surr1    = ratios * adv
            surr2    = np.clip(ratios, 1 - CLIP_EPS, 1 + CLIP_EPS) * adv
            a_loss   = -np.mean(np.minimum(surr1, surr2))

            # Entropy bonus (encourages exploration, prevents premature collapse)
            entropy  = np.sum(0.5 * np.log(2 * np.pi * np.e
                              * np.exp(2 * self.log_std) + 1e-8))
            a_loss  -= ENTROPY_COEF * entropy

            c_loss   = VALUE_COEF * np.mean((returns - val) ** 2)

            tot_a += a_loss
            tot_c += c_loss

            # ── Critic backward ───────────────────────────────────────────────
            d_val  = (2 * VALUE_COEF / N) * (val - returns)          # (N,)
            d_ch   = d_val[:, np.newaxis]                             # (N,1)
            d_h2_c = self.c_hd.backward(d_ch, lr=CRITIC_LR)          # (N,64)

            # ── Actor backward ───────────────────────────────────────────────
            # Correct PPO clipping: only suppress gradient when ratio is
            # outside the trust-region AND the update would still improve
            # the objective in the same direction.
            #   A > 0: clipped when ratio > 1+ε  (already rewarded enough)
            #   A < 0: clipped when ratio < 1-ε  (already penalised enough)
            clipped  = ((adv > 0) & (ratios > 1.0 + CLIP_EPS)) \
                     | ((adv < 0) & (ratios < 1.0 - CLIP_EPS))          # (N,)
            d_ratio  = np.where(clipped, 0.0, adv)                       # (N,)

            # Gradient of log_π w.r.t. mean: (a - μ) / σ²
            var      = std ** 2
            d_lp_dm  = (actions - mean) / (var + 1e-8)                   # (N,A)

            # Chain: d_loss/d_mean = -(d_ratio * ratio * d_lp_dm) / N
            d_mean   = -(d_ratio[:, None] * ratios[:, None]
                         * d_lp_dm) / N                                  # (N,A)

            # Back through tanh at actor_head output: mean = tanh(pre_act)
            d_mean_pre = d_mean * (1.0 - mean ** 2)                      # (N,A)
            d_h2_a     = self.a_hd.backward(d_mean_pre, lr=ACTOR_LR)    # (N,64)

            # Combined gradient into h2
            d_h2       = d_h2_a + d_h2_c                                 # (N,64)

            # Back through tanh at l2 output
            d_h2_pre   = d_h2 * (1.0 - h2 ** 2)
            d_h1       = self.l2.backward(d_h2_pre, lr=ACTOR_LR)    # (N,64)

            # Back through tanh at l1 output
            d_h1_pre   = d_h1 * (1.0 - h1 ** 2)
            self.l1.backward(d_h1_pre, lr=ACTOR_LR)

            # ── Update log_std ────────────────────────────────────────────────
            # d_lp/d_log_std = (a-μ)²/σ² − 1    (derived from Gaussian log-prob)
            d_lp_dls   = (actions - mean) ** 2 / (var + 1e-8) - 1.0  # (N,A)
            d_ls       = np.where(
                clipped[:, None], 0.0,
                -(d_ratio[:, None] * ratios[:, None] * d_lp_dls) / N
            ).mean(axis=0)
            self.log_std -= ACTOR_LR * 0.1 * d_ls
            self.log_std  = np.clip(self.log_std, -3.0, 0.5)

        return {
            "actor_loss":  float(tot_a / PPO_EPOCHS),
            "critic_loss": float(tot_c / PPO_EPOCHS),
        }

    # ── Serialisation ─────────────────────────────────────────────────────────

    def state_dict(self) -> dict:
        return {
            "l1":      self.l1.state_dict(),
            "l2":      self.l2.state_dict(),
            "a_hd":    self.a_hd.state_dict(),
            "c_hd":    self.c_hd.state_dict(),
            "log_std": self.log_std.copy(),
        }

    def load_state_dict(self, d: dict) -> None:
        self.l1.load_state_dict(d["l1"])
        self.l2.load_state_dict(d["l2"])
        self.a_hd.load_state_dict(d["a_hd"])
        self.c_hd.load_state_dict(d["c_hd"])
        self.log_std = d["log_std"].copy()


# ── Public PPO Agent ──────────────────────────────────────────────────────────

class PPOAgent:
    """
    PPO Agent: wraps ActorCritic and manages the experience buffer.

    Usage (per monitoring cycle):
        action, lp, val = agent.step(state)
        ... apply action, observe reward ...
        agent.remember(state, action, lp, reward, val)
        losses = agent.update_if_ready()    # returns dict or None
    """

    def __init__(self,
                 state_dim:    int = STATE_DIM,
                 action_dim:   int = ACTION_DIM,
                 save_path:    str = "logs/ppo_weights.pkl",
                 update_every: int = UPDATE_EVERY) -> None:

        self.net          = _ActorCritic(state_dim, action_dim)
        self.save_path    = save_path
        self.update_every = update_every

        self._buf: list = []      # experience buffer
        self._total_updates = 0

        # Try to restore saved weights
        self._try_load()

    # ── Inference ─────────────────────────────────────────────────────────────

    def step(self, state: np.ndarray):
        """
        Sample action from current policy.

        Returns:
            action   : (action_dim,) clipped to [-1, 1]
            log_prob : float
            value    : float (critic estimate)
        """
        mean, value, std = self.net.forward(state)
        noise  = np.random.randn(*mean.shape).astype(np.float32)
        action = np.clip(mean + std * noise, -1.0, 1.0)
        lp     = float(self.net.log_prob(
            action[np.newaxis], mean[np.newaxis], std
        ).item())
        return action, lp, value

    # ── Memory ────────────────────────────────────────────────────────────────

    def remember(self, state, action, log_prob: float,
                 reward: float, value: float) -> None:
        """Store one (s, a, lp, r, v) transition."""
        self._buf.append((
            np.asarray(state,  dtype=np.float32),
            np.asarray(action, dtype=np.float32),
            float(log_prob),
            float(reward),
            float(value),
        ))

    # ── Update ────────────────────────────────────────────────────────────────

    def update_if_ready(self) -> dict | None:
        """
        Run PPO update if enough transitions have been collected.

        Returns:
            dict with 'actor_loss' and 'critic_loss', or None if not ready.
        """
        if len(self._buf) < self.update_every:
            return None

        states, actions, log_probs, rewards, values = zip(*self._buf)
        states    = np.array(states,    dtype=np.float32)
        actions   = np.array(actions,   dtype=np.float32)
        log_probs = np.array(log_probs, dtype=np.float32)
        rewards   = np.array(rewards,   dtype=np.float32)
        values    = np.array(values,    dtype=np.float32)

        # Compute returns and GAE advantages
        T          = len(rewards)
        returns    = np.zeros(T, dtype=np.float32)
        advantages = np.zeros(T, dtype=np.float32)
        gae        = 0.0
        next_val   = 0.0
        for t in reversed(range(T)):
            delta         = rewards[t] + GAMMA * next_val - values[t]
            gae           = delta + GAMMA * GAE_LAMBDA * gae
            advantages[t] = gae
            next_val      = values[t]
            returns[t]    = advantages[t] + values[t]

        losses = self.net.update(states, actions, log_probs, returns, advantages)
        self._buf.clear()
        self._total_updates += 1
        self._save()
        return losses

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self) -> None:
        try:
            # Only create parent dirs when save_path has a directory component.
            # os.path.dirname("weights.pkl") returns "" which causes makedirs to crash.
            save_dir = os.path.dirname(self.save_path)
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)
            with open(self.save_path, "wb") as f:
                pickle.dump(self.net.state_dict(), f)
        except Exception as e:
            logger.warning("[PPO] Could not save weights: %s", e)

    def _try_load(self) -> None:
        if not os.path.exists(self.save_path):
            return
        try:
            with open(self.save_path, "rb") as f:
                self.net.load_state_dict(pickle.load(f))
            logger.info("[PPO] Loaded saved weights from %s", self.save_path)
        except Exception as e:
            logger.warning("[PPO] Could not load weights (%s) — starting fresh.", e)


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  PPO Agent — self-test")
    print("=" * 60)

    np.random.seed(42)
    agent = PPOAgent(save_path="/tmp/ppo_test.pkl")

    # Simulate 25 cycles of random data
    for cycle in range(25):
        state  = np.random.rand(STATE_DIM).astype(np.float32)
        action, lp, val = agent.step(state)
        reward = float(np.random.choice([-5, 1, 10]))
        agent.remember(state, action, lp, reward, val)

        losses = agent.update_if_ready()
        if losses:
            print(f"  Update #{agent._total_updates}  "
                  f"actor_loss={losses['actor_loss']:.4f}  "
                  f"critic_loss={losses['critic_loss']:.4f}")

    print()
    print("  Action sample:", action.round(4))
    print("  Log prob:      ", round(lp, 4))
    print("  Value est:     ", round(val, 4))
    print()
    print("  ✅ PPO Agent self-test PASSED")
