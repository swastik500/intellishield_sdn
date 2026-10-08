"""
================================================================================
Phase 7 — Comprehensive Verification Suite
================================================================================
Tests:
  1. _Linear  — forward/backward shapes, Adam update runs
  2. _ActorCritic — forward, log_prob, forward_train shapes
  3. GAE returns — correctness against known toy values
  4. PPO ratio clipping — verifies clip kicks in correctly
  5. PPOAgent end-to-end — 60 cycles, 3 updates, losses finite
  6. ThresholdAdapter — apply_action bounds, reward function logic
  7. SDNEnvironment — state vector shape and normalisation
  8. RLLogger — CSV rows written without errors
  9. Weight persistence — save → load → same output
 10. Integration smoke-test — simulates what flow_monitor does each cycle
================================================================================
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import tempfile
import csv

# ── helpers ───────────────────────────────────────────────────────────────────

PASS  = "  ✅ PASS"
FAIL  = "  ❌ FAIL"

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    print(f"{status}  {name}" + (f"  [{detail}]" if detail else ""))
    return condition

results = []

# ── import Phase 7 modules ────────────────────────────────────────────────────

print("=" * 66)
print("  IntelliShield Phase 7 — Verification Suite")
print("=" * 66)
print()

try:
    from rl_engine.ppo_agent         import PPOAgent, _Linear, _ActorCritic, STATE_DIM, ACTION_DIM, CLIP_EPS, GAMMA, GAE_LAMBDA
    from rl_engine.threshold_adapter import ThresholdAdapter, MIN_PKT, MAX_PKT, MIN_BYTE, MAX_BYTE, MIN_CONF, MAX_CONF
    from rl_engine.rl_env            import SDNEnvironment, STATE_DIM as ENV_STATE_DIM
    from rl_engine.rl_logger         import RLLogger
    print("  All Phase 7 modules imported successfully\n")
except ImportError as e:
    print(f"  ❌ IMPORT ERROR: {e}")
    sys.exit(1)

np.random.seed(0)

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1 — _Linear layer
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [1] _Linear Layer — forward/backward shapes & Adam update")
print("─" * 66)

lin = _Linear(10, 4)
x   = np.random.randn(8, 10).astype(np.float32)
y   = lin.forward(x)
results.append(check("forward shape  (8,4)", y.shape == (8, 4), str(y.shape)))

dout = np.ones_like(y)
dx   = lin.backward(dout, lr=1e-3)
results.append(check("backward shape (8,10)", dx.shape == (8, 10), str(dx.shape)))
results.append(check("Adam W updated (not all-zero)", not np.allclose(lin.W, 0)))
results.append(check("Adam t incremented", lin._t == 1, f"t={lin._t}"))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2 — _ActorCritic forward shapes
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [2] _ActorCritic — forward shapes & log_prob")
print("─" * 66)

ac  = _ActorCritic(STATE_DIM, ACTION_DIM)
s1  = np.random.rand(STATE_DIM).astype(np.float32)

mean, value, std = ac.forward(s1)
results.append(check("mean shape    (3,)",     mean.shape  == (ACTION_DIM,),  str(mean.shape)))
results.append(check("std shape     (3,)",     std.shape   == (ACTION_DIM,),  str(std.shape)))
results.append(check("mean in (-1,1)",          np.all(np.abs(mean) < 1.0),   str(mean.round(3))))
results.append(check("std positive",            np.all(std > 0),              str(std.round(3))))
results.append(check("value is scalar",         isinstance(value, float),     str(type(value))))

# Batch forward
sb  = np.random.rand(8, STATE_DIM).astype(np.float32)
mean_b, val_b, std_b = ac.forward_train(sb)
results.append(check("forward_train mean (8,3)", mean_b.shape == (8, ACTION_DIM), str(mean_b.shape)))
results.append(check("forward_train val  (8,)",  val_b.shape  == (8,),            str(val_b.shape)))

# log_prob
acts = np.random.randn(8, ACTION_DIM).astype(np.float32)
lps  = ac.log_prob(acts, mean_b, std_b)
results.append(check("log_prob shape (8,)",      lps.shape == (8,),           str(lps.shape)))
results.append(check("log_prob all finite",       np.all(np.isfinite(lps)),    str(lps.round(3))))
results.append(check("log_prob ≤ 0",              np.all(lps <= 0.01),         str(lps.round(3))))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3 — GAE returns correctness
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [3] GAE Returns — correctness against known toy values")
print("─" * 66)

# Simple 3-step episode: rewards=[1,1,1], values=[0.5,0.5,0.5]
# delta_t = r_t + γ*V_{t+1} - V_t
# delta_2 = 1 + 0       - 0.5 = 0.5          (next_val=0 at end)
# delta_1 = 1 + γ*0.5   - 0.5 = 0.5 + γ*0.5 - 0.5
# gae_2 = 0.5
# gae_1 = delta_1 + γ*λ*gae_2
# return_t = gae_t + value_t

def compute_gae_manually(rewards, values, gamma=GAMMA, lam=GAE_LAMBDA):
    T = len(rewards)
    returns = np.zeros(T); advantages = np.zeros(T)
    gae = 0.0; next_val = 0.0
    for t in reversed(range(T)):
        delta        = rewards[t] + gamma * next_val - values[t]
        gae          = delta + gamma * lam * gae
        advantages[t] = gae
        next_val     = values[t]
        returns[t]   = advantages[t] + values[t]
    return returns, advantages

rewards = np.array([1.0, 1.0, 1.0])
values  = np.array([0.5, 0.5, 0.5])
ret, adv = compute_gae_manually(rewards, values)

# Returns must be > values (since all rewards are positive)
results.append(check("Returns > values",  np.all(ret > values), str(ret.round(4))))
# Last advantage = 1 + 0 - 0.5 = 0.5
results.append(check("Last advantage ≈ 0.5", abs(adv[-1] - 0.5) < 1e-4, f"adv[-1]={adv[-1]:.4f}"))
# Advantages are all finite
results.append(check("All advantages finite", np.all(np.isfinite(adv)), str(adv.round(4))))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4 — PPO Clipping logic
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [4] PPO Clipping — surr2 ≤ (1+ε)*A when A>0")
print("─" * 66)

# With positive advantage, surr2 ≤ (1+ε)*A
# With negative advantage, surr2 ≥ (1-ε)*A  [clip lower bound]
N   = 50
adv_pos = np.abs(np.random.randn(N)) + 0.1    # all positive
adv_neg = -(np.abs(np.random.randn(N)) + 0.1) # all negative

# ratio > 1+ε with positive advantage → should be clipped to (1+ε)
ratios_high = np.ones(N) * (1 + CLIP_EPS + 0.1)
surr1_p = ratios_high * adv_pos
surr2_p = np.clip(ratios_high, 1-CLIP_EPS, 1+CLIP_EPS) * adv_pos
clipped_correctly = np.all(np.minimum(surr1_p, surr2_p) == surr2_p)
results.append(check("High ratio+pos adv → clipped (surr2<surr1)", clipped_correctly))

# ratio < 1-ε with negative advantage → should be clipped
ratios_low = np.ones(N) * (1 - CLIP_EPS - 0.1)
surr1_n = ratios_low * adv_neg
surr2_n = np.clip(ratios_low, 1-CLIP_EPS, 1+CLIP_EPS) * adv_neg
clipped_neg = np.all(np.minimum(surr1_n, surr2_n) == surr2_n)
results.append(check("Low ratio+neg adv → clipped (surr2<surr1)", clipped_neg))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 5 — PPOAgent end-to-end (60 cycles → 3 updates)
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [5] PPOAgent — end-to-end (60 cycles → 3 PPO updates)")
print("─" * 66)

with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
    tmp_pkl = f.name

agent    = PPOAgent(save_path=tmp_pkl, update_every=20)
losses_log = []

for cycle in range(60):
    state  = np.random.rand(STATE_DIM).astype(np.float32)
    action, lp, val = agent.step(state)

    # Verify action shape and range
    if cycle == 0:
        results.append(check("action shape (3,)",   action.shape == (ACTION_DIM,), str(action.shape)))
        results.append(check("action in [-1,1]",     np.all(np.abs(action) <= 1.0), str(action.round(3))))
        results.append(check("lp finite",             np.isfinite(lp),             f"lp={lp:.3f}"))
        results.append(check("val finite",            np.isfinite(val),            f"val={val:.3f}"))

    reward = float(np.random.choice([-5.0, 1.0, 10.0]))
    agent.remember(state, action, lp, reward, val)
    losses = agent.update_if_ready()
    if losses:
        losses_log.append(losses)

results.append(check("Exactly 3 PPO updates", agent._total_updates == 3,
                       f"updates={agent._total_updates}"))
results.append(check("Buffer cleared after update", len(agent._buf) == 0,
                       f"buf_len={len(agent._buf)}"))

for i, l in enumerate(losses_log):
    a_finite = np.isfinite(l["actor_loss"])
    c_finite = np.isfinite(l["critic_loss"])
    results.append(check(f"Update {i+1} actor_loss finite",  a_finite, f"{l['actor_loss']:.4f}"))
    results.append(check(f"Update {i+1} critic_loss finite", c_finite, f"{l['critic_loss']:.4f}"))
    results.append(check(f"Update {i+1} critic_loss > 0",   l["critic_loss"] > 0))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 6 — ThresholdAdapter
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [6] ThresholdAdapter — bounds, actions, reward logic")
print("─" * 66)

ta = ThresholdAdapter()
results.append(check("Init pkt=500",  ta.pkt_threshold  == 500.0))
results.append(check("Init byte=500k", ta.byte_threshold == 500_000.0))
results.append(check("Init conf=0.80", abs(ta.conf_threshold - 0.80) < 1e-6))

# Apply max positive action → should hit upper bound
ta.apply_action(np.array([1.0, 1.0, 1.0]))
results.append(check("Positive action tightens thresholds (pkt increases)",
                       ta.pkt_threshold > 500.0, f"pkt={ta.pkt_threshold:.0f}"))

# Apply max negative action 100 times → should hit lower bound
for _ in range(100):
    ta.apply_action(np.array([-1.0, -1.0, -1.0]))
results.append(check("Clamped to MIN_PKT after many neg actions",
                       ta.pkt_threshold == MIN_PKT, f"pkt={ta.pkt_threshold:.0f}"))
results.append(check("Clamped to MIN_BYTE",
                       ta.byte_threshold == MIN_BYTE, f"byte={ta.byte_threshold:.0f}"))
results.append(check("Clamped to MIN_CONF",
                       abs(ta.conf_threshold - MIN_CONF) < 0.01, f"conf={ta.conf_threshold:.3f}"))

# Reset for reward tests
ta2 = ThresholdAdapter()

# True positive: ATTACK + high rate
r_tp = ta2.compute_reward("ATTACK", 0.90, packet_rate=10_000, entropy_score=0.1)
results.append(check("True positive reward ≥ +10", r_tp >= 10.0, f"r={r_tp:.1f}"))

# False positive: ATTACK + low rate
r_fp = ta2.compute_reward("ATTACK", 0.85, packet_rate=50, entropy_score=0.95)
results.append(check("False positive reward < 0", r_fp < 0.0, f"r={r_fp:.1f}"))

# Normal quiet cycle
r_norm = ta2.compute_reward("NORMAL", 0.80, packet_rate=10, entropy_score=0.98)
results.append(check("Quiet cycle reward > 0", r_norm > 0.0, f"r={r_norm:.1f}"))

# Rolling windows
results.append(check("recent_attack_count ≥ 1", ta2.recent_attack_count >= 1))
results.append(check("recent_fp_count ≥ 1",     ta2.recent_fp_count     >= 1))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 7 — SDNEnvironment
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [7] SDNEnvironment — state vector shape & normalisation")
print("─" * 66)

env = SDNEnvironment()
results.append(check("STATE_DIM match", ENV_STATE_DIM == STATE_DIM, f"{ENV_STATE_DIM}"))

s = env.build_state(
    packet_rate_mean=1000, byte_rate_mean=100_000,
    entropy_score=0.9, flow_count=4,
    ml_confidence=0.85,
    pkt_threshold=500, byte_threshold=500_000,
    conf_threshold=0.80,
    recent_attack_cnt=2, recent_fp_cnt=0,
)
results.append(check("State shape (10,)",     s.shape == (STATE_DIM,), str(s.shape)))
results.append(check("State dtype float32",   s.dtype == np.float32,  str(s.dtype)))
results.append(check("All values in [0,1]",   np.all((s >= 0) & (s <= 1)), str(s.round(3))))

# Extreme inputs must still be clipped to [0,1]
s_ext = env.build_state(
    packet_rate_mean=9_999_999, byte_rate_mean=9_999_999,
    entropy_score=5.0, flow_count=9999,
    ml_confidence=5.0,
    pkt_threshold=99999, byte_threshold=99999999,
    conf_threshold=5.0,
    recent_attack_cnt=9999, recent_fp_cnt=9999,
)
results.append(check("Extreme values clamped to 1.0", np.all(s_ext <= 1.0), str(s_ext.round(3))))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 8 — RLLogger
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [8] RLLogger — CSV row written correctly")
print("─" * 66)

with tempfile.TemporaryDirectory() as tmpdir:
    rl_log = RLLogger(logs_dir=tmpdir)

    rl_log.log_decision(
        switch_id=1, pkt_rate=500.0, byte_rate=100_000.0,
        entropy=0.95, flow_count=4,
        ml_label="NORMAL", ml_conf=0.82,
        action=np.array([0.1, -0.2, 0.05]),
        thresholds={"pkt_threshold": 520, "byte_threshold": 480_000, "conf_threshold": 0.81},
        reward=1.0,
    )
    rl_log.log_training(update_number=1, actor_loss=-0.02, critic_loss=0.45, buffer_size=20)

    dec_path   = os.path.join(tmpdir, "rl_decisions.csv")
    train_path = os.path.join(tmpdir, "rl_training.csv")

    with open(dec_path) as f:
        rows = list(csv.reader(f))
    results.append(check("rl_decisions.csv has header + 1 data row", len(rows) == 2,
                           f"rows={len(rows)}"))
    results.append(check("ml_label column correct", rows[1][7] == "NORMAL", rows[1][7]))
    results.append(check("reward column correct",   rows[1][-1] == "1.0",   rows[1][-1]))

    with open(train_path) as f:
        rows2 = list(csv.reader(f))
    results.append(check("rl_training.csv has header + 1 data row", len(rows2) == 2,
                           f"rows={len(rows2)}"))
    results.append(check("update_number correct", rows2[1][1] == "1", rows2[1][1]))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 9 — Weight persistence (save → load → same output)
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [9] Weight Persistence — save → load → identical output")
print("─" * 66)

with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
    pkl_path = f.name

agent_a = PPOAgent(save_path=pkl_path, update_every=20)
# Force one update
for _ in range(20):
    s = np.random.rand(STATE_DIM).astype(np.float32)
    a, lp, v = agent_a.step(s)
    agent_a.remember(s, a, lp, 1.0, v)
agent_a.update_if_ready()   # saves weights

# Load into new agent and compare outputs
agent_b = PPOAgent(save_path=pkl_path, update_every=20)
test_state = np.random.rand(STATE_DIM).astype(np.float32)
np.random.seed(999)
a_out_a, _, _ = agent_a.step(test_state)
np.random.seed(999)
a_out_b, _, _ = agent_b.step(test_state)

results.append(check("Loaded agent produces same mean output",
                       np.allclose(a_out_a, a_out_b, atol=1e-5),
                       f"max_diff={np.max(np.abs(a_out_a-a_out_b)):.2e}"))
print()

# ══════════════════════════════════════════════════════════════════════════════
# TEST 10 — Integration smoke test (mimics flow_monitor cycle)
# ══════════════════════════════════════════════════════════════════════════════
print("─" * 66)
print("  [10] Integration — full cycle as flow_monitor executes it")
print("─" * 66)

with tempfile.TemporaryDirectory() as td:
    agent_i   = PPOAgent(save_path=os.path.join(td, "ppo.pkl"), update_every=20)
    adapter_i = ThresholdAdapter()
    env_i     = SDNEnvironment()
    logger_i  = RLLogger(logs_dir=td)

    # Simulate normal cycle
    pkt_mean  = 5.0;    byte_mean = 400.0
    ent_score = 0.98;   flow_cnt  = 2
    ml_label  = "NORMAL"; ml_conf = 0.82

    state = env_i.build_state(
        packet_rate_mean=pkt_mean, byte_rate_mean=byte_mean,
        entropy_score=ent_score, flow_count=flow_cnt,
        ml_confidence=ml_conf,
        pkt_threshold=adapter_i.pkt_threshold,
        byte_threshold=adapter_i.byte_threshold,
        conf_threshold=adapter_i.conf_threshold,
        recent_attack_cnt=adapter_i.recent_attack_count,
        recent_fp_cnt=adapter_i.recent_fp_count,
    )
    action, lp, val = agent_i.step(state)
    new_thresh      = adapter_i.apply_action(action)
    reward          = adapter_i.compute_reward(ml_label, ml_conf, pkt_mean, ent_score)
    agent_i.remember(state, action, lp, reward, val)
    logger_i.log_decision(
        switch_id=1, pkt_rate=pkt_mean, byte_rate=byte_mean,
        entropy=ent_score, flow_count=flow_cnt,
        ml_label=ml_label, ml_conf=ml_conf,
        action=action, thresholds=new_thresh, reward=reward,
    )

    results.append(check("Normal cycle: reward > 0",           reward > 0.0, f"r={reward:.1f}"))
    results.append(check("Normal cycle: pkt_threshold bounded",
                          MIN_PKT <= adapter_i.pkt_threshold <= MAX_PKT,
                          f"pkt={adapter_i.pkt_threshold:.0f}"))

    # Simulate attack cycle
    pkt_mean  = 120_000; byte_mean = 6_000_000
    ent_score = 0.0;     ml_label  = "ATTACK"; ml_conf = 0.87

    state_atk = env_i.build_state(
        packet_rate_mean=pkt_mean, byte_rate_mean=byte_mean,
        entropy_score=ent_score, flow_count=2,
        ml_confidence=ml_conf,
        pkt_threshold=adapter_i.pkt_threshold,
        byte_threshold=adapter_i.byte_threshold,
        conf_threshold=adapter_i.conf_threshold,
        recent_attack_cnt=adapter_i.recent_attack_count,
        recent_fp_cnt=adapter_i.recent_fp_count,
    )
    action_atk, lp_atk, val_atk = agent_i.step(state_atk)
    new_thresh_atk = adapter_i.apply_action(action_atk)
    reward_atk     = adapter_i.compute_reward(ml_label, ml_conf, pkt_mean, ent_score)
    agent_i.remember(state_atk, action_atk, lp_atk, reward_atk, val_atk)

    results.append(check("Attack cycle: reward ≥ +10", reward_atk >= 10.0, f"r={reward_atk:.1f}"))
    results.append(check("Attack cycle: state all finite",
                          np.all(np.isfinite(state_atk)), str(state_atk.round(3))))
    print()

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 66)
total  = len(results)
passed = sum(results)
failed = total - passed

print(f"  Result: {passed}/{total} tests passed", end="  ")
print("🎉 ALL PASS" if failed == 0 else f"⚠️  {failed} FAILED")
print("=" * 66)

if failed > 0:
    sys.exit(1)
