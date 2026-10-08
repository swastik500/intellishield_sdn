# AI Questions

Each entry: **Question** → **Expected Answer**

---

## Entropy (Phase 2)

### Q1. What is Shannon entropy and how do you use it?

**Expected Answer:** Shannon entropy H(X) = −Σ p(xᵢ) log₂(p(xᵢ)) measures uncertainty in a distribution. We normalise to [0,1]. Normal traffic has high entropy (diverse sources/destinations). DDoS collapses diversity — one source or victim dominates — entropy drops toward 0. We compute five dimensions: source MAC, destination MAC, packet, byte, and flow distribution.

---

### Q2. Why five entropy dimensions?

**Expected Answer:** Different attacks affect different distributions. SYN flood collapses source entropy; volumetric UDP may collapse destination or packet distribution. Multi-dimensional detection is more robust than a single metric and provides explainable alert types like `SRC_MAC_ENTROPY_COLLAPSE`.

---

### Q3. What are your entropy thresholds?

**Expected Answer:** Normalised thresholds: src/dst/flow ≤ 0.30; packet/byte ≤ 0.20; composite score ≤ 0.40. Weights: src 0.30, dst 0.30, packet 0.15, byte 0.15, flow 0.10. Status: NORMAL, WARNING, or ALERT.

---

### Q4. What is entropy collapse?

**Expected Answer:** During SYN flood, src_entropy may drop from ~1.0 to ~0.04 because one source MAC dominates the flow window. Composite score falls below 0.40 triggering ALERT. This is the core DDoS signature we detect.

---

## Machine Learning (Phase 4)

### Q5. Why use machine learning if you have entropy?

**Expected Answer:** Entropy is fast and interpretable but can be ambiguous on edge cases. ML fuses 15 features (flow stats + entropy) for richer classification, attack type hints, and confidence scores. Ensemble combines unsupervised novelty detection (Isolation Forest) with supervised pattern learning (Decision Tree).

---

### Q6. Explain your 15-dimensional feature vector.

**Expected Answer:** From Phase 1: packet_rate_mean/max, byte_rate_mean/max, flow_count, duration_mean, unique_src/dst counts. From Phase 2: five entropy dimensions plus composite entropy_score. Derived: flow_concentration = 1 − src_entropy. Built by `FeatureBuilder.build()` each cycle.

---

### Q7. What is Isolation Forest and why use it?

**Expected Answer:** Unsupervised anomaly detector — isolates points with random trees; anomalies need fewer splits. Outputs anomaly score 0–1. Trained on 300 normal samples with 10% contamination. Catches novel attack patterns without attack labels.

---

### Q8. What is the Decision Tree role?

**Expected Answer:** Supervised classifier trained on 300 normal + 200 attack synthetic samples. Learns if-then rules; in our training entropy_score had highest importance. Provides 60% weight in ensemble vote with Isolation Forest at 40%.

---

### Q9. How does the ensemble decide NORMAL vs ATTACK?

**Expected Answer:** Weighted vote of IF anomaly score and DT label, then heuristics: truly quiet traffic (high iso_score, pkt_max < 100) forced to NORMAL; elevated but non-flood downgraded to SUSPICIOUS. Final labels: NORMAL, SUSPICIOUS, ATTACK.

---

### Q10. How were ML models trained?

**Expected Answer:** Bootstrap: `model_trainer --synthetic` generates 300 normal + 200 attack feature vectors. Models saved to `logs/models/*.pkl`. Controller auto-trains on startup if models missing. Retrain on real logs: `--from-csv` reads `ml_features.csv` with inferred labels.

---

### Q11. What is model explainability in your project?

**Expected Answer:** `Explainer` module provides attack_type_hint (SYN_FLOOD, UDP_FLOOD, etc.), per-feature comparison to NORMAL_RANGES, Decision Tree importance, and narrative text. Controller may override uncertain hints with entropy-derived labels.

---

### Q12. Why not deep learning / neural networks?

**Expected Answer:** Lab scale and dependency simplicity. sklearn ensemble performs well on 15-dim features with interpretable results. Our RL uses a small NumPy MLP for PPO only — not for classification. Deep learning is future work.

---

## ADWIN & HDBSCAN (Phase 6)

### Q13. What is ADWIN?

**Expected Answer:** Adaptive Windowing — online algorithm detecting when the mean of a data stream changes significantly using Hoeffding bounds. We implement ADWIN2 in pure Python (no river library). Tracks packet_rate_mean, flow_count, entropy_score, byte_rate_mean per switch.

---

### Q14. How is ADWIN different from entropy?

**Expected Answer:** Entropy measures diversity collapse in current window. ADWIN detects statistical shift in metric means over time — e.g., jump from 250 pkt/s to 80,000 pkt/s. ADWIN often fires one 5-second cycle before ML confirms — early warning layer.

---

### Q15. What is HDBSCAN?

**Expected Answer:** Hierarchical density-based clustering from sklearn. Runs every ~10 cycles on buffered 15-dim ML vectors. Discovers clusters without specifying k. Labels: NORMAL, ATTACK, SUSPICIOUS, NOISE (-1). Used for profiling, not real-time blocking.

---

### Q16. Does HDBSCAN trigger mitigation?

**Expected Answer:** No. HDBSCAN is batch analytics for traffic characterisation. Detection and mitigation are driven by entropy and ML ensemble with confirmation gates.

---

## Reinforcement Learning (Phase 7)

### Q17. Why use reinforcement learning?

**Expected Answer:** Static thresholds fail when baseline traffic changes. PPO adapts packet-rate threshold, byte-rate threshold, and ML confidence gate online based on reward from true positives, false positives, and missed attacks.

---

### Q18. Explain PPO in your project.

**Expected Answer:** Proximal Policy Optimization — custom NumPy implementation. 10-dim state (rates, entropy, ML conf, thresholds, recent TP/FP counts) → Gaussian policy → 3-dim action (threshold deltas). Clipped surrogate objective, GAE advantages, updates every 20 transitions. Weights saved to `ppo_weights.pkl`.

---

### Q19. What is the RL state vector?

**Expected Answer:** Normalised: packet_rate_mean, byte_rate_mean, entropy_score, flow_count, ml_confidence, current pkt/byte/conf thresholds, recent_attack_count, recent_fp_count — 10 dimensions total from `SDNEnvironment.build_state()`.

---

### Q20. What is the reward function?

**Expected Answer:** `ThresholdAdapter.compute_reward()` rewards confirmed attacks, penalises false positive blocks, penalises ML false negatives during flood-like entropy collapse, credits entropy-only detection when ML is blind, and gives small positive reward for quiet normal traffic.

---

### Q21. Does RL replace ML or entropy?

**Expected Answer:** No. RL tunes gates — when to treat traffic as actionable — not the classifiers themselves. Mitigation uses RL `conf_threshold` (default 0.80) instead of static 60%.

---

## AI Integration

### Q22. How do AI components work together?

**Expected Answer:** Every 5 s: entropy analyzes window → ML predicts on 15-dim vector → ADWIN updates metric streams → HDBSCAN buffers vectors (clusters every 10 cycles) → PPO steps and adjusts thresholds → mitigation uses ML/entropy alert + RL confidence gate.

---

### Q23. What AI techniques are NOT used?

**Expected Answer:** No CNN/RNN/LSTM for traffic, no GPT/LLM, no federated learning, no AutoML, no PyTorch/TensorFlow for classification. ADWIN is custom Python; PPO is custom NumPy.

---

## Validation

### Q24. How do you validate AI components?

**Expected Answer:**

- Entropy: H([0.5,0.5])=1.0 math check; 4-flow NORMAL score 0.984
- ML: 6/6 synthetic sanity (3 NORMAL, 3 ATTACK)
- ADWIN/HDBSCAN: module self-tests
- PPO: `verify_phase7.py` 40+ checks on VM
- End-to-end: S1 NORMAL zero blocks; S2 SYN → ALERT → ATTACK → BLOCK

---

### Q25. What is the novelty in AI for this project?

**Expected Answer:** Not inventing Shannon entropy or PPO — but integrating entropy, hybrid ML, ADWIN, HDBSCAN, and online PPO threshold control in one SDN controller loop with explainability and closed-loop mitigation. Multi-timescale AI: fast entropy, medium ML, slow clustering, continuous RL adaptation.
