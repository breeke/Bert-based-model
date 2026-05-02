# Presentation Draft — Cross-Language Vulnerability Detection
**Target: 15–17 min content + Q&A**
Each slide is approximately 1 minute unless noted.

---

## Slide 1 — Title (~30 sec)

**Cross-Language Software Vulnerability Detection**
*via Fine-Tuned Pre-Trained Code Models*

Synthetic Training · Real-World Generalisation · Semantic Understanding

[Author Name] | April 2026

---

## Slide 2 — Motivation (~1 min)

**The Problem with Polyglot Codebases**

- ~80% of real projects use 7+ programming languages
- Vulnerability patterns differ per language:
  - Memory errors → mostly C/C++
  - Injection flaws → every language, but through different APIs
- Existing tools are monolingual — Flawfinder, Coverity etc. each cover one language
- Managing multiple tools leads to alert fatigue and low adoption

**Goal:** A single trained model that detects vulnerabilities across C and Python,
without language-specific preprocessing

> *Speaker note: Keep this brief — establish the "why" and move on.*

---

## Slide 3 — Research Questions (~1 min)

**What this work investigates**

1. Can a pre-trained code model be fine-tuned to detect vulnerabilities across C and Python?
2. Which CWE classes transfer across languages, and why?
3. How large is the gap between synthetic and real-world performance — and can it be reduced?
4. Does the model rely on pattern-matching or something closer to semantic understanding?
5. How well-calibrated are its confidence outputs for practical use?

---

## Slide 4 — Approach Overview (~1 min)

**One model, two languages**

| Component | Choice | Reason |
|---|---|---|
| Base model | UniXcoder | Multi-language pre-training + AST awareness |
| Classification head | CLS → Dropout → Linear → Sigmoid | Lightweight, low data cost |
| Training data | Synthetic: 17 CWEs × {C, Python} | No large Python real-world dataset exists |
| Augmentation | 1,000 DiverseVul C/C++ samples | Reduce synthetic-to-real gap |
| Calibration | Label smoothing ε = 0.1 | Trustworthy confidence scores |

---

## Slide 5 — Dataset and Model (~1 min)

**Dataset**
- 17 CWE types covering C and Python (8 shared cross-language classes)
- Each example wrapped in realistic context; hard negative contrastive pairs included
- Held-out validation: **1,230 samples** (660 C + 570 Python)
- Real-world test: **200 DiverseVul samples** — kept completely separate throughout

**Model**
- UniXcoder encoder → CLS token → Dropout(0.1) → Linear → Sigmoid
- AdamW, lr = 2×10⁻⁵, 3 epochs, batch size 8
- Label smoothing: vulnerable target → 0.95, safe target → 0.05

---

## Slide 6 — Experiment 1: Baseline Results (~1.5 min)

**Joint model on held-out synthetic set (n = 1,230)**

| Metric | Score |
|---|---|
| F1 | **0.931** |
| Precision | 0.961 |
| Recall | 0.902 |
| AUC-ROC | 0.964 |

- C: F1 = 0.905 | Python: F1 = 0.961
- **11 of 17 CWE classes reach perfect F1 = 1.00**
- Hardest class: CWE-416 (use-after-free) at F1 = 0.667

> *[Show per-CWE bar chart here]*

---

## Slide 7 — Experiment 2: Cross-Language Ablation (~1.5 min)

**3×3 matrix: train language × test language**

| Model | Test: C | Test: Python | Test: Joint |
|---|---|---|---|
| C-only | 0.861 | 0.811 | 0.836 |
| Python-only | 0.677 | 0.976 | 0.817 |
| **Joint** | **0.905** | **0.961** | **0.931** |

- Joint training outperforms single-language training on every test set
- C → Python transfer (0.811) is much stronger than Python → C (0.677)
- Python-only model: precision = 1.00 but recall = 0.596 on C — it becomes overly conservative

---

## Slide 8 — CWE Transfer: Three Profiles (~1 min)

**Transfer quality depends on surface similarity, not semantic similarity**

| Profile | Example CWEs | Why |
|---|---|---|
| **Bidirectional** — transfers both ways | CWE-798 (hardcoded credentials) | String literal = same token pattern in both languages |
| **Asymmetric** — one direction only | CWE-78 (command injection) | C-only → Python works; Python-only → C fails (different API sequence) |
| **Language-locked** — neither direction | CWE-367 (TOCTOU race) | Completely different idioms in C vs Python |

---

## Slide 9 — Training Improvements: Hard Negatives (~1 min)

**Problem:** model flagged `hashlib.sha256` (safe) as vulnerable at p = 0.906
because it learned `hashlib` → vulnerable rather than the specific algorithm name

**Fix:** Added 17 safe contrastive examples — sha256/sha512 usage, hardcoded `system()` calls

| Version | Before | After |
|---|---|---|
| CWE-327 — vulnerable (md5) | 0.960 | 0.960 ✓ |
| CWE-327 — fixed (sha256) | 0.906 ✗ | **0.048** ✓ |
| CWE-78 — fixed (hardcoded path) | 0.929 ✗ | 0.929 ✗ |

CWE-327 fully resolved. CWE-78 remains — distinguishing user-controlled vs hardcoded buffers
requires **data-flow tracking**, which a sequence encoder cannot do.

---

## Slide 10 — Training Improvements: Real-World Augmentation (~1.5 min)

**Added 1,000 DiverseVul C/C++ samples to training**

| Stage | Synthetic F1 | Real-world F1 | Gap |
|---|---|---|---|
| Synthetic-only | 0.931 | 0.410 | −0.522 |
| + Hard negatives | 0.931 | 0.471 | −0.460 |
| **+ Augmentation** | **0.931** | **0.749** | **−0.182** |

- Synthetic performance unchanged throughout — no regression
- Real-world F1 nearly doubled: 0.410 → 0.749
- **Single highest-leverage change in the entire project**
- Remaining gap reflects CWE classes entirely absent from training (CWE-787, CWE-400, CWE-703)

---

## Slide 11 — Semantic Understanding Tests (~1.5 min)

**Four tests to distinguish pattern-matching from deeper understanding**

| Test | What it checks | Result |
|---|---|---|
| 1. Variable renaming | Does prediction change if variable names change? | **6/6 pass** ✓ |
| 2. Minimal fix | Does the model recognise the one-line fix? | **7/8 pass** ✓ |
| 3. Dead code | Does unreachable code still trigger a prediction? | **1/5 pass** ✗ |
| 4. Token ablation | Does removing the dangerous keyword break detection? | **6/6 pass** ✓ |
| **Total** | | **20/25** |

---

## Slide 12 — What the Tests Reveal (~1 min)

**The model has learned structure, not just keywords**

✓ Predictions are stable across variable renames and keyword ablation
✓ Detects the structural change that fixes a vulnerability (md5 → sha256: p drops 0.960 → 0.048)

**But it cannot reason about control flow**

✗ Code inside `if(0)` or `if False:` still triggers VULNERABLE
✗ This requires a control-flow graph — unavailable to a sequence encoder
✗ This is an **architectural ceiling**, not a fixable data problem

> *This is one of the more interesting findings — the tests locate the limit precisely rather than just observing a lower accuracy number.*

---

## Slide 13 — Calibration (~45 sec)

**Are the confidence scores trustworthy?**

- Temperature scaling after training: optimal T = **0.981** (essentially 1.0)
- Near-unity temperature means label smoothing already did the calibration work
- On synthetic data: outputs are **bimodal** — clearly safe (p ≈ 0) or clearly vulnerable (p ≈ 0.96)
- On real-world data: broader distribution — more ambiguous partial matches
- Outputs can be used to **prioritise** a vulnerability report queue

---

## Slide 14 — Limitations and Future Work (~1 min)

**Honest limitations**
- Model cannot track data-flow or check reachability — architectural, not fixable with more data
- Only 17 CWE types; DiverseVul test spans ~50; recall on unseen classes is zero
- C and Python only; no large Python real-world dataset exists
- 200-sample real-world test set is small for per-CWE estimates

**Most promising next steps**
1. Add a GNN data-flow component to address the CWE-78/CWE-416 failures
2. Scale real-world augmentation (10,000 samples may close the remaining gap)
3. Extend synthetic templates to CWE-787, CWE-400, CWE-703

---

## Slide 15 — Summary (~1 min)

**What was built and what was found**

| Contribution | Result |
|---|---|
| Multi-language synthetic dataset | 17 CWEs, C + Python, 1,230 held-out samples |
| Fine-tuned UniXcoder classifier | F1 = 0.931, AUC = 0.964 on synthetic |
| Cross-language ablation (3×3) | Joint training outperforms single-language on all sets |
| Hard negative mining | Eliminated sha256 false positive completely |
| Real-world augmentation | F1: 0.410 → 0.749; gap: −0.522 → −0.182 |
| Semantic understanding tests | 20/25; architectural ceiling located precisely |

**Key takeaway:** With careful dataset design, targeted hard negatives, and real-world
augmentation, a pre-trained code model can reach practically useful multi-language
vulnerability detection — and the semantic tests show exactly where and why it falls short.

---

## [Questions]

*Leave remainder of time for Q&A*

**Likely questions to prepare for:**
- Why UniXcoder over CodeBERT or GraphCodeBERT?
- Why only 1,000 augmentation samples — why not more?
- How would this scale to Java or JavaScript?
- What would the graph-augmented architecture actually look like?
- How was the synthetic data validated for realism?
