# Experiment Results & Analysis

**Model:** UniXcoder (`microsoft/unixcoder-base`) fine-tuned for binary vulnerability classification
**Branch:** `claude/review-recent-branch-POtjK`

---

## Table of Contents

1. [Experiment 1 — Baseline](#1-experiment-1--baseline)
2. [Experiment 2 — Cross-Language Transfer Heatmaps](#2-experiment-2--cross-language-transfer-heatmaps)
3. [Insight 1 — Syntax vs Semantics (Full CWE Transfer Data)](#3-insight-1--syntax-vs-semantics-full-cwe-transfer-data)
4. [Insight 3 — Calibration / Error Analysis (Real-World)](#4-insight-3--calibration--error-analysis-real-world)

---

## 1. Experiment 1 — Baseline

**Test set:** `Files/multi_lang_test.jsonl` (1140 samples, 570 C + 570 Python)
**Model:** Joint baseline (`results/exp1_baseline/best_model.bin`)

### Overall Metrics

| Metric | Score |
|---|---|
| Accuracy | 0.9360 |
| Precision | 0.9778 |
| Recall | 0.9194 |
| **F1** | **0.9477** |
| AUC-ROC | 0.9812 |

### Confusion Matrix (n=1140)

| | Predicted Safe | Predicted Vulnerable |
|---|---|---|
| **Actually Safe** | TN = 405 | FP = 15 |
| **Actually Vulnerable** | FN = 58 | TP = 662 |

- False Positive Rate: 15/420 = **3.6%** (rarely cries wolf)
- False Negative Rate: 58/720 = **8.1%** (misses ~1 in 12 vulnerabilities)

### Per-Language Breakdown

| Language | F1 | Precision | Recall | n |
|---|---|---|---|---|
| C | 0.9162 | 0.9548 | 0.8806 | 570 |
| Python | **0.9787** | **1.000** | 0.9583 | 570 |

Python achieves **perfect precision** (zero false positives on Python data). C has lower recall —
the model misses more C vulnerabilities than Python ones, consistent with C's higher syntactic
variability across vulnerability patterns.

### Per-CWE F1

Most CWEs score 1.0. The four exceptions are the most important finding in this experiment:

| CWE | Description | F1 | Reason |
|---|---|---|---|
| CWE-89 | SQL injection | 0.833 | Pattern variability; hard in C regardless of training |
| CWE-416 | Use-after-free | 0.667 | Free and use often in separate functions |
| CWE-476 | Null dereference | 0.567 | Requires inter-procedural data-flow context |
| **CWE-367** | **TOCTOU race** | **0.000** | Race spans multiple operations; undetectable at snippet level |

**Key takeaway:** CWE-367, CWE-476, and CWE-416 all require understanding code flow *across
multiple functions*. A single-snippet classifier cannot detect them. This is a fundamental
architectural limitation, not a data problem. CWE-367 scoring zero is the strongest evidence.

---

## 2. Experiment 2 — Cross-Language Transfer Heatmaps

Measures per-CWE recall for each model (C-only, Python-only, Joint) tested on each language's
held-out set. Shared CWEs only (present in both C and Python training data).

### On C Test Set

| CWE | C-only | Python-only | Joint |
|---|---|---|---|
| CWE-22 (Path traversal) | 0.83 | 0.67 | 1.00 |
| CWE-134 (Format string) | 0.79 | 0.79 | 1.00 |
| CWE-327 (Weak crypto) | 0.60 | 0.47 | 1.00 |
| CWE-78 (Command injection) | 0.47 | **0.64** | 1.00 |
| CWE-798 (Hardcoded creds) | 0.47 | 0.24 | 1.00 |
| CWE-367 (TOCTOU) | 0.43 | 0.29 | 1.00 |
| CWE-732 (File permissions) | 0.41 | 0.32 | 1.00 |
| CWE-89 (SQL injection) | 0.26 | 0.11 | 1.00 |

Notable: CWE-78 — Python-only (0.64) **outperforms** C-only (0.47) on C test data. Command
injection patterns in Python training are expressed more consistently, and those patterns transfer
down to C.

### On Python Test Set

| CWE | C-only | Python-only | Joint |
|---|---|---|---|
| CWE-22 (Path traversal) | **0.91** | 0.78 | 1.00 |
| CWE-732 (File permissions) | **0.88** | 0.56 | 1.00 |
| CWE-78 (Command injection) | 0.80 | 0.76 | 1.00 |
| CWE-327 (Weak crypto) | 0.74 | 0.79 | 1.00 |
| CWE-134 (Format string) | 0.67 | 0.58 | 1.00 |
| CWE-367 (TOCTOU) | 0.60 | 0.40 | 1.00 |
| CWE-798 (Hardcoded creds) | 0.48 | 0.70 | 1.00 |
| CWE-89 (SQL injection) | 0.62 | 0.68 | 1.00 |

### Transfer Asymmetry

C-trained models generalise to Python far better than Python-trained models generalise to C:

| CWE | C-only→Python | Python-only→C | Direction |
|---|---|---|---|
| CWE-732 | **0.88** | 0.32 | C→Python |
| CWE-22 | **0.91** | 0.67 | C→Python |
| CWE-367 | 0.60 | 0.29 | C→Python |
| CWE-327 | 0.74 | 0.47 | C→Python |
| CWE-78 | 0.80 | 0.64 | C→Python |
| CWE-89 | 0.62 | 0.11 | C→Python |

C's explicit, structured syntax (syscalls, fixed-size buffers, numeric flag constants) produces
patterns that generalise upward to Python's higher-level equivalents. Python's idiomatic,
abstract patterns do not map cleanly down to C's low-level constructs.

**CWE-732 anomaly:** C-only achieves 0.88 on Python for file permissions. `chmod()`/`open()`
numeric flags in C are mirrored almost directly in Python's `os.chmod()`. The reverse (0.32)
fails because Python idioms don't translate to C's explicit bitmask patterns.

---

## 3. Insight 1 — Syntax vs Semantics (Full CWE Transfer Data)

This insight classifies CWEs into two categories based on cross-language transfer behaviour.

### Semantically-Transferable CWEs

The vulnerability concept is language-agnostic; either model transfers reasonably well:

| CWE | C-only→C | Python-only→C | C-only→Python | Python-only→Python |
|---|---|---|---|---|
| CWE-476 (Null deref) | 0.72 | 0.64 | — | — |
| CWE-457 (Uninitialised) | 0.65 | 0.61 | — | — |
| CWE-22 (Path traversal) | 0.83 | 0.67 | 0.91 | 0.78 |
| CWE-78 (Cmd injection) | 0.47 | 0.64 | 0.80 | 0.76 |

### Syntactically-Bound CWEs

Transfer collapses — the pattern is tied to one language's idioms:

| CWE | In-language | Cross-language | Gap |
|---|---|---|---|
| CWE-193 (Off-by-one) | C-only→C: **0.93** | Python-only→C: 0.27 | −0.66 |
| CWE-1333 (ReDoS) | Python-only→Py: **0.78** | C-only→Py: 0.22 | −0.56 |
| CWE-787 (OOB write) | C-only→C: 0.37 | Python-only→C: 0.23 | −0.14 |

CWE-193 is the most extreme: off-by-one errors in C are deeply syntactic (array indexing,
loop fenceposts, explicit size arithmetic). ReDoS is the mirror — it only exists in languages
with a regex engine; C has none, so C-only learns nothing about it.

### Three Anomalies

**1. CWE-119 reversal** — C-only=0.20, Python-only=0.40 on C test data.
Python-only *outperforms* C-only on a C vulnerability. CWE-119 (improper buffer bounds) is
apparently learned more abstractly from Python's boundary-check patterns than from C's
low-level pointer arithmetic.

**2. CWE-918 (SSRF) and CWE-611 (XXE) — C-only beats Python-only on Python data**
- SSRF: C-only→Python = 0.83, Python-only→Python = 0.61
- XXE: C-only→Python = 0.67, Python-only→Python = 0.50
C's socket/HTTP networking code shares enough structure with Python's `requests`/`urllib` that
the C-trained model generalises upward better than the Python model itself.

**3. CWE-120 (buffer overflow) at home = 0.48**
The most iconic C vulnerability scores barely above chance even with C-only training. Buffer
overflows appear in too many surface forms (`strcpy`, `gets`, `scanf`, `memcpy`, `sprintf`)
for the synthetic training patterns to cover adequately.

### Summary Statistics

| Configuration | Average recall |
|---|---|
| C-only on C-specific CWEs | 0.61 |
| Python-only on Python-specific CWEs | 0.75 |
| Joint on all CWEs (both languages) | **1.00** |

Python-only does better in-language than C-only, suggesting Python vulnerabilities have more
consistent, higher-level API patterns (easier to learn), while C vulnerabilities are more
varied in expression.

---

## 4. Insight 3 — Calibration / Error Analysis (Real-World)

**Test set:** `Files/sample_test.jsonl` (DiverseVul subset, 200 samples)
**Model:** Joint baseline

### Counts

| Outcome | n |
|---|---|
| True Positives (TP) | 34 |
| True Negatives (TN) | 48 |
| False Positives (FP) | 36 |
| False Negatives (FN) | 82 |

- Real-world Precision = 34/70 ≈ **0.49**
- Real-world Recall = 34/116 ≈ **0.29**
- Real-world F1 ≈ **0.37**

This is the **synthetic-to-real generalisation gap**: F1 drops from 0.948 (synthetic) to
0.37 (real-world) — a gap of ~0.57.

### Probability Distribution Analysis

The model is **bimodal and overconfident** — nearly all outputs are near 0 or near 1 with
almost no mass in the 0.2–0.8 range. There is no "uncertain" mode.

| Outcome | Probability distribution | Interpretation |
|---|---|---|
| TP (n=34) | Mostly 0.9–1.0 | Confident and correct |
| TN (n=48) | Mostly 0.0–0.05 | Confident and correct |
| FP (n=36) | **All 0.9–1.0** | Maximally confident when wrong — overconfidence |
| FN (n=82) | **Almost all 0.0–0.05** | Maximally confident when missing vulns |

### What This Means

**False Positives (36):** The model isn't hesitating — it is convinced real safe code is
vulnerable. These are safe functions that superficially match a synthetic vulnerability
template (similar API calls, structure, or keywords).

**False Negatives (82):** The model sees 116 real vulnerabilities and misses 82. These are
real vulnerable functions that don't match any synthetic pattern the model learned. The model
is equally confident they are safe.

**Root cause:** The model learned to pattern-match against synthetic templates, not to
understand the semantic properties of vulnerabilities. A lowered threshold (0.3 instead of 0.5)
would recover some FNs but at the cost of more FPs — the probability distribution itself needs
to shift, not just the decision boundary.

### Potential Mitigations

1. **Harder/more varied training data** — `wrap_in_context()` and independent held-out
   patterns are steps in this direction
2. **Temperature scaling / calibration** — post-hoc rescaling of output probabilities
3. **Real-world data augmentation** — mixing DiverseVul samples into fine-tuning
4. **Threshold tuning** — the threshold sweep (Exp 4) quantifies the precision/recall tradeoff

---

*Generated from `evaluate_experiments.py` and `analyse_insights.py` on branch
`claude/review-recent-branch-POtjK`.*
