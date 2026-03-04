# BERT-Based Vulnerability Detection — Project Report

**Date:** 2026-03-04
**Model:** CodeBERT / RoBERTa fine-tuned for binary vulnerability classification
**Repository:** `breeke/Bert-based-model`

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Model Architecture](#2-model-architecture)
3. [Dataset — Three Generations](#3-dataset--three-generations)
4. [Multi-Language Dataset — Full Coverage](#4-multi-language-dataset--full-coverage)
5. [Infrastructure Improvements](#5-infrastructure-improvements)
6. [Testing Plan](#6-testing-plan)
7. [Expected Results & Metrics](#7-expected-results--metrics)
8. [Cross-Language Generalisation Test](#8-cross-language-generalisation-test)
9. [Gaps to Address Before Final Testing](#9-gaps-to-address-before-final-testing)

---

## 1. Project Overview

This project fine-tunes **Microsoft's CodeBERT** model to automatically detect security vulnerabilities in source code. The task is binary classification: given a function, predict whether it contains a vulnerability (`1`) or is safe (`0`).

The project has evolved through three dataset generations, culminating in a **multi-language synthetic dataset** covering both C and Python, with 8 vulnerability types shared across both languages — enabling the model to learn language-agnostic vulnerability patterns.

---

## 2. Model Architecture

| Component | Detail |
|---|---|
| Base model | `microsoft/codebert-base` (RoBERTa encoder) |
| Task | Binary sequence classification |
| Labels | `1` = vulnerable, `0` = safe |
| Classifier head | Linear layer: 768 → 1, sigmoid activation |
| Loss function | Binary cross-entropy |
| Max sequence length | 400 tokens |
| Hidden dimension | 768 |
| Attention heads | 12 |
| Transformer layers | 12 |
| Optimizer | AdamW, lr = 2e-5, weight decay = 0.01 |
| Scheduler | Linear warmup (10% of total steps) |
| Gradient clipping | 1.0 |
| Dropout | 0.1 |

**Forward pass:**
1. Build attention mask from `input_ids` (ignores padding)
2. Pass through RoBERTa encoder
3. Extract `[CLS]` token as sequence representation
4. Apply dropout → linear classifier → sigmoid → probability

---

## 3. Dataset — Three Generations

### Generation 1 — Real World (DiverseVul)

| Split | Samples | Vulnerable | Safe |
|---|---|---|---|
| Train | 1,000 | 465 (46.5%) | 535 (53.5%) |
| Valid | 200 | 98 (49.0%) | 102 (51.0%) |
| Test | 200 | 116 (58.0%) | 84 (42.0%) |
| **Total** | **1,400** | | |

- Real C code from the DiverseVul dataset
- Slight class imbalance, especially in the test split
- Best for real-world validation

### Generation 2 — Minimal Synthetic (C only)

| Split | Samples | Vulnerable | Safe |
|---|---|---|---|
| Train | 4,200 | 2,090 | 2,110 |
| Valid | 900 | 444 | 456 |
| Test | 900 | 466 | 434 |
| **Total** | **6,000** | | |

- Perfectly balanced (50/50)
- Only 5 simple C vulnerability patterns
- Useful for sanity checks and fast iteration

### Generation 3 — Multi-Language (Current)

| Split | Samples | Notes |
|---|---|---|
| Train | 5,768 | 70% |
| Valid | 1,236 | 15% |
| Test | 1,236 | 15% |
| **Total** | **8,240** | |

- 206 base patterns × 40 random variations each
- C and Python, 29 vulnerability categories total
- 8 CWE types shared across both languages
- Variation engine adds comment, whitespace, and blank-line noise for diversity

---

## 4. Multi-Language Dataset — Full Coverage

### Pattern Counts

| Language | Vulnerable patterns | Safe patterns |
|---|---|---|
| C | 59 | 51 |
| Python | 48 | 48 |
| **Total** | **107** | **99** |

### Vulnerability Types

| CWE | Vulnerability | C | Python | Cross-Language |
|---|---|:---:|:---:|:---:|
| CWE-120 | Buffer Overflow | ✓ | — | — |
| CWE-122 | Heap Overflow | ✓ | — | — |
| CWE-134 | Format String / Template Injection | ✓ | ✓ | **Yes** |
| CWE-190 | Integer Overflow | ✓ | — | — |
| CWE-193 | Off-by-One | ✓ | — | — |
| CWE-415 | Double Free | ✓ | — | — |
| CWE-416 | Use-After-Free | ✓ | — | — |
| CWE-457 | Uninitialized Variable | ✓ | — | — |
| CWE-476 | Null Pointer Dereference | ✓ | — | — |
| CWE-502 | Insecure Deserialization | — | ✓ | — |
| CWE-611 | XXE | — | ✓ | — |
| CWE-918 | SSRF | — | ✓ | — |
| CWE-95 | Eval / Exec Injection | — | ✓ | — |
| CWE-1333 | ReDoS | — | ✓ | — |
| **CWE-22** | **Path Traversal** | **✓** | **✓** | **Yes** |
| **CWE-78** | **Command Injection** | **✓** | **✓** | **Yes** |
| **CWE-89** | **SQL Injection** | **✓** | **✓** | **Yes** |
| **CWE-327** | **Weak Cryptography** | **✓** | **✓** | **Yes** |
| **CWE-367** | **TOCTOU Race Condition** | **✓** | **✓** | **Yes** |
| **CWE-732** | **Insecure File Permissions** | **✓** | **✓** | **Yes** |
| **CWE-798** | **Hardcoded Credentials** | **✓** | **✓** | **Yes** |

**Cross-language CWE count: 8** (up from 2 in the original dataset)

---

## 5. Infrastructure Improvements

### Dynamic Padding
- **Before:** All sequences padded to the global max of 400 tokens regardless of actual length
- **After:** Sequences padded to the longest sequence in each batch
- **Memory saving:** ~53% reduction in padding storage
- **Speed gain:** ~20–30% faster training per epoch

### Truncation Tracking
- Previously: long sequences were silently truncated
- Now: a warning is logged for every truncated sample showing token count, limit, and % of content lost
- Observed: 11.4% of real-world samples (114 / 1,000) exceeded 400 tokens

### Code Normalisation
- Preserves newlines and indentation (structural information for code understanding)
- Collapses excess whitespace without destroying formatting
- Better than aggressive whitespace stripping used previously

### Variation Engine
Each base pattern is replicated 40 times with lightweight random variation:
- 30% chance — random comment inserted after the function signature
- 20% chance — trailing blank line appended
- 15% chance — leading blank line prepended
- Variable name substitution pools (e.g. `buffer` → `buf`, `tmpbuf`, `recv_buf`)

This prevents the model from memorising identical strings and improves generalisation.

### Error & Quality Logging
Dataset loading now tracks and reports:
- JSON parse errors
- Missing required fields (`func`, `target`)
- Empty function bodies
- Token length distribution (min / max / average)
- Class balance (vulnerable vs safe counts and percentages)

---

## 6. Testing Plan

### Step 1 — Generate the Dataset

```bash
python multi_language_dataset_creator.py
# Outputs: Files/multi_lang_train.jsonl
#          Files/multi_lang_valid.jsonl
#          Files/multi_lang_test.jsonl
```

### Step 2 — Train

```bash
python train.py \
    --train_data_file ./Files/multi_lang_train.jsonl \
    --eval_data_file  ./Files/multi_lang_valid.jsonl \
    --test_data_file  ./Files/multi_lang_test.jsonl  \
    --output_dir      ./multi_lang_model \
    --do_train --do_eval --do_test \
    --num_epochs 5 \
    --train_batch_size 16
```

### Step 3 — Evaluate

Run evaluation on the held-out test split. Collect the full set of metrics listed in section 7.

### Step 4 — Real-World Validation

After training on synthetic data, run inference on the original DiverseVul samples to check for overfitting:

```bash
python train.py \
    --test_data_file ./Files/sample_test.jsonl \
    --output_dir     ./multi_lang_model \
    --do_test
```

A significant drop in performance vs synthetic results signals the model has overfit to synthetic patterns and needs real-world data mixed in.

---

## 7. Expected Results & Metrics

### Metrics to Collect

The current `evaluate()` function only returns **accuracy**. The following must be added before final evaluation:

| Metric | Formula | Why It Matters |
|---|---|---|
| **Accuracy** | (TP + TN) / total | Baseline, already implemented |
| **Precision** | TP / (TP + FP) | Cost of false alarms — important for usability |
| **Recall** | TP / (TP + FN) | Cost of missed vulnerabilities — most critical for security |
| **F1 Score** | 2 × (P × R) / (P + R) | Harmonic balance of precision and recall |
| **AUC-ROC** | Area under ROC curve | Threshold-independent discriminative ability |
| **Per-language F1** | F1 split by C / Python | Tests cross-language generalisation |
| **Per-CWE F1** | F1 per vulnerability type | Identifies which CWEs the model struggles with |

### Performance Targets

| Metric | Realistic Target | Stretch Target |
|---|---|---|
| Accuracy | 85–90% | > 92% |
| F1 Score | 0.82–0.88 | > 0.90 |
| Recall (vulnerable class) | > 0.85 | > 0.90 |
| Precision (vulnerable class) | > 0.80 | > 0.88 |
| AUC-ROC | > 0.90 | > 0.95 |

> **Important caveat:** Synthetic datasets typically produce inflated metrics (often 95%+) because the patterns are regular and controlled. Targets above are for the synthetic test split. Real-world DiverseVul performance will be lower — a realistic F1 on real code is 0.65–0.75 for a model trained only on synthetic data.

---

## 8. Cross-Language Generalisation Test

The core research question: does training on both C and Python improve detection of the 8 shared CWEs compared to training on a single language?

### Suggested Ablation Matrix

| Train set | Test set | Expected outcome |
|---|---|---|
| C only | C test set | Baseline C performance |
| Python only | Python test set | Baseline Python performance |
| C + Python | C test set | Should match or exceed C-only |
| C + Python | Python test set | Should match or exceed Python-only |
| C + Python | Cross-CWE subset only | Target: F1 > 0.85 on the 8 shared CWEs |

### Hypothesis

The model trained on both languages should outperform single-language models on the shared CWEs because it has seen the same vulnerability concept expressed in two syntaxes, forcing it to learn the underlying pattern rather than language-specific surface features.

---

## 9. Gaps to Address Before Final Testing

| # | Gap | Impact | Fix |
|---|---|---|---|
| 1 | `evaluate()` returns only accuracy | Cannot assess recall or F1 — critical for a security tool | Add Precision, Recall, F1, AUC-ROC to evaluate() |
| 2 | No per-CWE breakdown in test output | Cannot identify which vulnerability types are weak | Group predictions by CWE label in test() |
| 3 | No real-world validation step | Risk of reporting inflated synthetic metrics | Run inference on `sample_test.jsonl` after training |
| 4 | Classification threshold inconsistency | `train.py` uses 0.5; `predict.py` uses 0.3 | Align to 0.3 or make configurable; 0.3 is better for security (higher recall) |
| 5 | No confusion matrix output | Hard to understand error distribution | Add confusion matrix to test() output |
| 6 | Safe counterparts missing for some new C CWEs | Slight class imbalance in C patterns | Add 1–2 safe patterns for heap_overflow, heap_safe |

---



