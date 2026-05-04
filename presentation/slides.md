# Presentation Slide Content
**Cross-Language Software Vulnerability Detection**
15–17 min content + Q&A

Each slide shows: what the audience sees | what to say

---

## Slide 1 — Title (30 sec)

**SLIDE TITLE:** *(none — full-bleed title slide)*

**ON SLIDE:**
> Cross-Language Software Vulnerability Detection
> via Fine-Tuned Pre-Trained Code Models
>
> [Author Name]
> April 2026

**SAY:**
"This dissertation looks at whether a single pre-trained model can be fine-tuned to detect
software vulnerabilities across both C and Python — without separate tools or preprocessing
for each language. I'll walk through the motivation, what was built, the experiments, and
what the results actually tell us."

---

## Slide 2 — Motivation (1 min)

**SLIDE TITLE:** Why Cross-Language Vulnerability Detection?

**ON SLIDE:**
- Around 80% of real-world projects use 7 or more programming languages
- Vulnerability patterns differ per language — same conceptual flaw, different APIs
- Cross-language detection is an active area: GraphCodeBERT, LineVul, DiverseVul-based work
- Most existing approaches are evaluated on a single language or a single dataset
- Less work looks at **which specific vulnerability classes actually transfer** and why
- This project: fine-tune a pre-trained model on C + Python, measure transfer at the CWE level,
  and test whether the model has learned patterns or just surface tokens

**VISUAL:** No image file needed. Simple two-column layout — left column: bullet list of languages in a typical project (C, Python, JS, YAML, Bash…); right column: the goal statement in a highlight box.

**SAY:**
"Cross-language vulnerability detection isn't an unsolved problem — there's active work in
this space, and models like GraphCodeBERT and CodeBERT have been applied to vulnerability
detection across multiple languages. The motivation here is more specific: most of that
work is evaluated at the overall accuracy level, on C-heavy datasets. There's less
systematic analysis of which vulnerability classes actually transfer between languages,
and why some do and others don't. This project looks at that question directly — by
training on both C and Python and measuring performance class by class, with a separate
test designed to distinguish what the model has actually learned from what it's just
pattern-matching."

---

## Slide 3 — Research Questions (45 sec)

**SLIDE TITLE:** What This Work Investigates

**ON SLIDE:**
1. Can a pre-trained code model detect vulnerabilities across C and Python from one model?
2. Which CWE vulnerability classes transfer across languages — and why?
3. How large is the gap between synthetic and real-world performance, and can it be reduced?
4. Does the model rely on pattern-matching or something closer to semantic understanding?
5. How well-calibrated are the model's confidence scores for practical use?

**SAY:**
"These five questions shaped the experimental design. The first three are about whether the
approach works and where it breaks down. The fourth is more diagnostic — trying to understand
what the model has actually learned rather than just measuring accuracy. The fifth is about
whether the outputs can be trusted in practice."

---

## Slide 4 — System Overview (1 min)

**SLIDE TITLE:** Approach at a Glance

**ON SLIDE:**
```
Source code (C or Python)
        ↓
  UniXcoder encoder
  (pre-trained on multi-language code)
        ↓
  [CLS] token
        ↓
  Dropout → Linear → Sigmoid
        ↓
  VULNERABLE / SAFE  (+ confidence score)
```

Three training ingredients:
- Synthetic examples: 17 CWE types across C and Python
- Hard negatives: safe code that looks dangerous on the surface
- Real-world augmentation: 1,000 samples from DiverseVul (real CVE-labelled C functions)

**SAY:**
"The model itself is straightforward — UniXcoder is a pre-trained encoder that already
understands code structure from large-scale pre-training. On top of it sits a very small
classification head. The interesting parts are the training data: a synthetic dataset
covering 17 vulnerability classes in two languages, deliberately constructed contrastive
pairs to fix specific failure modes, and a small injection of real-world C code to reduce
the gap between training conditions and what real code looks like."

---

## Slide 5 — Dataset (1 min)

**SLIDE TITLE:** Dataset Construction

**ON SLIDE:**

| | C | Python |
|---|---|---|
| CWE types | 14 | 11 |
| Shared across both languages | **8** | **8** |
| Held-out validation samples | 660 | 570 |

- Examples are wrapped in realistic function context (not bare snippets)
- Hard negative pairs: safe functions using the same API as vulnerable ones
- Real-world test set: **200 DiverseVul samples** — never seen during training

Notable gap: no large real-world Python vulnerability dataset exists at scale,
which is why synthetic training data was necessary for Python.

**SAY:**
"The synthetic dataset covers 17 CWE types — 8 of which appear in both languages, which
is what the cross-language experiments are based on. Each example is wrapped in a
realistic function body rather than being a bare code snippet, to make the training
distribution closer to what a real function looks like. For evaluation I kept 1,230 samples
completely held out from training, plus a separate 200-sample set of real CVE-labelled
functions from DiverseVul, which is a dataset of real C code from open-source projects."

---

## Slide 6 — Baseline Results (1.5 min)

**SLIDE TITLE:** Experiment 1: How Well Does the Joint Model Perform?

**ON SLIDE:**

| Metric | Score |
|---|---|
| F1 | **0.931** |
| Precision | 0.961 |
| Recall | 0.902 |
| AUC-ROC | 0.964 |

C: F1 = 0.905 &nbsp;&nbsp;&nbsp; Python: F1 = 0.961

**11 of 17 CWE classes reach perfect F1 = 1.00**
Hardest class: CWE-416 (use-after-free) — F1 = 0.667

**VISUAL — use both, side by side:**
- Left: `results/plots/exp1_confusion_matrix.png` — confusion matrix (TN=390, FP=30, FN=79, TP=731)
- Right: `results/plots/exp1_per_cwe_f1.png` — bar chart of per-CWE F1, clearly shows the 11 perfect classes and CWE-416 as the lowest bar

Place the two images side by side, metrics table above them or replaced by the confusion matrix.

**SAY:**
"On the held-out synthetic set of 1,230 samples, the joint model reaches F1 of 0.931 with
precision just under 0.96 — meaning when it flags something as vulnerable, it's right 96%
of the time. 11 of the 17 CWE classes are detected perfectly. The hardest is use-after-free,
which is expected — it requires tracking where a pointer was freed relative to where it's
used, which is an inter-statement reasoning problem. Python outperforms C slightly, which
comes down to Python's vulnerability patterns tending to be more syntactically compact."

---

## Slide 7 — Cross-Language Ablation (1.5 min)

**SLIDE TITLE:** Experiment 2: Does Cross-Language Transfer Actually Work?

**ON SLIDE:**

| Trained on → Tested on | C test | Python test |
|---|---|---|
| C only | 0.861 | 0.811 |
| Python only | 0.677 | 0.976 |
| **Joint (both)** | **0.905** | **0.961** |

Key findings:
- Joint training outperforms single-language training on **every** test set
- C → Python transfer (0.811) is substantially stronger than Python → C (0.677)
- Python-only model collapses on C: precision 1.00 but recall only 0.596 — too conservative

**Why joint training wins:**
The 8 shared CWEs appear in both languages during training. Seeing the same vulnerability
concept expressed in two different syntactic forms forces the model to learn the
*underlying pattern* rather than a language-specific surface representation.
Each shared CWE effectively doubles the training signal for that concept — the Python
SQL injection examples reinforce the C SQL injection examples and vice versa.
The result is a more robust decision boundary for shared classes, which lifts performance
even on single-language test sets (Joint on C = 0.905 vs C-only on C = 0.861).

**VISUAL — use both:**
- `results/plots/exp2_ablation_heatmap.png` — colour-coded 3×3 F1 heatmap (rows = train language, columns = test language); place this prominently, it tells the story at a glance
- The table in the slide is a text backup — if the heatmap is clear enough on its own, drop the table and let the image fill the slide with a few bullet points below it

**SAY:**
"This is a 3-by-3 ablation — three model variants, three test sets. The clearest result is
that joint training helps in both directions: it's better on C than the C-only model, and
better on Python than the Python-only model. The primary reason is the 8 CWE classes that
appear in both languages during training. When the model sees SQL injection in Python and
SQL injection in C, it can't rely on Python-specific tokens — it has to learn the
structural pattern that makes both dangerous. That shared signal makes the representation
more general, and that generalisation shows up even on within-language test sets.
The asymmetry is interesting — C-trained models transfer to Python reasonably well because
Python adopted a lot of C-originated idioms. The reverse is much weaker. The Python-only
model essentially refuses to flag C functions — very high precision but very low recall."

---

## Slide 8 — CWE Transfer Profiles (1 min)

**SLIDE TITLE:** Why Some CWEs Transfer and Others Don't

**VISUAL — use both, one per column:**
- Left: `results/insights/insight1_cwe_transfer_c.png` — per-CWE F1 heatmap on the C test set across all three model variants
- Right: `results/insights/insight1_cwe_transfer_python.png` — same for Python test set
- The contrast between the two images makes the asymmetry visible immediately; point to CWE-78 and CWE-367 rows during the talk

**ON SLIDE:**

**Bidirectional transfer** ✓ both directions
- CWE-798 (hardcoded credentials) — a string literal assigned to a password variable looks identical in C and Python

**Asymmetric transfer** → one direction only
- CWE-78 (command injection) — C-only model transfers to Python (shared `system()` token); Python-only fails on C (different buffer pattern)

**Language-locked** ✗ neither direction
- CWE-367 (TOCTOU race condition) — C uses `stat()`/`open()`; Python uses `os.path.exists()`/`open()` — completely different surface tokens

**Key insight:** Transfer quality tracks **surface similarity**, not how conceptually similar the flaw is.

**SAY:**
"Digging into the per-CWE numbers explains the asymmetry. Hardcoded credentials transfer
perfectly in both directions because the pattern is literally the same — a string assigned
to a variable called password. Command injection is asymmetric because Python's os.system()
shares tokens with C's system(), but C's pattern involves buffer setup with sprintf first.
TOCTOU race conditions don't transfer at all — the languages express the same race condition
through completely different function calls. The headline finding is that transfer quality
is about surface token overlap, not semantic equivalence."

---

## Slide 9 — Hard Negative Mining (1 min)

**SLIDE TITLE:** Fixing Failure Mode 1: Hard Negatives

**ON SLIDE:**

**Problem found:** `hashlib.sha256` (safe) predicted VULNERABLE at p = 0.906
→ Model learned: *anything with hashlib = dangerous*

**Fix:** Added 17 safe contrastive examples with sha256, sha512, and safe `system()` usage

**Result:**

| Case | Before | After |
|---|---|---|
| md5 — VULNERABLE | 0.960 | 0.960 ✓ |
| sha256 — SAFE | 0.906 ✗ | **0.048** ✓ |
| system() with hardcoded path — SAFE | 0.929 ✗ | 0.929 ✗ |

CWE-327 fully resolved. The `system()` case is **not fixable with data** — it needs data-flow tracking to distinguish user-controlled from hardcoded inputs.

**SAY:**
"After the initial training run I went through the false positives manually and found two
systematic patterns. The clearest one: the model was flagging sha256 as vulnerable because
it had only ever seen hashlib in vulnerable examples using md5. Adding 17 contrastive
examples — safe functions using sha256 in the same structural position as the dangerous
md5 examples — dropped the sha256 probability from 0.906 to 0.048. The system() case
is different. Both the vulnerable and the safe version call system() with a char buffer.
The only difference is where the buffer's value came from — and that requires following
data flow through the function, which a sequence encoder can't do."

---

## Slide 10 — Real-World Augmentation (1.5 min)

**SLIDE TITLE:** Fixing Failure Mode 2: Real-World Augmentation

**VISUAL — use both, side by side:**
- Left: `results/plots/exp3_confusion_synthetic.png` — confusion matrix on synthetic held-out set (good numbers, to show the baseline is solid)
- Right: `results/plots/exp3_confusion_realworld.png` — confusion matrix on real-world test set after augmentation (post-augmentation state)
- Caption them clearly: "Synthetic (held-out)" and "Real-world (post-augmentation)" so the audience sees the remaining gap visually

**ON SLIDE:**

**Problem:** Real-world F1 = 0.410 despite synthetic F1 = 0.931
→ Real functions are longer, noisier, and stylistically different from synthetic examples

**Fix:** Added 1,000 DiverseVul C/C++ samples (real CVE-labelled functions) to training

| Training stage | Synthetic F1 | Real-world F1 | Gap |
|---|---|---|---|
| Synthetic only | 0.931 | 0.410 | −0.522 |
| + Hard negatives | 0.931 | 0.471 | −0.460 |
| **+ Real augmentation** | **0.931** | **0.749** | **−0.182** |

Synthetic performance unchanged. Real-world F1 nearly doubled.
This was the single highest-leverage change in the project.

**SAY:**
"The bigger problem was the gap between synthetic and real performance — 0.931 on the
held-out set, 0.410 on real CVE code. That's a 0.52 point gap. Hard negatives helped a
little — they reduced false positives on safe code that shares tokens with dangerous code.
But the majority of the improvement came from mixing 1,000 real DiverseVul samples into
the training set. That alone took real-world F1 from 0.471 to 0.749 and cut the gap to
0.182. Synthetic performance didn't move at all. The lesson is simple: if real-world
performance matters, real-world training data has a much higher return than any amount
of synthetic tuning."

---

## Slide 11 — Semantic Understanding Tests (1.5 min)

**SLIDE TITLE:** Experiment 4: What Has the Model Actually Learned?

**VISUAL:**
- `results/insights/insight2_missed_cwes.png` — bar chart of false negatives by CWE class on the real-world test; place in the bottom half or right column to show which classes the model misses most (CWE-703, CWE-125, CWE-787)
- Optional secondary: `results/insights/insight2_length_vs_accuracy.png` — accuracy vs function length (short/medium/long); shows medium-length functions are hardest — use this only if you have time to mention it

**ON SLIDE:**

Four probing tests designed to go beyond accuracy:

| Test | Question asked | Outcome |
|---|---|---|
| Variable renaming | Does prediction change if we rename all variables? | **6/6 pass** |
| Minimal fix | Does a one-line security fix flip the prediction? | **7/8 pass** |
| Dead code | Does unreachable code still trigger VULNERABLE? | **1/5 pass** |
| Token ablation | Can we remove the "dangerous" keyword and still detect it? | **6/6 pass** |
| | **Total** | **20 / 25** |

**SAY:**
"Standard accuracy numbers don't tell you what the model has learned — just whether it
gets the right answer. So I designed four tests that probe specific aspects of understanding.
The renaming and ablation tests check whether the model is just keyword-spotting. The
minimal-fix test checks whether it recognises the change that actually fixes a vulnerability.
The dead-code test checks whether it understands control flow — whether it knows a code
path is unreachable. The results split cleanly."

---

## Slide 12 — What the Tests Reveal (1 min)

**SLIDE TITLE:** The Ceiling of Sequence-Based Models

**VISUAL:**
- `results/insights/insight4_gap_per_cwe.png` — bar chart showing per-CWE recall gap between synthetic held-out and real-world test; bars going left (negative = worse on real) vs right (positive = better on real)
- Place on the right half; use bullet points on the left; point to CWE-134 (biggest negative gap) and CWE-732/CWE-78 (positive transfer) during the talk

**ON SLIDE:**

**What the model has learned** ✓
- Stable predictions across variable renames — not anchored to identifier names
- Stable across single-token removal — not relying on one keyword
- Detects the structural change that fixes a vulnerability:
  md5 → sha256 drops predicted probability from 0.960 to 0.048

**Where it fails** ✗
- Code inside `if(0)` or `if False:` still predicts VULNERABLE
- The model cannot determine whether a code path is reachable
- Reachability requires a **control-flow graph** — unavailable to a sequence encoder
- This is an **architectural ceiling**, not a data problem

**SAY:**
"The passing tests confirm the model has learned something structural — it's not just
matching keywords. But the dead-code failures are a clean demonstration of the limit.
If I put a dangerous-looking call inside an if(0) block that can never execute, the model
still flags the function as vulnerable. It's reading the tokens, not reasoning about
whether they can run. And there's no way to fix that by adding more training data —
the architecture fundamentally can't represent control flow. Interestingly, one CWE-798
dead-code case passed — because the hardcoded credential was absent from the token stream
entirely, so the model correctly predicted safe."

---

## Slide 13 — Calibration (45 sec)

**SLIDE TITLE:** Are the Confidence Scores Trustworthy?

**VISUAL — use both, side by side:**
- Left: `results/insights/insight3_calibration_synthetic.png` — reliability diagram on synthetic held-out set; bimodal, well-calibrated
- Right: `results/insights/insight3_calibration_real_world.png` — same on real-world test; broader distribution, more mass in the middle
- Label them clearly: "Synthetic" and "Real-world" — the contrast is the story
- Alternative if you want the raw output histogram: `results/plots/calibration_histograms.png`

**ON SLIDE:**
- Temperature scaling after training: T = **0.981** (essentially 1.0)
- Near-unity T means label smoothing (ε = 0.1) already calibrated the model during training
- Synthetic outputs: **bimodal** — clearly safe (p ≈ 0.05) or clearly vulnerable (p ≈ 0.96)
- Real-world outputs: broader — more ambiguous partial matches in the 0.3–0.7 range
- Practical use: scores can be used to **rank and prioritise** a vulnerability report queue

**SAY:**
"A quick note on calibration — this matters for practical use. After training, temperature
scaling found an optimal T of 0.981, which is essentially 1.0, meaning the model's raw
outputs are already well-calibrated. That's a direct consequence of label smoothing during
training. The synthetic calibration plot is nicely bimodal — the model is either confident
it's safe or confident it's vulnerable. The real-world plot is broader, with more mass in
the middle, which reflects the model's uncertainty when it sees code styles it hasn't been
trained on."

---

## Slide 15 — Limitations and Future Work (1 min)

**SLIDE TITLE:** Where This Falls Short and What Comes Next

**VISUAL:**
- No dedicated image needed here — this is a text-heavy summary slide
- Optional: `results/plots/exp4_precision_recall_curve.png` as a small insert to illustrate the threshold trade-off point if you want to mention deployment flexibility (precision = 1.00 is achievable at threshold 0.8)

**ON SLIDE:**

**Main limitations**
- Cannot track data flow or check reachability — architectural, not fixable with more data
- Only 17 CWE types in training; DiverseVul test spans ~50 — recall on unseen classes is zero
- C and Python only; no large Python real-world dataset exists at comparable scale
- 200-sample real-world test set too small for reliable per-CWE estimates

**Most direct next steps**
1. **Graph-augmented encoder** — add a GNN over the data-flow graph to enable taint tracking
2. **Scale augmentation** — 10,000 real samples could plausibly close the remaining 0.182 gap
3. **More CWE types** — add synthetic templates for CWE-787, CWE-400, CWE-703 (the three biggest miss clusters in the real-world test)

**SAY:**
"To be clear about the limitations: the synthetic-to-real gap of 0.182 that remains after
augmentation isn't a failure — it's a measurement of how hard the problem is. Some of it
comes from CWE classes that simply aren't in the training data at all; those just need more
coverage. The harder part is the architectural ceiling — the things where more data won't
help. The most impactful single architectural change would be adding a data-flow graph
component, which would let the model follow values from input sources to dangerous sinks."

---

## Slide 16 — Summary (1 min)

**SLIDE TITLE:** Summary

**ON SLIDE:**

| What was built / done | Key number |
|---|---|
| Multi-language synthetic dataset | 17 CWEs · C + Python · 1,230 validation samples |
| Fine-tuned UniXcoder classifier | F1 = 0.931 · Precision = 0.961 · AUC = 0.964 |
| Cross-language ablation study | Joint training outperforms single-language on every test set |
| Hard negative mining | sha256 false positive: 0.906 → 0.048 |
| Real-world augmentation | Real F1: 0.410 → 0.749 · Gap: −0.522 → −0.182 |
| Semantic understanding tests | 20/25 · Architectural ceiling located precisely |

**One-sentence takeaway:**
With careful dataset design, targeted hard negatives, and a small injection of real-world
data, a pre-trained code model can reach practically useful multi-language vulnerability
detection — and the semantic tests show exactly what it has learned and where it stops.

**SAY:**
"To summarise: the system works and reaches practically useful performance on the synthetic
evaluation. The most important finding beyond the accuracy numbers is probably the
augmentation result — 1,000 real samples nearly doubled real-world F1 — because it has a
clear implication for anyone building something similar. And the semantic tests are the
most honest part of the evaluation: they show the model has learned something meaningful,
but also draw a clear line at what sequence-based models can and can't do."

---

## Slide 17 — Questions

**ON SLIDE:**
> Thank you
>
> Questions?

**Suggested Q&A prep:**

| Likely question | Short answer |
|---|---|
| Why UniXcoder over CodeBERT / GraphCodeBERT? | UniXcoder incorporates AST structure at pre-training time; single architecture for both understanding and generation; competitive on code benchmarks |
| Why only 1,000 augmentation samples? | Proof-of-concept scale — the strong response suggests scaling further would help, addressed in future work |
| How does this scale to Java or JavaScript? | Would need retraining with data from those languages; pre-training corpus already includes Java/JS so transfer cost should be low |
| What would the graph architecture look like? | Replace or augment the sequence encoder with a GNN over the data-flow graph; GraphCodeBERT is the closest existing model |
| How was synthetic data validated? | Hard negative tests and the semantic understanding suite act as validation — the minimal-fix tests confirm the synthetic patterns are recognisable to the model |
