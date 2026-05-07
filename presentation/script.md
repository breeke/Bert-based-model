# Speaker Script
**Cross-Language Software Vulnerability Detection**

---

## Slide 1 — Title

"This dissertation looks at whether a single pre-trained model can be fine-tuned to detect software vulnerabilities across both C and Python — without separate tools or preprocessing for each language. I'll walk through the motivation, what was built, the experiments, and what the results actually tell us."

---

## Slide 2 — Motivation

"Cross-language vulnerability detection isn't an unsolved problem — there's active work in this space, and models like GraphCodeBERT and CodeBERT have been applied to vulnerability detection across multiple languages. The motivation here is more specific: most of that work is evaluated at the overall accuracy level, on C-heavy datasets. There's less systematic analysis of which vulnerability classes actually transfer between languages, and why some do and others don't. This project looks at that question directly — by training on both C and Python and measuring performance class by class, with a separate test designed to distinguish what the model has actually learned from what it's just pattern-matching."

---

## Slide 3 — Research Questions

"These five questions shaped the experimental design. The first three are about whether the approach works and where it breaks down. The fourth is more diagnostic — trying to understand what the model has actually learned rather than just measuring accuracy. The fifth is about whether the outputs can be trusted in practice."

---

## Slide 4 — Approach at a Glance

"The approach has two main parts. First, we start with UniXcoder — a model that has already seen millions of lines of code and learned how code is structured. We don't train from scratch; we build on that existing knowledge. Second, we fine-tune it on our own labelled data by adding a small classification head on top and adjusting the weights to distinguish vulnerable from safe code. The training data has three ingredients: synthetic examples we built ourselves, hard negatives to stop the model from learning the wrong patterns, and a small set of real CVE-labelled functions to bridge the gap to real-world code."

---

## Slide 5 — How the Model Reads Code

*(Point to: Source function → tokenise)*
"The input is a raw source function in C or Python. The first thing that happens is tokenisation — the function is broken into small subword pieces that the model was trained on. A special CLS token is added at the very front."

*(Point to: 12 transformer layers)*
"All tokens then pass through 12 transformer layers. The key thing here is self-attention — every token can look at every other token at the same time. So the model isn't reading left to right; it sees the whole function at once and learns which parts relate to which other parts. A token like system() can directly attend to where user_input came from, several lines earlier."

*(Point to: CLS → summary)*
"After all 12 layers, the CLS token has absorbed information from the entire function. Think of it as a fixed-size summary of the whole input — everything the model learned about the function is compressed into this one vector."

*(Point to: Dropout → Linear → Sigmoid → score)*
"That summary is passed to the classification head — a dropout layer, a single linear layer, and a sigmoid — which produces a probability between 0 and 1. Above 0.5 means VULNERABLE."

*(Point to the before/after effect)*
"Fine-tuning is where we actually teach the model what we want it to do. UniXcoder arrives pre-trained — it has already seen millions of lines of code and learned how functions are structured, what common API calls look like, and how tokens relate to each other. But it has no concept of vulnerable versus safe. It has never seen a label that says this function is dangerous.

Fine-tuning changes that. We pass our labelled examples through the model, compare its output to the correct label, compute the error, and use that error to update the weights — not just in the classification head, but across all 12 transformer layers. So the internal representations themselves change. The attention patterns that were previously tuned to understand general code structure get shifted toward patterns that matter for security — things like user-controlled data reaching a dangerous function call, a weak hashing algorithm being used for a password, or a buffer being written to without a bounds check.

The reason we use a very low learning rate — 2 times 10 to the power of negative 5 — is that we don't want to erase the pre-trained knowledge. If we used a large learning rate, we would overwrite everything the model already knows about code and essentially start from scratch, which would need far more data and training time. The low rate means each update is a small nudge — the model shifts toward vulnerability detection while keeping its existing understanding of code structure intact. That's what makes fine-tuning on a relatively small synthetic dataset practical."

---

## Slide 6 — Dataset Construction

"The dataset was built in five steps. First, hand-written base patterns — one per CWE per language, kept minimal so the vulnerability is unambiguous. Then each pattern was expanded 40 times with small random variations so the model doesn't just memorise one version. The context wrapping step is particularly important — instead of feeding the model a bare 5-line snippet, each example is embedded in a realistic function body with things like null checks, mutex locks, and return statements. That makes the training distribution closer to what real code looks like. Hard negatives were added to fix specific failure modes — safe functions that share the same API structure as dangerous ones. Finally the data was split 70/15/15, with the 200 DiverseVul real-world samples kept completely separate as a second test set."

---

## Slide 7 — CWE Types Covered

*(Shared CWEs)*
"The 8 shared CWEs are the ones that appear in both C and Python training examples and are the basis of the cross-language transfer experiments. These are vulnerability classes where the same conceptual flaw can be expressed in both languages, even if the specific API looks different.

CWE-78 command injection is where user input gets passed into a shell command without sanitisation — in C that's system() with a user-controlled buffer, in Python that's os.system() or subprocess.call().

CWE-89 SQL injection is where user input is concatenated directly into a query string instead of using parameterised queries.

CWE-22 path traversal is where user input containing dot-dot-slash sequences is used to construct a file path, letting an attacker escape the intended directory.

CWE-798 hardcoded credentials means a password or API key is written directly in the source code rather than loaded from an environment variable or secrets manager.

CWE-327 is using a broken cryptographic algorithm — in our case MD5 for password hashing, which is both too fast and cryptographically broken.

CWE-134 is format string or template injection — passing user input directly as a format argument to printf in C, or into a template engine in Python without escaping.

CWE-732 is setting file permissions too broadly, like chmod 0777, making sensitive files readable or writable by anyone on the system.

CWE-367 is a time-of-check to time-of-use race condition — the program checks a condition like whether a file is safe, and an attacker swaps the file between the check and the use."

*(C-only CWEs)*
"The C-only classes are mostly memory safety issues that don't exist in Python because Python manages memory automatically. Buffer overflow is writing past the end of an array. Integer overflow is arithmetic wrapping around to a small number, often causing an undersized allocation. Use after free and double free are heap corruption bugs from mismanaging manually allocated memory. Null pointer dereference is using a pointer without checking whether it's null. Off-by-one and uninitialized variable are classic C mistakes with subtle but exploitable consequences."

*(Python-only CWEs)*
"The Python-only classes are higher-level. Unsafe deserialization means using Python's pickle library on untrusted input, which can execute arbitrary code during unpickling. SSRF is where the server makes an HTTP request to a URL constructed from user input, letting attackers probe internal services. Eval injection is passing user input directly to eval() or exec(), which runs it as Python code."

---

## Slide 8 — Dataset Examples

"These are four examples from the training set — each one represents a different vulnerability class.

CWE-78 is command injection: user_input is formatted directly into a shell command string and passed to system(). An attacker can append a semicolon and run arbitrary commands. This is cross-language — the same pattern appears in Python via os.system().

CWE-367 is a time-of-check to time-of-use race condition: the program checks whether the file is readable with access(), then opens it a moment later. In a concurrent environment an attacker can swap the file between those two calls — the check passes but the wrong file gets opened.

CWE-89 is SQL injection: the username is concatenated directly into a query string. An attacker who passes something like ' OR '1'='1 can bypass authentication or dump the entire table. The fix is a parameterised query.

CWE-190 is an integer overflow: new_size is an unsigned short, so if old_size plus extra exceeds 65535 it wraps to a small number. The buffer is allocated too small and a later write overflows it.

These are all function-level snippets — the model sees the whole function and predicts vulnerable or safe."

---

## Slide 9 — Baseline Results

"On the held-out synthetic set of 1,230 samples, the joint model reaches F1 of 0.931 with precision just under 0.96 — meaning when it flags something as vulnerable, it's right 96% of the time. 11 of the 17 CWE classes are detected perfectly. The hardest is use-after-free, which is expected — it requires tracking where a pointer was freed relative to where it's used, which is an inter-statement reasoning problem. Python outperforms C slightly, which comes down to Python's vulnerability patterns tending to be more syntactically compact."

---

## Slide 10 — Cross-Language Ablation

"This is a 3-by-3 ablation — three model variants, three test sets. The clearest result is that joint training helps in both directions: it's better on C than the C-only model, and better on Python than the Python-only model. The primary reason is the 8 CWE classes that appear in both languages during training. When the model sees SQL injection in Python and SQL injection in C, it can't rely on Python-specific tokens — it has to learn the structural pattern that makes both dangerous. That shared signal makes the representation more general, and that generalisation shows up even on within-language test sets. The asymmetry is interesting — C-trained models transfer to Python reasonably well because Python adopted a lot of C-originated idioms. The reverse is much weaker. The Python-only model essentially refuses to flag C functions — very high precision but very low recall."

---

## Slide 11 — CWE Transfer Profiles

"Digging into the per-CWE numbers explains the asymmetry. Hardcoded credentials transfer perfectly in both directions because the pattern is literally the same — a string assigned to a variable called password. Command injection is asymmetric because Python's os.system() shares tokens with C's system(), but C's pattern involves buffer setup with sprintf first. TOCTOU race conditions don't transfer at all — the languages express the same race condition through completely different function calls. The headline finding is that transfer quality is about surface token overlap, not semantic equivalence."

---

## Slide 12 — Hard Negative Mining

"After the initial training run I went through the false positives manually and found two systematic patterns. The clearest one: the model was flagging sha256 as vulnerable because it had only ever seen hashlib in vulnerable examples using md5. Adding 17 contrastive examples — safe functions using sha256 in the same structural position as the dangerous md5 examples — dropped the sha256 probability from 0.906 to 0.048. The system() case is different. Both the vulnerable and the safe version call system() with a char buffer. The only difference is where the buffer's value came from — and that requires following data flow through the function, which a sequence encoder can't do."

---

## Slide 13 — Real-World Augmentation

"The bigger problem was the gap between synthetic and real performance — 0.931 on the held-out set, 0.410 on real CVE code. That's a 0.52 point gap. Hard negatives helped a little — they reduced false positives on safe code that shares tokens with dangerous code. But the majority of the improvement came from mixing 1,000 real DiverseVul samples into the training set. That alone took real-world F1 from 0.471 to 0.749 and cut the gap to 0.182. Synthetic performance didn't move at all. The lesson is simple: if real-world performance matters, real-world training data has a much higher return than any amount of synthetic tuning."

---

## Slide 14 — Semantic Understanding Tests

"Rather than just reporting accuracy, I ran four controlled tests to understand what the model has actually learned. In the renaming test, I take a vulnerable C function and rename every variable — run_command becomes execute_action, user_input becomes data, cmd becomes buffer. The prediction barely moves: 0.958 to 0.957. The model is reading the code structure, not the names. In the minimal-fix test, I change just one token — md5 to sha256 — and the probability drops from 0.960 to 0.048. It knows exactly what made that function dangerous. The token ablation test flips this: replace system with safe_exec and the probability doesn't move — 0.958 stays 0.958 — which means it's detecting the pattern around that call, not the call name itself. Then the dead code test: I add a system call inside if(0), which can never run. The model predicts VULNERABLE at 0.860. It saw the token, matched the pattern, and had no way to know the branch was unreachable."

---

## Slide 15 — What the Tests Reveal

"The passing tests confirm the model has learned something structural — it's not just matching keywords. But the dead-code failures are a clean demonstration of the limit. If I put a dangerous-looking call inside an if(0) block that can never execute, the model still flags the function as vulnerable. It's reading the tokens, not reasoning about whether they can run. And there's no way to fix that by adding more training data — the architecture fundamentally can't represent control flow. Interestingly, one CWE-798 dead-code case passed — because the hardcoded credential was absent from the token stream entirely, so the model correctly predicted safe."

---

## Slide 16 — Calibration

"A quick note on calibration — this matters for practical use. After training, temperature scaling found an optimal T of 0.981, which is essentially 1.0, meaning the model's raw outputs are already well-calibrated. That's a direct consequence of label smoothing during training. The synthetic calibration plot is nicely bimodal — the model is either confident it's safe or confident it's vulnerable. The real-world plot is broader, with more mass in the middle, which reflects the model's uncertainty when it sees code styles it hasn't been trained on."

---

## Slide 17 — Limitations and Future Work

"To be clear about the limitations: the synthetic-to-real gap of 0.182 that remains after augmentation isn't a failure — it's a measurement of how hard the problem is. Some of it comes from CWE classes that simply aren't in the training data at all; those just need more coverage. The harder part is the architectural ceiling — the things where more data won't help. The most impactful single architectural change would be adding a data-flow graph component, which would let the model follow values from input sources to dangerous sinks."

---

## Slide 18 — Summary

"To summarise: the system works and reaches practically useful performance on the synthetic evaluation. The most important finding beyond the accuracy numbers is probably the augmentation result — 1,000 real samples nearly doubled real-world F1 — because it has a clear implication for anyone building something similar. And the semantic tests are the most honest part of the evaluation: they show the model has learned something meaningful, but also draw a clear line at what sequence-based models can and can't do."

---

## Slide 19 — Questions

"Thank you. Happy to take questions."
