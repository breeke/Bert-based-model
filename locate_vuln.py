"""
locate_vuln.py — Run vulnerability detection on a C file and a Python file,
pinpoint WHICH lines are most likely vulnerable, then compare similarities
between the two files' vulnerabilities.

Usage:
    python locate_vuln.py --c_file examples/vuln_example.c --py_file examples/vuln_example.py --model_dir ./saved_models
    python locate_vuln.py --c_file path/to/file.c --py_file path/to/file.py --model_dir ./saved_models --threshold 0.4 --window 5
"""

import re
import argparse
import torch
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from model import Model


# ---------------------------------------------------------------------------
# Vulnerability pattern catalogue — maps keywords to human-readable category
# Works for both C and Python flagged lines
# ---------------------------------------------------------------------------
VULN_PATTERNS = {
    "Command Injection": [
        r"\bsystem\s*\(", r"\bpopen\s*\(", r"\bexecv?\w*\s*\(",
        r"\bos\.system\b", r"\bsubprocess\.(call|run|Popen)\b",
        r"\bshell\s*=\s*True\b",
    ],
    "Buffer Overflow / Memory Safety": [
        r"\bstrcpy\s*\(", r"\bstrcat\s*\(", r"\bgets\s*\(",
        r"\bsprintf\s*\(", r"\bmemcpy\s*\(", r"\bscanf\s*\(",
    ],
    "Format String": [
        r"\bprintf\s*\(\s*\w+\s*\)",     # printf(var) — no format literal
        r"\bfprintf\s*\(\w+,\s*\w+\)",   # fprintf(f, var)
        r"\bsyslog\s*\(\w+,\s*\w+\)",
    ],
    "SQL Injection": [
        r"['\"].*\+.*\w",                 # string concat near quotes
        r"\bexecute\s*\(.*\+",
        r"SELECT.*\+", r"INSERT.*\+", r"UPDATE.*\+", r"DELETE.*\+",
    ],
    "Arbitrary Code Execution": [
        r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\(",
    ],
    "Insecure Deserialization": [
        r"\bpickle\.loads?\b", r"\bunpickle\b", r"\byaml\.load\b",
        r"\bjson\.loads\b.*unsafe",
    ],
    "Use-After-Free / Memory Corruption": [
        r"\bfree\s*\(", r"\bdelete\s+", r"\bnullptr\b",
    ],
    "Integer Overflow": [
        r"\bmalloc\s*\(.*\+\s*1\)",      # malloc(count + 1) pattern
        r"\brealloc\s*\(", r"\bcalloc\s*\(",
    ],
    "Path Traversal": [
        r"\.\./", r"\bopen\s*\(.*\+",    # open with string concat
        r"\bos\.path\.join\b.*\+",
    ],
}


# ---------------------------------------------------------------------------
# Model loader (done once, reused for both files)
# ---------------------------------------------------------------------------

def load_model(model_dir: str):
    config = RobertaConfig.from_pretrained("microsoft/codebert-base")
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
    base_model = RobertaForSequenceClassification.from_pretrained(
        "microsoft/codebert-base", config=config
    )

    class Args:
        dropout_probability = 0.1
        block_size = 400

    model = Model(base_model, config, tokenizer, Args())
    model_path = f"{model_dir}/best_model.bin"
    model.load_state_dict(torch.load(model_path, map_location="cpu"))
    model.eval()
    return model, tokenizer, Args()


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def score_code(code: str, model, tokenizer, args) -> float:
    """Return vulnerability probability [0-1] for a code snippet."""
    code = re.sub(r"[ \t]+", " ", code)
    code = re.sub(r"\n\n+", "\n\n", code)
    code = code.strip()

    max_tokens = args.block_size - 2
    tokens = tokenizer.tokenize(code)[:max_tokens]
    source_tokens = [tokenizer.cls_token] + tokens + [tokenizer.sep_token]
    input_ids = torch.tensor([tokenizer.convert_tokens_to_ids(source_tokens)])

    with torch.no_grad():
        prob = model(input_ids)
    return prob.item()


def sliding_window_scores(lines: list, model, tokenizer, args, window: int) -> list:
    """
    Score every window of `window` consecutive lines.
    Returns one averaged score per line.
    """
    n = len(lines)
    line_scores = [0.0] * n
    line_counts = [0] * n

    for start in range(n):
        end = min(start + window, n)
        snippet = "\n".join(lines[start:end])
        if not snippet.strip():
            continue
        prob = score_code(snippet, model, tokenizer, args)
        for i in range(start, end):
            line_scores[i] += prob
            line_counts[i] += 1

    return [
        line_scores[i] / line_counts[i] if line_counts[i] > 0 else 0.0
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Pattern-based vulnerability classifier
# ---------------------------------------------------------------------------

def classify_line(line: str) -> list:
    """Return a list of vulnerability category names matched in the line."""
    matched = []
    for category, patterns in VULN_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, line, re.IGNORECASE):
                matched.append(category)
                break
    return matched


def classify_flagged_lines(lines: list, flagged_indices: list) -> dict:
    """
    Return {category: [line_numbers]} for all flagged lines.
    """
    categories = {}
    for idx in flagged_indices:
        for cat in classify_line(lines[idx]):
            categories.setdefault(cat, []).append(idx + 1)  # 1-based
    return categories


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def analyse_file(filepath: str, model, tokenizer, args, threshold: float, window: int):
    """
    Analyse a single file. Returns:
        (full_prob, flagged_line_indices, lines, category_map)
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    lines = code.splitlines()

    print(f"\n{'='*65}")
    print(f"File : {filepath}")
    print(f"Lines: {len(lines)}")
    print(f"{'='*65}")

    full_prob = score_code(code, model, tokenizer, args)
    verdict = "VULNERABLE" if full_prob > threshold else "NOT VULNERABLE"
    print(f"\nOverall probability : {full_prob:.4f}")
    print(f"Verdict             : {verdict}  (threshold={threshold})")

    if full_prob <= threshold:
        print("\nNo vulnerability detected — skipping line-level analysis.")
        return full_prob, [], lines, {}

    print(f"\nRunning sliding-window analysis (window={window} lines)...")
    scores = sliding_window_scores(lines, model, tokenizer, args, window)

    flag_threshold = max(threshold, full_prob * 0.60)
    flagged = [(i, s) for i, s in enumerate(scores) if s > flag_threshold]

    print(f"\n{'─'*65}")
    print(f"{'Line':>5}  {'Score':>7}  Code")
    print(f"{'─'*65}")

    for i, line in enumerate(lines):
        score = scores[i]
        marker = "  <-- VULN" if score > flag_threshold else ""
        print(f"{i+1:>5}  {score:.4f}  {line.rstrip()[:75]}{marker}")

    print(f"{'─'*65}")

    flagged_indices = [i for i, _ in flagged]

    if flagged:
        print(f"\nTop suspicious lines:")
        top = sorted(flagged, key=lambda x: x[1], reverse=True)[:5]
        for lineno, score in top:
            print(f"  Line {lineno+1:>4} (score={score:.4f}): {lines[lineno].strip()[:75]}")

        # Pattern-based classification
        category_map = classify_flagged_lines(lines, flagged_indices)
        if category_map:
            print(f"\nDetected vulnerability categories:")
            for cat, line_nums in category_map.items():
                print(f"  [{cat}]  at line(s): {line_nums}")
    else:
        print("\nNo individual lines exceeded the flag threshold.")
        category_map = {}

    return full_prob, flagged_indices, lines, category_map


# ---------------------------------------------------------------------------
# Similarity comparison
# ---------------------------------------------------------------------------

def compare_vulnerabilities(
    c_file: str, c_prob: float, c_categories: dict, c_lines: list, c_flagged: list,
    py_file: str, py_prob: float, py_categories: dict, py_lines: list, py_flagged: list,
):
    print(f"\n{'='*65}")
    print("SIMILARITY ANALYSIS")
    print(f"{'='*65}")

    # --- Score similarity ---
    diff = abs(c_prob - py_prob)
    score_sim = max(0.0, 1.0 - diff)
    print(f"\nVulnerability Score Comparison:")
    print(f"  C file   : {c_prob:.4f}  ({c_file})")
    print(f"  Python   : {py_prob:.4f}  ({py_file})")
    print(f"  Difference : {diff:.4f}  —  {'Similar severity' if diff < 0.15 else 'Different severity'}")

    # --- Shared vulnerability categories ---
    c_cats   = set(c_categories.keys())
    py_cats  = set(py_categories.keys())
    shared   = c_cats & py_cats
    c_only   = c_cats - py_cats
    py_only  = py_cats - c_cats

    print(f"\nVulnerability Category Overlap:")
    if shared:
        print(f"  Shared categories ({len(shared)}):")
        for cat in sorted(shared):
            c_ln  = c_categories[cat]
            py_ln = py_categories[cat]
            print(f"    [{cat}]")
            print(f"       C      → line(s) {c_ln}:  {c_lines[c_ln[0]-1].strip()[:60]}")
            print(f"       Python → line(s) {py_ln}:  {py_lines[py_ln[0]-1].strip()[:60]}")
    else:
        print("  No overlapping vulnerability categories detected.")

    if c_only:
        print(f"\n  Only in C file:")
        for cat in sorted(c_only):
            print(f"    [{cat}]  at line(s) {c_categories[cat]}")

    if py_only:
        print(f"\n  Only in Python file:")
        for cat in sorted(py_only):
            print(f"    [{cat}]  at line(s) {py_categories[cat]}")

    # --- Root-cause narrative ---
    print(f"\nSimilarity Summary:")
    if shared:
        cats_str = ", ".join(sorted(shared))
        print(f"  Both files share the same class(es) of vulnerability: {cats_str}.")
        print(f"  This typically means both suffer from the same root cause:")

        narratives = {
            "Command Injection":
                "    User-controlled input is passed directly to a shell/OS command\n"
                "    without sanitisation. In C via system(), in Python via os.system().",
            "Buffer Overflow / Memory Safety":
                "    Unbounded writes to fixed-size buffers (C) map to\n"
                "    unchecked input handling (Python).",
            "Format String":
                "    User input is used as a format string, allowing memory\n"
                "    reads/writes (C) or log injection (Python).",
            "SQL Injection":
                "    Query strings are built by concatenating user input instead\n"
                "    of using parameterised queries in both languages.",
            "Arbitrary Code Execution":
                "    User-supplied strings are executed as code via eval()/exec(),\n"
                "    enabling full remote code execution in both cases.",
            "Insecure Deserialization":
                "    Untrusted data is deserialized without validation,\n"
                "    allowing object injection / arbitrary code execution.",
            "Path Traversal":
                "    File paths are built by concatenating user input without\n"
                "    normalisation, allowing '../' sequences to escape the intended directory.",
            "Integer Overflow":
                "    Arithmetic on sizes before allocation can wrap,\n"
                "    causing under-allocation and subsequent out-of-bounds access.",
            "Use-After-Free / Memory Corruption":
                "    Memory is accessed after it has been freed/released,\n"
                "    leading to undefined behaviour or exploitable conditions.",
        }
        for cat in sorted(shared):
            if cat in narratives:
                print(f"\n  [{cat}]")
                print(narratives[cat])
    else:
        print("  The two files appear to have different classes of vulnerability.")
        print("  Review the per-file sections above for individual details.")

    print(f"\n{'='*65}")
    print("Analysis complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Locate and compare vulnerabilities in a C file and a Python file"
    )
    parser.add_argument("--c_file",    required=True, help="Path to the C source file")
    parser.add_argument("--py_file",   required=True, help="Path to the Python source file")
    parser.add_argument("--model_dir", required=True, help="Directory containing best_model.bin")
    parser.add_argument("--threshold", type=float, default=0.3,
                        help="Vulnerability probability threshold (default: 0.3)")
    parser.add_argument("--window",    type=int, default=5,
                        help="Sliding window size in lines (default: 5)")
    args = parser.parse_args()

    print("Loading model...")
    model, tokenizer, model_args = load_model(args.model_dir)
    print("Model loaded.")

    c_prob, c_flagged, c_lines, c_cats = analyse_file(
        args.c_file, model, tokenizer, model_args, args.threshold, args.window
    )
    py_prob, py_flagged, py_lines, py_cats = analyse_file(
        args.py_file, model, tokenizer, model_args, args.threshold, args.window
    )

    compare_vulnerabilities(
        args.c_file,  c_prob,  c_cats,  c_lines,  c_flagged,
        args.py_file, py_prob, py_cats, py_lines, py_flagged,
    )


if __name__ == "__main__":
    main()
