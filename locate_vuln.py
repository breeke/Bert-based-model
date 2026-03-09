"""
locate_vuln.py — Run vulnerability detection on a C file and a Python file,
then pinpoint WHICH lines are most likely vulnerable using a sliding window.

Usage:
    python locate_vuln.py --c_file path/to/file.c --py_file path/to/file.py --model_dir ./saved_models
    python locate_vuln.py --c_file path/to/file.c --py_file path/to/file.py --model_dir ./saved_models --threshold 0.4 --window 5
"""

import argparse
import torch
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from model import Model


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
    import re
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


def sliding_window_scores(lines: list[str], model, tokenizer, args, window: int) -> list[float]:
    """
    Score every window of `window` consecutive lines.
    Returns one score per line (average of all windows that include it).
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

    # Average
    averaged = [
        line_scores[i] / line_counts[i] if line_counts[i] > 0 else 0.0
        for i in range(n)
    ]
    return averaged


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

def analyse_file(filepath: str, model, tokenizer, args, threshold: float, window: int):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()

    lines = code.splitlines()

    print(f"\n{'='*65}")
    print(f"File : {filepath}")
    print(f"Lines: {len(lines)}")
    print(f"{'='*65}")

    # --- Full-file score ---
    full_prob = score_code(code, model, tokenizer, args)
    verdict = "VULNERABLE" if full_prob > threshold else "NOT VULNERABLE"
    print(f"\nOverall probability : {full_prob:.4f}")
    print(f"Verdict             : {verdict}  (threshold={threshold})")

    if full_prob <= threshold:
        print("\nNo vulnerability detected — skipping line-level analysis.")
        return

    # --- Line-level sliding window ---
    print(f"\nRunning sliding-window analysis (window={window} lines)...")
    scores = sliding_window_scores(lines, model, tokenizer, args, window)

    # Determine a local threshold: lines whose score exceeds 60 % of the
    # full-file score are flagged.
    flag_threshold = max(threshold, full_prob * 0.60)

    flagged = [(i, s) for i, s in enumerate(scores) if s > flag_threshold]

    print(f"\n{'─'*65}")
    print(f"{'Line':>5}  {'Score':>7}  Code")
    print(f"{'─'*65}")

    for i, line in enumerate(lines):
        score = scores[i]
        is_flagged = score > flag_threshold
        marker = "  <-- VULN" if is_flagged else ""
        bar = f"{score:.4f}"
        display = line.rstrip()[:80]  # truncate long lines for display
        print(f"{i+1:>5}  {bar:>7}  {display}{marker}")

    print(f"{'─'*65}")

    if flagged:
        print(f"\nTop suspicious lines:")
        top = sorted(flagged, key=lambda x: x[1], reverse=True)[:5]
        for lineno, score in top:
            print(f"  Line {lineno+1:>4} (score={score:.4f}): {lines[lineno].strip()[:80]}")
    else:
        print("\nNo individual lines exceeded the flag threshold.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Locate vulnerabilities in a C file and a Python file"
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
    print("Model loaded.\n")

    for filepath in [args.c_file, args.py_file]:
        analyse_file(filepath, model, tokenizer, model_args, args.threshold, args.window)

    print(f"\n{'='*65}")
    print("Analysis complete.")


if __name__ == "__main__":
    main()
