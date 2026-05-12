"""
test_attribution.py — Token-level attribution via occlusion.

For each token in the input, replaces it with the pad token and measures
how much the predicted vulnerability probability changes. Tokens that cause
the largest drop are the ones the model is relying on most to predict VULNERABLE.

Prints:
  - Baseline prediction and probability
  - Ranked list of the top-K most influential tokens
  - The token stream with colour coding:
      RED   = token strongly drives VULNERABLE prediction
      GREEN = token strongly drives SAFE prediction
      plain = token has little influence

Usage:
    python test_attribution.py --model_dir ./results/exp1_baseline
    python test_attribution.py --model_dir ./results/exp1_baseline --top_k 10
"""

import argparse
import json
import torch
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from model import Model

THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Test cases — key CWEs plus ablated / safe variants to show what changes
# ---------------------------------------------------------------------------

TEST_CASES = [
    {
        "name": "CWE-78 — Command Injection (C) [VULNERABLE]",
        "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}
""",
    },
    {
        "name": "CWE-78 — Hardcoded path, no user input (C) [SAFE]",
        "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls /safe/path");
    system(cmd);
}
""",
    },
    {
        "name": "CWE-327 — MD5 password hash (Python) [VULNERABLE]",
        "code": """
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
    },
    {
        "name": "CWE-327 — SHA256 password hash (Python) [SAFE]",
        "code": """
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
""",
    },
    {
        "name": "CWE-327 — md5 replaced with hash_fn (Python) [ABLATED — expect VULNERABLE]",
        "code": """
import hashlib
def hash_password(password):
    return hashlib.hash_fn(password.encode()).hexdigest()
""",
    },
    {
        "name": "CWE-89 — SQL Injection (Python) [VULNERABLE]",
        "code": """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
""",
    },
    {
        "name": "CWE-798 — Hardcoded credentials (Python) [VULNERABLE]",
        "code": """
def connect_db():
    password = "admin123"
    return connect("localhost", "admin", password)
""",
    },
    {
        "name": "CWE-416 — Use-After-Free (C) [VULNERABLE]",
        "code": """
void handle_request(Request *req) {
    free(req);
    log_request(req->method);
}
""",
    },
]

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RESET  = "\033[0m"

def colorize(token, score, hi=0.05, lo=0.02):
    clean = token.replace("Ġ", "")  # strip Roberta leading-space marker
    if score >= hi:
        return f"{RED}{clean}{RESET}"
    elif score >= lo:
        return f"{YELLOW}{clean}{RESET}"
    elif score <= -lo:
        return f"{GREEN}{clean}{RESET}"
    return clean

# ---------------------------------------------------------------------------
# Model loading (same as test_understanding.py)
# ---------------------------------------------------------------------------

def load_model(model_dir):
    config = RobertaConfig.from_pretrained("microsoft/unixcoder-base")
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained("microsoft/unixcoder-base")
    base_model = RobertaForSequenceClassification.from_pretrained(
        "microsoft/unixcoder-base", config=config
    )

    class Args:
        dropout_probability = 0.1
        block_size = 400
        label_smoothing = 0.0

    model = Model(base_model, config, tokenizer, Args())
    model_path = f"{model_dir}/best_model.bin"
    model.load_state_dict(torch.load(model_path, map_location="cpu"))
    model.eval()
    return model, tokenizer

# ---------------------------------------------------------------------------
# Occlusion attribution
# ---------------------------------------------------------------------------

def tokenize(tokenizer, code, block_size=400):
    tokens = tokenizer.tokenize(code)
    tokens = tokens[: block_size - 2]
    tokens = [tokenizer.cls_token] + tokens + [tokenizer.sep_token]
    ids = tokenizer.convert_tokens_to_ids(tokens)
    ids += [tokenizer.pad_token_id] * (block_size - len(ids))
    return tokens, ids


def predict_ids(model, ids):
    with torch.no_grad():
        return model(torch.tensor([ids])).item()


def attribute(model, tokenizer, code, block_size=400):
    tokens, ids = tokenize(tokenizer, code, block_size)
    baseline = predict_ids(model, ids)

    scores = []
    # Skip position 0 (CLS) and last real token (SEP)
    n_real = len([t for t in tokens])  # includes CLS and SEP
    for i in range(1, n_real - 1):
        ablated = ids.copy()
        ablated[i] = tokenizer.pad_token_id
        prob = predict_ids(model, ablated)
        scores.append({
            "token": tokens[i],
            "position": i,
            "score": round(baseline - prob, 4),  # positive = pushed toward VULNERABLE
        })

    scores.sort(key=lambda x: x["score"], reverse=True)
    return baseline, tokens, scores

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_case(name, code, model, tokenizer, top_k):
    print(f"\n{'='*65}")
    print(f"  {name}")
    print(f"{'='*65}")

    baseline, tokens, scores = attribute(model, tokenizer, code)
    label = "VULNERABLE" if baseline > THRESHOLD else "SAFE"
    colour = RED if label == "VULNERABLE" else GREEN
    print(f"\n  Prediction : {colour}{label}{RESET}  (p = {baseline:.4f})")

    # Ranked top-K
    print(f"\n  Top {top_k} tokens by influence on VULNERABLE prediction:")
    print(f"  {'#':<4} {'Token':<18} {'Score':>8}   Effect")
    print(f"  {'-'*55}")
    for rank, s in enumerate(scores[:top_k], 1):
        tok = s["token"].replace("Ġ", "")
        score = s["score"]
        if score > 0.02:
            effect = f"{RED}drives VULNERABLE{RESET}"
        elif score < -0.02:
            effect = f"{GREEN}drives SAFE{RESET}"
        else:
            effect = "neutral"
        print(f"  {rank:<4} {tok:<18} {score:>+.4f}   {effect}")

    # Colour-coded token stream
    score_by_pos = {s["position"]: s["score"] for s in scores}
    print(f"\n  Highlighted code  ({RED}RED{RESET}=drives vulnerable  "
          f"{GREEN}GREEN{RESET}=drives safe  {YELLOW}YELLOW{RESET}=mild):")
    print()

    # Reconstruct lines roughly by splitting on newline tokens
    line = "  "
    for i, tok in enumerate(tokens[1:], start=1):
        if tok in (tokenizer.sep_token, tokenizer.pad_token):
            break
        sc = score_by_pos.get(i, 0.0)
        clean = tok.replace("Ġ", " ").replace("Ċ", "\n  ")
        if "\n" in clean:
            parts = clean.split("\n")
            line += colorize(parts[0], sc)
            print(line)
            for p in parts[1:]:
                line = "  " + colorize(p, sc)
        else:
            line += colorize(clean, sc)
    if line.strip():
        print(line)
    print()

    return {
        "name": name,
        "prediction": label,
        "probability": round(baseline, 4),
        "top_tokens": scores[:top_k],
    }

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir", default="./results/exp1_baseline")
    parser.add_argument("--top_k", default=8, type=int,
                        help="Number of top tokens to show per case")
    parser.add_argument("--threshold", default=0.5, type=float)
    args = parser.parse_args()

    THRESHOLD = args.threshold

    print(f"Loading model from {args.model_dir} ...")
    model, tokenizer = load_model(args.model_dir)
    print("Model loaded. Running attribution...\n")
    print(f"Method: occlusion (replace token with [PAD], measure probability drop)")
    print(f"Score  = baseline_prob - ablated_prob")
    print(f"  Positive score → token pushes prediction toward VULNERABLE")
    print(f"  Negative score → token pushes prediction toward SAFE")

    all_results = []
    for case in TEST_CASES:
        result = print_case(case["name"], case["code"], model, tokenizer, args.top_k)
        all_results.append(result)

    with open("results/test_attribution_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull results saved to results/test_attribution_results.json")
