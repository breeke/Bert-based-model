"""
test_understanding.py — Tests whether the model understands vulnerability semantics
or is simply pattern-matching on surface tokens.

Four tests:
  1. Semantic-preserving transformations (variable renaming) — prediction should stay the same
  2. Minimal fix test — prediction should flip from vulnerable to safe
  3. Dead code injection — prediction should stay safe (unreachable vulnerable code)
  4. Key token ablation — tests whether prediction relies on a single keyword

Usage:
    python test_understanding.py --model_dir ./results/exp1_baseline
"""

import argparse
import torch
import json
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from model import Model

THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

TEST_CASES = {

    # -----------------------------------------------------------------------
    # TEST 1 — Semantic-preserving transformations
    # Rename variables/functions. Vulnerability logic unchanged.
    # Expected: prediction stays VULNERABLE for both original and renamed.
    # If prediction flips → model was matching variable names, not the pattern.
    # -----------------------------------------------------------------------
    "test1_rename": [
        {
            "name": "CWE-78 C — original (system + user input)",
            "language": "c",
            "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-78 C — renamed variables (same logic)",
            "language": "c",
            "code": """
void execute_action(char *data) {
    char buffer[256];
    sprintf(buffer, "ls %s", data);
    system(buffer);
}
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-327 Python — original (md5)",
            "language": "python",
            "code": """
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-327 Python — renamed variables (same logic)",
            "language": "python",
            "code": """
import hashlib
def compute_digest(data):
    return hashlib.md5(data.encode()).hexdigest()
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-89 Python — original (SQL injection)",
            "language": "python",
            "code": """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-89 Python — renamed variables (same logic)",
            "language": "python",
            "code": """
def fetch_record(name):
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(sql)
""",
            "expected": "VULNERABLE",
        },
    ],

    # -----------------------------------------------------------------------
    # TEST 2 — Minimal fix test
    # Apply only the exact patch that removes the vulnerability.
    # Expected: prediction flips from VULNERABLE to SAFE.
    # If prediction stays VULNERABLE → model did not learn what made it vulnerable.
    # -----------------------------------------------------------------------
    "test2_minimal_fix": [
        {
            "name": "CWE-327 Python — VULNERABLE (md5)",
            "language": "python",
            "code": """
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-327 Python — FIXED (sha256 only change)",
            "language": "python",
            "code": """
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-798 Python — VULNERABLE (hardcoded password)",
            "language": "python",
            "code": """
def connect_db():
    password = "admin123"
    return connect("localhost", "admin", password)
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-798 Python — FIXED (env var only change)",
            "language": "python",
            "code": """
import os
def connect_db():
    password = os.getenv("DB_PASSWORD")
    return connect("localhost", "admin", password)
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-89 Python — VULNERABLE (string concat query)",
            "language": "python",
            "code": """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-89 Python — FIXED (parameterized query only change)",
            "language": "python",
            "code": """
def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (username,))
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-78 C — VULNERABLE (system + user input)",
            "language": "c",
            "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-78 C — FIXED (hardcoded path only change)",
            "language": "c",
            "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls /safe/path");
    system(cmd);
}
""",
            "expected": "SAFE",
        },
    ],

    # -----------------------------------------------------------------------
    # TEST 3 — Dead code injection
    # A safe function with a vulnerable block that never executes (if 0).
    # Expected: prediction stays SAFE — the code cannot actually run.
    # If prediction flips to VULNERABLE → model matched tokens without
    # understanding control flow.
    # -----------------------------------------------------------------------
    "test3_dead_code": [
        {
            "name": "CWE-78 C — SAFE function (no vulnerability)",
            "language": "c",
            "code": """
void safe_logger(char *message) {
    printf("Log: %s\\n", message);
}
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-78 C — SAFE function + dead system() call (if 0)",
            "language": "c",
            "code": """
void safe_logger(char *message) {
    printf("Log: %s\\n", message);
    if (0) {
        system(message);
    }
}
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-327 Python — SAFE function (no hashing)",
            "language": "python",
            "code": """
def greet_user(name):
    return "Hello, " + name
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-327 Python — SAFE function + dead md5 block (if False)",
            "language": "python",
            "code": """
import hashlib
def greet_user(name):
    if False:
        hashlib.md5(name.encode()).hexdigest()
    return "Hello, " + name
""",
            "expected": "SAFE",
        },
        {
            "name": "CWE-798 Python — SAFE function + dead hardcoded password (if False)",
            "language": "python",
            "code": """
def connect_db():
    if False:
        password = "admin123"
    password = os.getenv("DB_PASSWORD")
    return connect("localhost", "admin", password)
""",
            "expected": "SAFE",
        },
    ],

    # -----------------------------------------------------------------------
    # TEST 4 — Key token ablation
    # Replace the single token that signals the vulnerability with a neutral name.
    # Expected: if the model understands context, prediction stays VULNERABLE
    # because the surrounding logic is still dangerous.
    # If prediction flips to SAFE → model relied only on that one token.
    # -----------------------------------------------------------------------
    "test4_token_ablation": [
        {
            "name": "CWE-78 C — original (system keyword present)",
            "language": "c",
            "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    system(cmd);
}
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-78 C — system replaced with safe_exec (ablated)",
            "language": "c",
            "code": """
void run_command(char *user_input) {
    char cmd[256];
    sprintf(cmd, "ls %s", user_input);
    safe_exec(cmd);
}
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-327 Python — original (md5 keyword present)",
            "language": "python",
            "code": """
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-327 Python — md5 replaced with hash_fn (ablated)",
            "language": "python",
            "code": """
import hashlib
def hash_password(password):
    return hashlib.hash_fn(password.encode()).hexdigest()
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-798 Python — original (hardcoded string present)",
            "language": "python",
            "code": """
def connect_db():
    password = "admin123"
    return connect("localhost", "admin", password)
""",
            "expected": "VULNERABLE",
        },
        {
            "name": "CWE-798 Python — credential string replaced with variable (ablated)",
            "language": "python",
            "code": """
def connect_db():
    password = get_credential()
    return connect("localhost", "admin", password)
""",
            "expected": "VULNERABLE",
        },
    ],
}


# ---------------------------------------------------------------------------
# Model loading
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


def predict(model, tokenizer, code, block_size=400):
    tokens = tokenizer.tokenize(code)
    tokens = tokens[: block_size - 2]
    tokens = [tokenizer.cls_token] + tokens + [tokenizer.sep_token]
    input_ids = tokenizer.convert_tokens_to_ids(tokens)
    padding = block_size - len(input_ids)
    input_ids += [tokenizer.pad_token_id] * padding
    input_tensor = torch.tensor([input_ids])
    with torch.no_grad():
        prob = model(input_tensor).item()
    label = "VULNERABLE" if prob > THRESHOLD else "SAFE"
    return prob, label


# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

def run_tests(model, tokenizer):
    all_results = {}
    summary = {"total": 0, "passed": 0, "failed": 0}

    for test_name, cases in TEST_CASES.items():
        print(f"\n{'='*60}")
        print(f"  {test_name.upper()}")
        print(f"{'='*60}")
        results = []

        for case in cases:
            prob, label = predict(model, tokenizer, case["code"])
            passed = label == case["expected"]
            status = "PASS" if passed else "FAIL"
            summary["total"] += 1
            if passed:
                summary["passed"] += 1
            else:
                summary["failed"] += 1

            print(f"  [{status}] {case['name']}")
            print(f"         prob={prob:.4f}  predicted={label}  expected={case['expected']}")

            results.append({
                "name": case["name"],
                "prob": round(prob, 4),
                "predicted": label,
                "expected": case["expected"],
                "passed": passed,
            })

        all_results[test_name] = results

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total : {summary['total']}")
    print(f"  Passed: {summary['passed']}")
    print(f"  Failed: {summary['failed']}")

    # Interpretation
    print(f"\n{'='*60}")
    print("  INTERPRETATION")
    print(f"{'='*60}")

    t1 = all_results["test1_rename"]
    flipped_rename = [r for r in t1 if not r["passed"]]
    print(f"\nTest 1 (Variable renaming): {len(flipped_rename)} predictions changed")
    if flipped_rename:
        print("  -> Model is sensitive to variable names (surface pattern matching)")
    else:
        print("  -> Model is robust to renaming (good sign for understanding)")

    t2 = all_results["test2_minimal_fix"]
    pairs = [(t2[i], t2[i+1]) for i in range(0, len(t2)-1, 2)]
    fix_flipped = sum(1 for vuln, fixed in pairs if vuln["predicted"] == "VULNERABLE" and fixed["predicted"] == "SAFE")
    print(f"\nTest 2 (Minimal fix): {fix_flipped}/{len(pairs)} pairs correctly flipped after fix")
    if fix_flipped == len(pairs):
        print("  -> Model detects the specific fix — strong understanding of vulnerability cause")
    elif fix_flipped == 0:
        print("  -> Model ignores the fix — relying on surrounding code structure, not the flaw itself")
    else:
        print("  -> Partial understanding — some fixes recognised, others not")

    t3 = all_results["test3_dead_code"]
    pairs3 = [(t3[i], t3[i+1]) for i in range(0, len(t3)-1, 2)]
    dead_fooled = sum(1 for safe, dead in pairs3 if safe["predicted"] == "SAFE" and dead["predicted"] == "VULNERABLE")
    print(f"\nTest 3 (Dead code): {dead_fooled}/{len(pairs3)} cases fooled by unreachable vulnerable tokens")
    if dead_fooled == len(pairs3):
        print("  -> Model cannot reason about control flow — pure token matching")
    elif dead_fooled == 0:
        print("  -> Model ignores dead code — some control flow awareness")
    else:
        print("  -> Mixed — some vulnerability tokens trigger prediction even when unreachable")

    t4 = all_results["test4_token_ablation"]
    pairs4 = [(t4[i], t4[i+1]) for i in range(0, len(t4)-1, 2)]
    ablation_flipped = sum(1 for orig, ablated in pairs4 if orig["predicted"] == "VULNERABLE" and ablated["predicted"] == "SAFE")
    print(f"\nTest 4 (Token ablation): {ablation_flipped}/{len(pairs4)} predictions dropped when key token removed")
    if ablation_flipped == len(pairs4):
        print("  -> Model heavily relies on specific keywords (system, md5, etc.) — keyword matching")
    elif ablation_flipped == 0:
        print("  -> Model detects vulnerability from context even without the keyword — good understanding")
    else:
        print("  -> Mixed — some CWEs rely on keywords, others understood from context")

    # Save results
    with open("results/test_understanding_results.json", "w") as f:
        json.dump({"summary": summary, "results": all_results}, f, indent=2)
    print(f"\nFull results saved to results/test_understanding_results.json")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir", default="./results/exp1_baseline",
                        help="Path to trained model directory")
    parser.add_argument("--threshold", default=0.5, type=float,
                        help="Decision threshold")
    args = parser.parse_args()

    THRESHOLD = args.threshold

    print(f"Loading model from {args.model_dir} ...")
    model, tokenizer = load_model(args.model_dir)
    print("Model loaded. Running tests...\n")

    run_tests(model, tokenizer)
