"""
test_samples.py — Generate sample C and Python vulnerable/safe code files
and run predict.py on each to verify the model's predictions.

Usage:
    python test_samples.py --model_dir ./saved_model
"""

import os
import argparse
import tempfile
from predict import predict_vulnerability

# ---------------------------------------------------------------------------
# Sample snippets
# ---------------------------------------------------------------------------

SAMPLES = {
    # --- C samples ---
    "c_vuln_buffer_overflow": {
        "lang": "c",
        "expected": "VULNERABLE",
        "code": """\
#include <string.h>
void copy_input(char *user_input) {
    char buf[64];
    strcpy(buf, user_input);   /* no bounds check — classic buffer overflow */
}
""",
    },
    "c_vuln_format_string": {
        "lang": "c",
        "expected": "VULNERABLE",
        "code": """\
#include <stdio.h>
void log_msg(char *msg) {
    printf(msg);   /* user-controlled format string */
}
""",
    },
    "c_vuln_use_after_free": {
        "lang": "c",
        "expected": "VULNERABLE",
        "code": """\
#include <stdlib.h>
void process() {
    int *ptr = (int *)malloc(sizeof(int));
    free(ptr);
    *ptr = 42;   /* use-after-free */
}
""",
    },
    "c_safe_bounded_copy": {
        "lang": "c",
        "expected": "NOT VULNERABLE",
        "code": """\
#include <string.h>
void copy_input(char *user_input) {
    char buf[64];
    strncpy(buf, user_input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
}
""",
    },

    # --- Python samples ---
    "py_vuln_command_injection": {
        "lang": "python",
        "expected": "VULNERABLE",
        "code": """\
import os

def run_command(user_input):
    os.system("ls " + user_input)   # unsanitised shell command
""",
    },
    "py_vuln_sql_injection": {
        "lang": "python",
        "expected": "VULNERABLE",
        "code": """\
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")  # SQLi
    return cur.fetchall()
""",
    },
    "py_vuln_eval": {
        "lang": "python",
        "expected": "VULNERABLE",
        "code": """\
def calculate(expr):
    return eval(expr)   # arbitrary code execution via eval
""",
    },
    "py_safe_parameterised_query": {
        "lang": "python",
        "expected": "NOT VULNERABLE",
        "code": """\
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchall()
""",
    },
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all(model_dir: str, threshold: float = 0.3):
    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        for name, sample in SAMPLES.items():
            ext = "c" if sample["lang"] == "c" else "py"
            fpath = os.path.join(tmpdir, f"{name}.{ext}")

            with open(fpath, "w") as f:
                f.write(sample["code"])

            print(f"\n{'='*60}")
            print(f"Sample : {name}")
            print(f"Expected: {sample['expected']}")

            prediction, prob = predict_vulnerability(fpath, model_dir, threshold)
            predicted_label = "VULNERABLE" if prediction else "NOT VULNERABLE"
            correct = predicted_label == sample["expected"]

            results.append({
                "name": name,
                "expected": sample["expected"],
                "predicted": predicted_label,
                "prob": prob,
                "correct": correct,
            })
            print(f"Result  : {'PASS' if correct else 'FAIL'}")

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    passed = sum(1 for r in results if r["correct"])
    for r in results:
        status = "PASS" if r["correct"] else "FAIL"
        print(f"[{status}] {r['name']:40s} prob={r['prob']:.4f}  "
              f"expected={r['expected']}  got={r['predicted']}")
    print(f"\n{passed}/{len(results)} tests passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test predict.py with C/Python vulnerability samples")
    parser.add_argument("--model_dir", required=True, help="Path to trained model directory")
    parser.add_argument("--threshold", type=float, default=0.3,
                        help="Vulnerability probability threshold (default: 0.3)")
    args = parser.parse_args()

    run_all(args.model_dir, args.threshold)
