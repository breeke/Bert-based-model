"""
augment_with_real_data.py — Mix DiverseVul real-world samples into training data.

Takes the existing synthetic training file and adds real CVE-labelled functions
from sample_test.jsonl (DiverseVul subset). Outputs an augmented training file.

WARNING: Once sample_test.jsonl samples are included in training, Exp 3
real-world evaluation must use a different held-out real-world test set.
This script keeps 20% of real-world samples aside as a new real-world test split.

Usage:
    python augment_with_real_data.py \
        --train_file   ./Files/multi_lang_train.jsonl \
        --real_file    ./Files/sample_test.jsonl \
        --output_train ./Files/multi_lang_train_augmented.jsonl \
        --output_real_test ./Files/sample_test_holdout.jsonl \
        --real_ratio   0.8 \
        --seed         42
"""

import argparse
import json
import random


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def normalise_real_sample(s, idx):
    """Convert DiverseVul record to training format."""
    return {
        "func": s["func"],
        "target": s["target"],
        "idx": f"real_{idx}",
        "language": "c",          # DiverseVul is C/C++
        "cwe": s.get("cwe", []),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train_file",      default="./Files/multi_lang_train.jsonl")
    parser.add_argument("--real_file",       default="./Files/sample_test.jsonl")
    parser.add_argument("--output_train",    default="./Files/multi_lang_train_augmented.jsonl")
    parser.add_argument("--output_real_test",default="./Files/sample_test_holdout.jsonl")
    parser.add_argument("--real_ratio",      default=0.8, type=float,
                        help="Fraction of real samples to add to training (rest held out for testing)")
    parser.add_argument("--seed",            default=42, type=int)
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # Load
    train = load_jsonl(args.train_file)
    real  = load_jsonl(args.real_file)

    print(f"Synthetic training samples : {len(train)}")
    print(f"Real-world samples         : {len(real)}")

    vuln_real = sum(1 for s in real if s["target"] == 1)
    safe_real = sum(1 for s in real if s["target"] == 0)
    print(f"  Real vuln: {vuln_real}, Real safe: {safe_real}")

    # Split real data: train fraction vs held-out test
    rng.shuffle(real)
    split_idx = int(len(real) * args.real_ratio)
    real_train = real[:split_idx]
    real_test  = real[split_idx:]

    print(f"\nSplitting real data at {args.real_ratio:.0%}:")
    print(f"  Added to training : {len(real_train)}")
    print(f"  Kept for testing  : {len(real_test)}")

    # Normalise and merge
    real_train_norm = [normalise_real_sample(s, i) for i, s in enumerate(real_train)]
    augmented = train + real_train_norm
    rng.shuffle(augmented)

    # Stats
    vuln_aug = sum(1 for s in augmented if s["target"] == 1)
    safe_aug = sum(1 for s in augmented if s["target"] == 0)
    print(f"\nAugmented training set: {len(augmented)} total")
    print(f"  Vulnerable: {vuln_aug} ({vuln_aug/len(augmented)*100:.1f}%)")
    print(f"  Safe      : {safe_aug} ({safe_aug/len(augmented)*100:.1f}%)")

    # Write outputs
    write_jsonl(args.output_train, augmented)
    write_jsonl(args.output_real_test, real_test)

    print(f"\nWrote augmented training to : {args.output_train}")
    print(f"Wrote real-world test holdout: {args.output_real_test}")
    print("\nTo retrain with augmented data:")
    print(f"  python train.py --train_data_file {args.output_train} "
          f"--output_dir ./results/exp1_augmented "
          f"--eval_data_file ./Files/multi_lang_valid.jsonl "
          f"--do_train --do_eval --label_smoothing 0.1")
    print("\nTo evaluate real-world generalisation after retraining:")
    print(f"  python evaluate_experiments.py --mode realworld "
          f"--baseline_model ./results/exp1_augmented "
          f"--realworld_test {args.output_real_test}")


if __name__ == "__main__":
    main()
