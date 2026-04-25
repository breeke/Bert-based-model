"""
analyse_insights.py
===================
Deeper analysis script for dissertation insights.

Covers questions evaluate_experiments.py does NOT answer:

  1. Syntax vs Semantics test
       - Per-CWE transfer: shared CWEs across C-only / Python-only / Joint models
       - Did joint training help shared CWEs more than language-specific ones?

  2. Real-world error analysis
       - FP vs FN ratio on DiverseVul
       - Which real-world CWEs are being missed vs falsely flagged
       - Function length vs correctness (does the model fail on longer functions?)

  3. Probability calibration
       - Are model outputs spread across 0-1 or clustered at extremes?
       - Separate histograms for TP / TN / FP / FN

  4. Held-out vs real-world gap per CWE
       - Which CWEs transfer from synthetic held-out to real-world?
       - Which CWEs collapse entirely on real data?

  5. Cross-language transfer per shared CWE
       - For each of the 8 shared CWEs, compare recall:
         C-only model | Python-only model | Joint model

Usage:
    python analyse_insights.py

    # Individual analyses:
    python analyse_insights.py --mode syntax_vs_semantics
    python analyse_insights.py --mode error_analysis
    python analyse_insights.py --mode calibration
    python analyse_insights.py --mode gap_per_cwe
    python analyse_insights.py --mode all

Output: ./results/insights/
"""

import argparse
import json
import os
import re
import numpy as np
import torch
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from torch.utils.data import DataLoader, SequentialSampler
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from sklearn.metrics import (
    recall_score, precision_score, f1_score, confusion_matrix
)
from collections import defaultdict, Counter
import logging

from dataset import TextDataset, collate_fn_dynamic_padding
from model import Model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OUT_DIR = "./results/insights"

SHARED_CWES = ["CWE-89", "CWE-78", "CWE-22", "CWE-134",
               "CWE-327", "CWE-367", "CWE-732", "CWE-798"]


# ═══════════════════════════════════════════════════════════════════════════════
# Model / inference helpers
# ═══════════════════════════════════════════════════════════════════════════════

def load_model(model_dir, device, model_name="microsoft/unixcoder-base"):
    config    = RobertaConfig.from_pretrained(model_name)
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    base      = RobertaForSequenceClassification.from_pretrained(model_name, config=config)

    class _A:
        block_size          = 400
        dropout_probability = 0.1

    model = Model(base, config, tokenizer, _A())
    path  = os.path.join(model_dir, "best_model.bin")
    if not os.path.exists(path):
        raise FileNotFoundError(f"No best_model.bin in {model_dir}")
    model.load_state_dict(torch.load(path, map_location=device))
    model.to(device)
    model.eval()
    return model, tokenizer


def infer(model, tokenizer, data_file, device):
    """Returns (probs, labels, metadata) — metadata loaded directly from jsonl."""
    class _A:
        block_size          = 400
        dropout_probability = 0.1

    dataset = TextDataset(tokenizer, _A(), data_file)
    loader  = DataLoader(dataset, sampler=SequentialSampler(dataset),
                         batch_size=16, collate_fn=collate_fn_dynamic_padding)

    probs, labels = [], []
    with torch.no_grad():
        for batch in loader:
            inp = batch[0].to(device)
            lbl = batch[1].to(device)
            _, logits = model(inp, lbl)
            probs.extend(logits.cpu().numpy().flatten().tolist())
            labels.extend(lbl.cpu().numpy().tolist())

    # Load metadata directly from file (guaranteed to match dataset order)
    meta = []
    with open(data_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if "func" not in d or "target" not in d or not d["func"].strip():
                    continue
                meta.append({
                    "cwe":      d.get("cwe", []),
                    "language": d.get("language", "unknown"),
                    "func":     d["func"],
                })
            except Exception:
                continue

    return np.array(probs), np.array(labels), meta


def classify(probs, threshold=0.5):
    return (probs >= threshold).astype(int)


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  SYNTAX VS SEMANTICS
# ═══════════════════════════════════════════════════════════════════════════════

def run_syntax_vs_semantics(args, device):
    logger.info("\n" + "="*60)
    logger.info("INSIGHT 1: Syntax vs Semantics — Per-CWE Transfer")
    logger.info("="*60)

    model_configs = {
        "C-only":      args.c_only_model,
        "Python-only": args.python_only_model,
        "Joint":       args.baseline_model,
    }
    test_files = {
        "c":     args.c_only_test,
        "python":args.python_only_test,
    }

    # cwe_transfer[cwe][model_name][test_lang] = recall
    cwe_transfer = defaultdict(lambda: defaultdict(dict))

    for model_name, model_dir in model_configs.items():
        if not os.path.exists(os.path.join(model_dir, "best_model.bin")):
            logger.warning(f"Skipping {model_name} — model not found")
            continue
        model, tokenizer = load_model(model_dir, device)

        for lang, test_file in test_files.items():
            if not os.path.exists(test_file):
                continue
            probs, labels, meta = infer(model, tokenizer, test_file, device)
            preds = classify(probs)

            # Per-CWE recall
            cwe_data = defaultdict(lambda: {"preds": [], "labels": []})
            for i, m in enumerate(meta):
                for cwe in (m["cwe"] if isinstance(m["cwe"], list) else []):
                    if cwe:
                        cwe_data[cwe]["preds"].append(int(preds[i]))
                        cwe_data[cwe]["labels"].append(int(labels[i]))

            for cwe, data in cwe_data.items():
                if data["labels"]:
                    cwe_transfer[cwe][model_name][lang] = recall_score(
                        data["labels"], data["preds"], zero_division=0)

        del model

    # ── Plot: shared CWE recall heatmap per model ────────────────────────────
    shared = [c for c in SHARED_CWES if c in cwe_transfer]
    models = [m for m in ["C-only", "Python-only", "Joint"] if m in list(model_configs.keys())]
    langs  = ["c", "python"]

    for lang in langs:
        data_matrix = []
        row_labels  = []
        for cwe in shared:
            row = []
            for m in models:
                row.append(cwe_transfer[cwe].get(m, {}).get(lang, 0.0))
            data_matrix.append(row)
            row_labels.append(cwe)

        if not data_matrix:
            continue

        fig, ax = plt.subplots(figsize=(7, max(4, len(shared) * 0.5)))
        mat = np.array(data_matrix)
        im  = ax.imshow(mat, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
        plt.colorbar(im, ax=ax, label="Recall")
        ax.set_xticks(range(len(models)))
        ax.set_yticks(range(len(row_labels)))
        ax.set_xticklabels(models)
        ax.set_yticklabels(row_labels)
        ax.set_title(f"Per-CWE Recall on {lang.upper()} test set\n(shared CWEs only)")
        ax.set_xlabel("Training Data")
        ax.set_ylabel("CWE")
        for i in range(len(row_labels)):
            for j in range(len(models)):
                ax.text(j, i, f"{mat[i,j]:.2f}", ha="center", va="center",
                        fontsize=9,
                        color="black" if mat[i,j] < 0.8 else "white")
        plt.tight_layout()
        save = os.path.join(OUT_DIR, f"insight1_cwe_transfer_{lang}.png")
        plt.savefig(save, dpi=150)
        plt.close()
        logger.info(f"Saved: {save}")

    # ── Shared vs language-specific CWE transfer comparison ─────────────────
    # For the Joint model: compare avg recall on shared CWEs vs non-shared CWEs
    joint_dir = args.baseline_model
    if os.path.exists(os.path.join(joint_dir, "best_model.bin")):
        model, tokenizer = load_model(joint_dir, device)
        probs, labels, meta = infer(model, tokenizer, args.test_data, device)
        preds = classify(probs)
        del model

        shared_recalls, specific_recalls = [], []
        cwe_data = defaultdict(lambda: {"preds": [], "labels": []})
        for i, m in enumerate(meta):
            for cwe in (m["cwe"] if isinstance(m["cwe"], list) else []):
                if cwe:
                    cwe_data[cwe]["preds"].append(int(preds[i]))
                    cwe_data[cwe]["labels"].append(int(labels[i]))

        for cwe, data in cwe_data.items():
            if not data["labels"]:
                continue
            r = recall_score(data["labels"], data["preds"], zero_division=0)
            if cwe in SHARED_CWES:
                shared_recalls.append((cwe, r))
            else:
                specific_recalls.append((cwe, r))

        logger.info("\nJoint model — Shared CWE recall:")
        for cwe, r in sorted(shared_recalls, key=lambda x: x[1], reverse=True):
            logger.info(f"  {cwe:<12} {r:.3f}")
        logger.info("\nJoint model — Language-specific CWE recall:")
        for cwe, r in sorted(specific_recalls, key=lambda x: x[1], reverse=True):
            logger.info(f"  {cwe:<12} {r:.3f}")

        if shared_recalls and specific_recalls:
            avg_shared   = np.mean([r for _, r in shared_recalls])
            avg_specific = np.mean([r for _, r in specific_recalls])
            logger.info(f"\nAvg shared CWE recall   : {avg_shared:.3f}")
            logger.info(f"Avg specific CWE recall : {avg_specific:.3f}")
            if avg_shared > avg_specific:
                logger.info("  → Model generalises BETTER on shared CWEs (semantic learning signal)")
            else:
                logger.info("  → Model generalises BETTER on specific CWEs (syntax memorisation signal)")

        # Save to JSON
        _save_json({
            "shared_cwe_recall":   dict(shared_recalls),
            "specific_cwe_recall": dict(specific_recalls),
            "avg_shared":   float(np.mean([r for _, r in shared_recalls])) if shared_recalls else 0,
            "avg_specific": float(np.mean([r for _, r in specific_recalls])) if specific_recalls else 0,
            "cwe_transfer": {cwe: {m: dict(langs) for m, langs in models.items()}
                             for cwe, models in cwe_transfer.items()},
        }, "insight1_syntax_vs_semantics.json")


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  REAL-WORLD ERROR ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def run_error_analysis(args, device):
    logger.info("\n" + "="*60)
    logger.info("INSIGHT 2: Real-World Error Analysis")
    logger.info("="*60)

    model, tokenizer = load_model(args.baseline_model, device)
    probs, labels, meta = infer(model, tokenizer, args.realworld_test, device)
    del model
    preds = classify(probs)

    tn, fp, fn, tp = confusion_matrix(labels, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    logger.info(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    logger.info(f"False Positive Rate (safe flagged as vuln) : {fpr:.3f}")
    logger.info(f"False Negative Rate (vuln missed)          : {fnr:.3f}")
    if fnr > fpr:
        logger.info("  → Model tends to MISS vulnerabilities more than it false-alarms")
    else:
        logger.info("  → Model tends to FALSE-ALARM more than it misses vulnerabilities")

    # ── Which CWEs are being missed (FN) vs falsely flagged (FP) ─────────────
    fn_cwes = Counter()
    fp_cwes = Counter()
    for i, m in enumerate(meta):
        cwes = m["cwe"] if isinstance(m["cwe"], list) else []
        if labels[i] == 1 and preds[i] == 0:   # missed vulnerability
            for c in cwes:
                if c: fn_cwes[c] += 1
        elif labels[i] == 0 and preds[i] == 1: # false alarm
            for c in cwes:
                if c: fp_cwes[c] += 1

    logger.info("\nTop missed CWEs (false negatives):")
    for cwe, count in fn_cwes.most_common(10):
        logger.info(f"  {cwe:<12} missed {count} times")

    logger.info("\nTop falsely flagged CWEs (false positives — safe samples):")
    for cwe, count in fp_cwes.most_common(5):
        logger.info(f"  {cwe:<12} false-alarmed {count} times")

    # ── Function length vs correctness ────────────────────────────────────────
    length_buckets = {"short (1-30)": [], "medium (31-80)": [], "long (81+)": []}
    for i, m in enumerate(meta):
        nlines = len(m["func"].split("\n"))
        if nlines <= 30:
            bucket = "short (1-30)"
        elif nlines <= 80:
            bucket = "medium (31-80)"
        else:
            bucket = "long (81+)"
        correct = int(preds[i] == labels[i])
        length_buckets[bucket].append(correct)

    logger.info("\nAccuracy by function length (real-world data):")
    bucket_accs = {}
    for bucket, results in length_buckets.items():
        if results:
            acc = np.mean(results)
            bucket_accs[bucket] = acc
            logger.info(f"  {bucket:<18} acc={acc:.3f}  n={len(results)}")

    # ── Plot: length vs accuracy bar chart ────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 4))
    buckets = list(bucket_accs.keys())
    accs    = [bucket_accs[b] for b in buckets]
    colors  = ["#2ecc71" if a >= 0.6 else "#e74c3c" for a in accs]
    bars = ax.bar(buckets, accs, color=colors, edgecolor="white")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Accuracy")
    ax.set_title("Real-World Accuracy by Function Length")
    ax.axhline(0.5, color="gray", linestyle="--", alpha=0.5, label="random baseline")
    for bar, acc in zip(bars, accs):
        ax.text(bar.get_x() + bar.get_width()/2, acc + 0.02,
                f"{acc:.2f}", ha="center", fontsize=10)
    ax.legend()
    plt.tight_layout()
    save = os.path.join(OUT_DIR, "insight2_length_vs_accuracy.png")
    plt.savefig(save, dpi=150)
    plt.close()
    logger.info(f"\nSaved: {save}")

    # ── Plot: FN CWEs bar chart ───────────────────────────────────────────────
    if fn_cwes:
        top_fn = fn_cwes.most_common(12)
        cwes_  = [c for c, _ in top_fn]
        counts = [n for _, n in top_fn]
        colors = ["#e74c3c" if c in SHARED_CWES else "#e67e22" for c in cwes_]
        fig, ax = plt.subplots(figsize=(8, max(4, len(cwes_) * 0.4)))
        ax.barh(cwes_, counts, color=colors)
        ax.set_xlabel("Times Missed (False Negatives)")
        ax.set_title("Real-World: Most-Missed CWE Types")
        from matplotlib.patches import Patch
        ax.legend(handles=[Patch(color="#e74c3c", label="Shared CWE"),
                           Patch(color="#e67e22", label="C-only CWE")],
                  loc="lower right", fontsize=8)
        plt.tight_layout()
        save = os.path.join(OUT_DIR, "insight2_missed_cwes.png")
        plt.savefig(save, dpi=150, bbox_inches="tight")
        plt.close()
        logger.info(f"Saved: {save}")

    _save_json({
        "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
                      "fpr": float(fpr), "fnr": float(fnr)},
        "missed_cwes":    dict(fn_cwes.most_common()),
        "fp_cwes":        dict(fp_cwes.most_common()),
        "length_accuracy": bucket_accs,
    }, "insight2_error_analysis.json")


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  PROBABILITY CALIBRATION
# ═══════════════════════════════════════════════════════════════════════════════

def run_calibration(args, device):
    logger.info("\n" + "="*60)
    logger.info("INSIGHT 3: Probability Calibration")
    logger.info("="*60)

    model, tokenizer = load_model(args.baseline_model, device)

    for label, data_file in [("Synthetic", args.test_data),
                              ("Real-world", args.realworld_test)]:
        probs, labels, _ = infer(model, tokenizer, data_file, device)
        preds = classify(probs)

        # Split probs by outcome
        tp_probs = probs[(labels == 1) & (preds == 1)]
        tn_probs = probs[(labels == 0) & (preds == 0)]
        fp_probs = probs[(labels == 0) & (preds == 1)]
        fn_probs = probs[(labels == 1) & (preds == 0)]

        logger.info(f"\n{label} — probability distributions:")
        for name, p in [("TP", tp_probs), ("TN", tn_probs),
                        ("FP", fp_probs), ("FN", fn_probs)]:
            if len(p):
                logger.info(f"  {name}: mean={np.mean(p):.3f}  "
                            f"std={np.std(p):.3f}  n={len(p)}")

        # Plot
        fig, axes = plt.subplots(2, 2, figsize=(9, 6), sharey=False)
        fig.suptitle(f"Probability Distribution by Outcome ({label})")
        for ax, (name, p, col) in zip(axes.flatten(),
            [("True Positives (TP)",  tp_probs, "#2ecc71"),
             ("True Negatives (TN)",  tn_probs, "#3498db"),
             ("False Positives (FP)", fp_probs, "#e67e22"),
             ("False Negatives (FN)", fn_probs, "#e74c3c")]):
            if len(p):
                ax.hist(p, bins=20, range=(0, 1), color=col, edgecolor="white")
                ax.axvline(0.5, color="black", linestyle="--", alpha=0.5)
                ax.set_title(f"{name} (n={len(p)})")
                ax.set_xlabel("Model Probability")
                ax.set_ylabel("Count")
            else:
                ax.set_title(f"{name} (n=0)")
                ax.text(0.5, 0.5, "No samples", ha="center", va="center",
                        transform=ax.transAxes)
        plt.tight_layout()
        tag  = label.lower().replace("-", "_")
        save = os.path.join(OUT_DIR, f"insight3_calibration_{tag}.png")
        plt.savefig(save, dpi=150)
        plt.close()
        logger.info(f"Saved: {save}")

    del model


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  HELD-OUT VS REAL-WORLD GAP PER CWE
# ═══════════════════════════════════════════════════════════════════════════════

def run_gap_per_cwe(args, device):
    logger.info("\n" + "="*60)
    logger.info("INSIGHT 4: Held-out vs Real-World Gap Per CWE")
    logger.info("="*60)

    model, tokenizer = load_model(args.baseline_model, device)

    def cwe_recall(data_file):
        probs, labels, meta = infer(model, tokenizer, data_file, device)
        preds = classify(probs)
        cwe_data = defaultdict(lambda: {"preds": [], "labels": []})
        for i, m in enumerate(meta):
            for cwe in (m["cwe"] if isinstance(m["cwe"], list) else []):
                if cwe:
                    cwe_data[cwe]["preds"].append(int(preds[i]))
                    cwe_data[cwe]["labels"].append(int(labels[i]))
        results = {}
        for cwe, d in cwe_data.items():
            if d["labels"]:
                results[cwe] = recall_score(d["labels"], d["preds"], zero_division=0)
        return results

    held_recalls  = cwe_recall(args.held_out_test)
    real_recalls  = cwe_recall(args.realworld_test)
    del model

    # CWEs present in both
    common_cwes = sorted(set(held_recalls) & set(real_recalls))

    logger.info(f"\n{'CWE':<12} {'Held-out':>10} {'Real-world':>12} {'Gap':>8}")
    logger.info("-" * 46)
    gaps = {}
    for cwe in common_cwes:
        gap = real_recalls[cwe] - held_recalls[cwe]
        gaps[cwe] = gap
        tag = "✓" if gap > -0.2 else "✗"
        logger.info(f"  {cwe:<12} {held_recalls[cwe]:>9.3f}  "
                    f"{real_recalls[cwe]:>11.3f}  {gap:>+8.3f}  {tag}")

    # Plot side-by-side bar chart
    if common_cwes:
        x     = np.arange(len(common_cwes))
        width = 0.35
        fig, ax = plt.subplots(figsize=(max(8, len(common_cwes) * 0.7), 5))
        ax.bar(x - width/2, [held_recalls[c] for c in common_cwes],
               width, label="Held-out (synthetic)", color="#3498db", alpha=0.85)
        ax.bar(x + width/2, [real_recalls[c]  for c in common_cwes],
               width, label="Real-world (DiverseVul)", color="#e74c3c", alpha=0.85)
        ax.set_xticks(x)
        ax.set_xticklabels(common_cwes, rotation=45, ha="right")
        ax.set_ylim(0, 1.1)
        ax.set_ylabel("Recall")
        ax.set_title("Per-CWE Recall: Held-out vs Real-World")
        ax.legend()
        ax.axhline(0.5, color="gray", linestyle="--", alpha=0.4)
        plt.tight_layout()
        save = os.path.join(OUT_DIR, "insight4_gap_per_cwe.png")
        plt.savefig(save, dpi=150)
        plt.close()
        logger.info(f"\nSaved: {save}")

    _save_json({
        "held_out_recall":  held_recalls,
        "real_world_recall": real_recalls,
        "gap":              gaps,
    }, "insight4_gap_per_cwe.json")


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _save_json(data, filename):
    def _conv(obj):
        if isinstance(obj, (np.float32, np.float64)): return float(obj)
        if isinstance(obj, (np.int32,   np.int64)):   return int(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        return obj
    path = os.path.join(OUT_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=_conv)
    logger.info(f"Saved: {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="all",
                        choices=["all", "syntax_vs_semantics",
                                 "error_analysis", "calibration", "gap_per_cwe"])

    # Model paths
    parser.add_argument("--baseline_model",    default="./results/exp1_improved")
    parser.add_argument("--c_only_model",      default="./results/exp2_c_only")
    parser.add_argument("--python_only_model", default="./results/exp2_python_only")

    # Data paths
    parser.add_argument("--test_data",        default="./Files/multi_lang_test.jsonl")
    parser.add_argument("--c_only_test",      default="./Files/held_out_c_valid.jsonl")
    parser.add_argument("--python_only_test", default="./Files/held_out_python_valid.jsonl")
    parser.add_argument("--held_out_test",    default="./Files/held_out_valid.jsonl")
    parser.add_argument("--realworld_test",   default="./Files/sample_test.jsonl")

    args   = parser.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")

    os.makedirs(OUT_DIR, exist_ok=True)

    if args.mode in ("all", "syntax_vs_semantics"):
        run_syntax_vs_semantics(args, device)

    if args.mode in ("all", "error_analysis"):
        run_error_analysis(args, device)

    if args.mode in ("all", "calibration"):
        run_calibration(args, device)

    if args.mode in ("all", "gap_per_cwe"):
        run_gap_per_cwe(args, device)

    logger.info(f"\nAll outputs saved to {OUT_DIR}/")


if __name__ == "__main__":
    main()
