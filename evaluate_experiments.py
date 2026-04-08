"""
evaluate_experiments.py
=======================
Runs all dissertation experiments and generates plots + results tables.

Experiments covered:
  1. Baseline          — full multi-language synthetic test set
  2. Ablation          — C-only / Python-only / joint models on each language test set
  3. Real-world        — trained model on DiverseVul sample_test.jsonl
  4. Threshold sweep   — precision/recall/F1 across thresholds 0.1–0.9

Usage:
  # Run all experiments (assumes Exp1 and Exp2 models are already trained):
  python evaluate_experiments.py --mode all

  # Individual experiments:
  python evaluate_experiments.py --mode baseline
  python evaluate_experiments.py --mode ablation
  python evaluate_experiments.py --mode realworld
  python evaluate_experiments.py --mode threshold

  # Override model/data paths if needed:
  python evaluate_experiments.py --mode baseline \\
      --baseline_model ./results/exp1_baseline \\
      --test_data ./Files/multi_lang_test.jsonl

Output directory: ./results/plots/  (created automatically)
"""

import argparse
import json
import os
import numpy as np
import torch
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from torch.utils.data import DataLoader, SequentialSampler
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    precision_recall_curve, average_precision_score,
)
from collections import defaultdict
import logging

from dataset import TextDataset, collate_fn_dynamic_padding
from model import Model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PLOT_DIR = "./results/plots"
RESULTS_DIR = "./results"

# ── Cross-language CWEs present in both C and Python ──────────────────────────
SHARED_CWES = {"CWE-78", "CWE-367", "CWE-798", "CWE-22",
               "CWE-732", "CWE-327", "CWE-89", "CWE-134"}


# ══════════════════════════════════════════════════════════════════════════════
# Model helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_model(model_dir, device, model_name="microsoft/unixcoder-base"):
    """Load a saved best_model.bin from model_dir."""
    config = RobertaConfig.from_pretrained(model_name)
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    base = RobertaForSequenceClassification.from_pretrained(model_name, config=config)

    class _Args:
        block_size = 400
        dropout_probability = 0.1
        label_smoothing = 0.0

    model = Model(base, config, tokenizer, _Args())
    model_path = os.path.join(model_dir, "best_model.bin")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"No best_model.bin found in {model_dir}")
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.to(device)
    model.eval()
    logger.info(f"Loaded model from {model_path}")
    return model, tokenizer


def load_metadata(data_file):
    """Load cwe and language fields directly from jsonl — index matches TextDataset order."""
    records = []
    with open(data_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if "func" not in d or "target" not in d or not d["func"].strip():
                    continue
                records.append({"cwe": d.get("cwe", []), "language": d.get("language", "unknown")})
            except Exception:
                continue
    return records


def _load_temperature(results_dir="./results"):
    """Return saved temperature scalar, or 1.0 if not calibrated yet."""
    temp_path = os.path.join(results_dir, "temperature.json")
    if os.path.exists(temp_path):
        with open(temp_path) as f:
            T = json.load(f).get("temperature", 1.0)
        logger.info(f"Applying temperature scaling T={T:.4f}")
        return float(T)
    return 1.0


def _apply_temperature(probs, T):
    """Scale probabilities using temperature T via inverse-sigmoid → scale → sigmoid."""
    if T == 1.0:
        return probs
    raw = np.log(probs / (1 - probs + 1e-10) + 1e-10)
    return 1 / (1 + np.exp(-raw / T))


def get_probabilities(model, tokenizer, data_file, device, block_size=400):
    """Run inference and return (probs, labels, metadata) arrays.

    Applies temperature scaling automatically if results/temperature.json exists.
    """

    class _Args:
        dropout_probability = 0.1
        label_smoothing = 0.0

    _args = _Args()
    _args.block_size = block_size

    dataset = TextDataset(tokenizer, _args, data_file)
    loader = DataLoader(dataset, sampler=SequentialSampler(dataset),
                        batch_size=16, collate_fn=collate_fn_dynamic_padding)

    all_probs, all_labels = [], []
    with torch.no_grad():
        for batch in loader:
            inputs = batch[0].to(device)
            batch_labels = batch[1].to(device)
            _, logits = model(inputs, batch_labels)
            all_probs.extend(logits.cpu().numpy().flatten().tolist())
            all_labels.extend(batch_labels.cpu().numpy().tolist())

    probs = np.array(all_probs)

    # Apply temperature scaling if calibration has been run
    T = _load_temperature()
    probs = _apply_temperature(probs, T)

    # Load cwe/language directly from file — guaranteed to match dataset order
    metadata = load_metadata(data_file)

    return probs, np.array(all_labels), metadata


def metrics_at_threshold(probs, labels, threshold=0.5):
    preds = (probs >= threshold).astype(int)
    acc  = accuracy_score(labels, preds)
    prec = precision_score(labels, preds, zero_division=0)
    rec  = recall_score(labels, preds, zero_division=0)
    f1   = f1_score(labels, preds, zero_division=0)
    try:
        auc = roc_auc_score(labels, probs)
    except ValueError:
        auc = float("nan")
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    return {"accuracy": acc, "precision": prec, "recall": rec,
            "f1": f1, "auc_roc": auc, "confusion_matrix": cm}


# ══════════════════════════════════════════════════════════════════════════════
# Per-CWE and per-language breakdown
# ══════════════════════════════════════════════════════════════════════════════

def per_cwe_f1(probs, labels, metadata, threshold=0.5):
    """Return dict of CWE -> recall (detection rate per CWE, vulnerable samples only)."""
    preds = (probs >= threshold).astype(int)
    cwe_data = defaultdict(lambda: {"preds": [], "labels": []})

    for i, meta in enumerate(metadata):
        raw_cwe = meta.get("cwe", [])
        if not raw_cwe:
            continue
        cwes = raw_cwe if isinstance(raw_cwe, list) else [raw_cwe]
        cwes = [c for c in cwes if c]
        for cwe in cwes:
            cwe_data[cwe]["preds"].append(int(preds[i]))
            cwe_data[cwe]["labels"].append(int(labels[i]))

    results = {}
    for cwe, data in cwe_data.items():
        if not data["labels"]:
            continue
        results[cwe] = recall_score(data["labels"], data["preds"], zero_division=0)

    return dict(sorted(results.items(), key=lambda x: x[1], reverse=True))


def per_language_metrics(probs, labels, metadata, threshold=0.5):
    """Return dict of language -> metrics dict."""
    preds = (probs >= threshold).astype(int)
    lang_data = defaultdict(lambda: {"probs": [], "preds": [], "labels": []})

    for i, meta in enumerate(metadata):
        lang = meta.get("language", "unknown") or "unknown"
        lang_data[lang]["probs"].append(probs[i])
        lang_data[lang]["preds"].append(preds[i])
        lang_data[lang]["labels"].append(labels[i])

    results = {}
    for lang, data in lang_data.items():
        lp = np.array(data["probs"])
        ld = np.array(data["preds"])
        ll = np.array(data["labels"])
        results[lang] = {
            "f1":        f1_score(ll, ld, zero_division=0),
            "precision": precision_score(ll, ld, zero_division=0),
            "recall":    recall_score(ll, ld, zero_division=0),
            "n":         len(ll),
        }
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Plotting helpers
# ══════════════════════════════════════════════════════════════════════════════

def plot_confusion_matrix(cm, title, save_path):
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.colorbar(im, ax=ax)
    classes = ["Safe (0)", "Vulnerable (1)"]
    ax.set(xticks=[0, 1], yticks=[0, 1],
           xticklabels=classes, yticklabels=classes,
           xlabel="Predicted", ylabel="True", title=title)
    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    logger.info(f"Saved: {save_path}")


def plot_per_cwe_f1(cwe_f1_dict, title, save_path, highlight_shared=True):
    cwes  = list(cwe_f1_dict.keys())
    f1s   = list(cwe_f1_dict.values())
    colors = ["#e74c3c" if c in SHARED_CWES else "#3498db" for c in cwes]

    fig, ax = plt.subplots(figsize=(8, max(4, len(cwes) * 0.4)))
    bars = ax.barh(cwes, f1s, color=colors)
    ax.set_xlim(0, 1.0)
    ax.set_xlabel("Recall (Detection Rate)")
    ax.set_title(title)
    ax.xaxis.set_major_formatter(mticker.FormatStrFormatter("%.2f"))

    for bar, val in zip(bars, f1s):
        ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.2f}", va="center", fontsize=8)

    if highlight_shared:
        from matplotlib.patches import Patch
        legend = [Patch(color="#e74c3c", label="Cross-language CWE"),
                  Patch(color="#3498db", label="Language-specific CWE")]
        ax.legend(handles=legend, loc="lower right", fontsize=8)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info(f"Saved: {save_path}")


def plot_precision_recall_curve(probs, labels, save_path):
    precision, recall, thresholds = precision_recall_curve(labels, probs)
    ap = average_precision_score(labels, probs)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(recall, precision, color="#2c3e50", lw=2,
            label=f"PR curve (AP = {ap:.3f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.05)

    # Mark threshold 0.5 and 0.3
    for thr, col, lbl in [(0.5, "red", "t=0.5"), (0.3, "green", "t=0.3")]:
        idx = np.argmin(np.abs(thresholds - thr))
        ax.scatter(recall[idx], precision[idx], s=80, color=col, zorder=5,
                   label=f"{lbl}  P={precision[idx]:.2f} R={recall[idx]:.2f}")

    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    logger.info(f"Saved: {save_path}")


def plot_threshold_sweep(probs, labels, save_path):
    thresholds = np.arange(0.1, 0.95, 0.05)
    precisions, recalls, f1s = [], [], []
    for t in thresholds:
        preds = (probs >= t).astype(int)
        precisions.append(precision_score(labels, preds, zero_division=0))
        recalls.append(recall_score(labels, preds, zero_division=0))
        f1s.append(f1_score(labels, preds, zero_division=0))

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(thresholds, precisions, "b-o", markersize=4, label="Precision")
    ax.plot(thresholds, recalls,    "r-o", markersize=4, label="Recall")
    ax.plot(thresholds, f1s,        "g-o", markersize=4, label="F1")
    ax.axvline(0.5, color="gray", linestyle="--", alpha=0.7, label="t=0.5")
    ax.axvline(0.3, color="orange", linestyle="--", alpha=0.7, label="t=0.3")
    ax.set_xlabel("Classification Threshold")
    ax.set_ylabel("Score")
    ax.set_title("Threshold Sweep: Precision / Recall / F1")
    ax.set_ylim(0, 1.05)
    ax.legend()
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    logger.info(f"Saved: {save_path}")


def plot_ablation_matrix(ablation_results, save_path):
    """
    ablation_results: dict of {model_name: {test_lang: f1_value}}
    e.g. {"C-only": {"c": 0.88, "python": 0.61},
          "Python-only": {"c": 0.55, "python": 0.91},
          "Joint": {"c": 0.87, "python": 0.89}}
    """
    models = list(ablation_results.keys())
    langs  = sorted({l for v in ablation_results.values() for l in v})
    data   = np.array([[ablation_results[m].get(l, 0.0) for l in langs] for m in models])

    fig, ax = plt.subplots(figsize=(6, 4))
    im = ax.imshow(data, cmap="YlOrRd", vmin=0, vmax=1)
    plt.colorbar(im, ax=ax, label="F1 Score")
    ax.set_xticks(range(len(langs)))
    ax.set_yticks(range(len(models)))
    ax.set_xticklabels([l.upper() for l in langs])
    ax.set_yticklabels(models)
    ax.set_xlabel("Test Language")
    ax.set_ylabel("Training Data")
    ax.set_title("Cross-Language Ablation: F1 Heatmap")

    for i in range(len(models)):
        for j in range(len(langs)):
            ax.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center",
                    color="black" if data[i, j] < 0.7 else "white", fontsize=11)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    logger.info(f"Saved: {save_path}")


def save_results_json(data, path):
    def _convert(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        if isinstance(obj, (np.int32, np.int64)):
            return int(obj)
        return obj

    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=_convert)
    logger.info(f"Saved results: {path}")


# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 1 — Baseline
# ══════════════════════════════════════════════════════════════════════════════

def run_baseline(args, device):
    logger.info("\n" + "="*60)
    logger.info("EXPERIMENT 1: Baseline (Full Synthetic Test Set)")
    logger.info("="*60)

    model, tokenizer = load_model(args.baseline_model, device)
    probs, labels, examples = get_probabilities(
        model, tokenizer, args.test_data, device)

    m = metrics_at_threshold(probs, labels, threshold=0.5)
    logger.info(f"  Accuracy  : {m['accuracy']:.4f}")
    logger.info(f"  Precision : {m['precision']:.4f}")
    logger.info(f"  Recall    : {m['recall']:.4f}")
    logger.info(f"  F1        : {m['f1']:.4f}")
    logger.info(f"  AUC-ROC   : {m['auc_roc']:.4f}")

    # Confusion matrix
    plot_confusion_matrix(m["confusion_matrix"],
                          "Exp1: Confusion Matrix (Synthetic Test)",
                          os.path.join(PLOT_DIR, "exp1_confusion_matrix.png"))

    # Per-CWE F1
    cwe_f1 = per_cwe_f1(probs, labels, examples)
    plot_per_cwe_f1(cwe_f1,
                    "Exp1: Per-CWE F1 Score",
                    os.path.join(PLOT_DIR, "exp1_per_cwe_f1.png"))

    # Per-language F1
    lang_metrics = per_language_metrics(probs, labels, examples)
    logger.info("Per-language metrics:")
    for lang, lm in lang_metrics.items():
        logger.info(f"  {lang}: F1={lm['f1']:.4f}  P={lm['precision']:.4f}  R={lm['recall']:.4f}  n={lm['n']}")

    # Save raw results
    save_results_json({
        "overall": {k: v for k, v in m.items() if k != "confusion_matrix"},
        "confusion_matrix": m["confusion_matrix"].tolist(),
        "per_cwe_f1": cwe_f1,
        "per_language": lang_metrics,
    }, os.path.join(RESULTS_DIR, "exp1_baseline_results.json"))

    return probs, labels, examples


# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 2 — Cross-Language Ablation
# ══════════════════════════════════════════════════════════════════════════════

def run_ablation(args, device):
    logger.info("\n" + "="*60)
    logger.info("EXPERIMENT 2: Cross-Language Ablation")
    logger.info("="*60)

    model_configs = {
        "C-only":     args.c_only_model,
        "Python-only": args.python_only_model,
        "Joint":      args.baseline_model,
    }

    test_files = {
        "c":      args.c_only_test,
        "python": args.python_only_test,
        "joint":  args.test_data,
    }

    ablation_results = {}
    full_results = {}

    for model_name, model_dir in model_configs.items():
        if not os.path.exists(os.path.join(model_dir, "best_model.bin")):
            logger.warning(f"Skipping {model_name} — no best_model.bin in {model_dir}")
            continue

        logger.info(f"\n--- Model: {model_name} ---")
        model, tokenizer = load_model(model_dir, device)
        ablation_results[model_name] = {}
        full_results[model_name] = {}

        for lang, test_file in test_files.items():
            if not os.path.exists(test_file):
                logger.warning(f"  Skipping test file {test_file} — not found")
                continue
            probs, labels, examples = get_probabilities(model, tokenizer, test_file, device)
            m = metrics_at_threshold(probs, labels)
            ablation_results[model_name][lang] = m["f1"]
            full_results[model_name][lang] = {
                k: v for k, v in m.items() if k != "confusion_matrix"
            }
            logger.info(f"  Test={lang}  F1={m['f1']:.4f}  P={m['precision']:.4f}  R={m['recall']:.4f}")

            # Shared CWE breakdown
            cwe_f1 = per_cwe_f1(probs, labels, examples)
            shared_f1s = {k: v for k, v in cwe_f1.items() if k in SHARED_CWES}
            if shared_f1s:
                avg_shared = np.mean(list(shared_f1s.values()))
                logger.info(f"    Shared CWE avg F1: {avg_shared:.4f}  {shared_f1s}")
                full_results[model_name][lang]["shared_cwe_f1"] = shared_f1s

        del model  # free memory

    # Heatmap
    if ablation_results:
        plot_ablation_matrix(ablation_results,
                             os.path.join(PLOT_DIR, "exp2_ablation_heatmap.png"))

    save_results_json({
        "ablation_f1_matrix": ablation_results,
        "full_results": full_results,
    }, os.path.join(RESULTS_DIR, "exp2_ablation_results.json"))


# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 3 — Real-World Validation
# ══════════════════════════════════════════════════════════════════════════════

def run_realworld(args, device):
    logger.info("\n" + "="*60)
    logger.info("EXPERIMENT 3: Real-World Validation (DiverseVul)")
    logger.info("="*60)

    model, tokenizer = load_model(args.baseline_model, device)

    # Synthetic test results (for comparison)
    logger.info("Re-evaluating on synthetic test for direct comparison...")
    syn_probs, syn_labels, _ = get_probabilities(
        model, tokenizer, args.test_data, device)
    syn_m = metrics_at_threshold(syn_probs, syn_labels)

    # Real-world results
    logger.info("Evaluating on real-world DiverseVul test set...")
    real_probs, real_labels, real_examples = get_probabilities(
        model, tokenizer, args.realworld_test, device)
    real_m = metrics_at_threshold(real_probs, real_labels)

    logger.info("\n--- Synthetic vs Real-World ---")
    for metric in ["accuracy", "precision", "recall", "f1", "auc_roc"]:
        gap = real_m[metric] - syn_m[metric]
        logger.info(f"  {metric:<12} Synthetic={syn_m[metric]:.4f}  "
                    f"Real={real_m[metric]:.4f}  Gap={gap:+.4f}")

    # Confusion matrices side-by-side
    plot_confusion_matrix(syn_m["confusion_matrix"],
                          "Exp3: Confusion Matrix (Synthetic)",
                          os.path.join(PLOT_DIR, "exp3_confusion_synthetic.png"))
    plot_confusion_matrix(real_m["confusion_matrix"],
                          "Exp3: Confusion Matrix (Real-World)",
                          os.path.join(PLOT_DIR, "exp3_confusion_realworld.png"))

    save_results_json({
        "synthetic": {k: v for k, v in syn_m.items() if k != "confusion_matrix"},
        "real_world": {k: v for k, v in real_m.items() if k != "confusion_matrix"},
        "gap": {metric: real_m[metric] - syn_m[metric]
                for metric in ["accuracy", "precision", "recall", "f1"]},
    }, os.path.join(RESULTS_DIR, "exp3_realworld_results.json"))

    return real_probs, real_labels


# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT 4 — Threshold Analysis
# ══════════════════════════════════════════════════════════════════════════════

def run_threshold(args, device):
    logger.info("\n" + "="*60)
    logger.info("EXPERIMENT 4: Threshold Analysis")
    logger.info("="*60)

    model, tokenizer = load_model(args.baseline_model, device)
    probs, labels, _ = get_probabilities(
        model, tokenizer, args.test_data, device)

    # Precision-recall curve
    plot_precision_recall_curve(
        probs, labels,
        os.path.join(PLOT_DIR, "exp4_precision_recall_curve.png"))

    # Threshold sweep
    plot_threshold_sweep(
        probs, labels,
        os.path.join(PLOT_DIR, "exp4_threshold_sweep.png"))

    # Print table
    logger.info(f"\n{'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    logger.info("-" * 44)
    thresholds_to_report = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    threshold_table = []
    for t in thresholds_to_report:
        preds = (probs >= t).astype(int)
        p = precision_score(labels, preds, zero_division=0)
        r = recall_score(labels, preds, zero_division=0)
        f = f1_score(labels, preds, zero_division=0)
        logger.info(f"  {t:>8.1f}   {p:>9.4f}   {r:>9.4f}   {f:>9.4f}")
        threshold_table.append({"threshold": t, "precision": p, "recall": r, "f1": f})

    save_results_json({"threshold_sweep": threshold_table},
                      os.path.join(RESULTS_DIR, "exp4_threshold_results.json"))


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Run dissertation experiments")

    parser.add_argument("--mode", default="all",
                        choices=["all", "baseline", "ablation", "realworld", "threshold"],
                        help="Which experiment(s) to run")

    # Model directories
    parser.add_argument("--baseline_model",    default="./results/exp1_baseline")
    parser.add_argument("--c_only_model",      default="./results/exp2_c_only")
    parser.add_argument("--python_only_model", default="./results/exp2_python_only")

    # Data files
    parser.add_argument("--test_data",       default="./Files/multi_lang_test.jsonl")
    parser.add_argument("--c_only_test",     default="./Files/c_only_test.jsonl")
    parser.add_argument("--python_only_test",default="./Files/python_only_test.jsonl")
    parser.add_argument("--realworld_test",  default="./Files/sample_test.jsonl")

    args = parser.parse_args()

    os.makedirs(PLOT_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    if args.mode in ("all", "baseline"):
        run_baseline(args, device)

    if args.mode in ("all", "ablation"):
        run_ablation(args, device)

    if args.mode in ("all", "realworld"):
        run_realworld(args, device)

    if args.mode in ("all", "threshold"):
        run_threshold(args, device)

    logger.info(f"\nAll outputs saved to {RESULTS_DIR}/ and {PLOT_DIR}/")


if __name__ == "__main__":
    main()
