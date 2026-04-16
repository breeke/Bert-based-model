"""
calibrate.py — Post-hoc temperature scaling for the vulnerability detection model
==================================================================================
Learns a single scalar temperature T on a held-out validation set such that
  calibrated_prob = sigmoid(logit / T)
pushes probabilities away from 0/1 extremes (fixes overconfidence).

Usage:
    python calibrate.py \\
        --model_dir  ./results/exp1_baseline \\
        --val_data   ./Files/held_out_valid.jsonl \\
        --output_dir ./results

Outputs:
    results/temperature.json              — {"temperature": T}
    results/plots/calibration_curve.png   — reliability diagram before vs after
"""

import argparse
import json
import os
import numpy as np
import torch
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.optimize import minimize_scalar
from torch.utils.data import DataLoader, SequentialSampler
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
import logging

from dataset import TextDataset, collate_fn_dynamic_padding
from model import Model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def load_model(model_dir, device, model_name="microsoft/unixcoder-base"):
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
    return model, tokenizer


def get_logits_and_labels(model, tokenizer, data_file, device, block_size=400):
    """Collect raw pre-sigmoid logits and true labels from the validation set."""
    class _Args:
        dropout_probability = 0.1
        label_smoothing = 0.0
    _args = _Args()
    _args.block_size = block_size

    dataset = TextDataset(tokenizer, _args, data_file)
    loader = DataLoader(dataset, sampler=SequentialSampler(dataset),
                        batch_size=16, collate_fn=collate_fn_dynamic_padding)

    all_logits, all_labels = [], []
    with torch.no_grad():
        for batch in loader:
            inputs = batch[0].to(device)
            batch_labels = batch[1].to(device)
            logits = model(inputs, return_logits=True)
            all_logits.extend(logits.cpu().numpy().flatten().tolist())
            all_labels.extend(batch_labels.cpu().numpy().tolist())

    return np.array(all_logits), np.array(all_labels)


def nll_loss(T, logits, labels):
    """Negative log-likelihood after temperature scaling."""
    scaled = logits / T
    probs = 1 / (1 + np.exp(-scaled))
    probs = np.clip(probs, 1e-10, 1 - 1e-10)
    return -np.mean(labels * np.log(probs) + (1 - labels) * np.log(1 - probs))


def reliability_diagram(probs, labels, n_bins=10, title="", ax=None):
    """Plot a reliability diagram (calibration curve)."""
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_accs, bin_confs, bin_counts = [], [], []

    for i in range(n_bins):
        mask = (probs >= bin_edges[i]) & (probs < bin_edges[i + 1])
        if mask.sum() == 0:
            continue
        bin_accs.append(labels[mask].mean())
        bin_confs.append(probs[mask].mean())
        bin_counts.append(mask.sum())

    if ax is None:
        fig, ax = plt.subplots()

    ax.plot([0, 1], [0, 1], "k--", label="Perfect calibration")
    ax.bar(bin_confs, bin_accs, width=0.08, alpha=0.6, label="Model")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xlabel("Mean predicted probability")
    ax.set_ylabel("Fraction of positives")
    ax.set_title(title)
    ax.legend(fontsize=8)

    # ECE
    ece = sum(abs(a - c) * n for a, c, n in zip(bin_accs, bin_confs, bin_counts)) / sum(bin_counts)
    ax.text(0.05, 0.9, f"ECE = {ece:.4f}", transform=ax.transAxes, fontsize=9)
    return ece


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_dir",   required=True, help="Directory with best_model.bin")
    parser.add_argument("--val_data",    required=True, help="Held-out validation jsonl")
    parser.add_argument("--output_dir",  default="./results")
    parser.add_argument("--model_name",  default="microsoft/unixcoder-base")
    parser.add_argument("--block_size",  default=400, type=int)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Device: {device}")

    # Load model and collect logits
    logger.info("Loading model...")
    model, tokenizer = load_model(args.model_dir, device, args.model_name)

    logger.info(f"Collecting logits from {args.val_data}...")
    logits, labels = get_logits_and_labels(model, tokenizer, args.val_data, device, args.block_size)

    probs_before = 1 / (1 + np.exp(-logits))
    logger.info(f"Before calibration — prob range: [{probs_before.min():.4f}, {probs_before.max():.4f}]")
    logger.info(f"  mean prob on positives: {probs_before[labels == 1].mean():.4f}")
    logger.info(f"  mean prob on negatives: {probs_before[labels == 0].mean():.4f}")

    # Optimise temperature
    logger.info("Optimising temperature T...")
    result = minimize_scalar(
        lambda T: nll_loss(T, logits, labels),
        bounds=(0.1, 10.0),
        method="bounded"
    )
    T = result.x
    logger.info(f"Optimal temperature T = {T:.4f}  (NLL: {result.fun:.6f})")

    probs_after = 1 / (1 + np.exp(-logits / T))
    logger.info(f"After calibration  — prob range: [{probs_after.min():.4f}, {probs_after.max():.4f}]")
    logger.info(f"  mean prob on positives: {probs_after[labels == 1].mean():.4f}")
    logger.info(f"  mean prob on negatives: {probs_after[labels == 0].mean():.4f}")

    # Save temperature
    os.makedirs(args.output_dir, exist_ok=True)
    temp_path = os.path.join(args.output_dir, "temperature.json")
    with open(temp_path, "w") as f:
        json.dump({"temperature": float(T)}, f, indent=2)
    logger.info(f"Saved temperature to {temp_path}")

    # Reliability diagram — before vs after
    os.makedirs(os.path.join(args.output_dir, "plots"), exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    ece_before = reliability_diagram(probs_before, labels, title="Before (T=1.0)", ax=axes[0])
    ece_after  = reliability_diagram(probs_after,  labels, title=f"After  (T={T:.2f})", ax=axes[1])
    fig.suptitle(f"Calibration: ECE {ece_before:.4f} → {ece_after:.4f}", fontsize=12)
    plt.tight_layout()
    plot_path = os.path.join(args.output_dir, "plots", "calibration_curve.png")
    plt.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info(f"Saved calibration curve to {plot_path}")

    # Probability histograms — before vs after
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, probs, title in [
        (axes[0], probs_before, "Before calibration"),
        (axes[1], probs_after,  f"After calibration (T={T:.2f})"),
    ]:
        ax.hist(probs[labels == 0], bins=20, alpha=0.6, color="blue",  label="Safe")
        ax.hist(probs[labels == 1], bins=20, alpha=0.6, color="red",   label="Vulnerable")
        ax.axvline(0.5, color="k", linestyle="--")
        ax.set_xlim(0, 1)
        ax.set_xlabel("Predicted probability")
        ax.set_ylabel("Count")
        ax.set_title(title)
        ax.legend(fontsize=8)
    plt.tight_layout()
    hist_path = os.path.join(args.output_dir, "plots", "calibration_histograms.png")
    plt.savefig(hist_path, dpi=150, bbox_inches="tight")
    plt.close()
    logger.info(f"Saved probability histograms to {hist_path}")

    logger.info(f"\nDone. T={T:.4f}  ECE: {ece_before:.4f} → {ece_after:.4f}")
    logger.info("evaluate_experiments.py will apply this temperature automatically.")


if __name__ == "__main__":
    main()
