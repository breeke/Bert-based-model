"""
split_by_language.py
====================
Splits multi_lang_train/valid/test.jsonl into per-language files.

Outputs (in ./Files/):
  c_only_train.jsonl      python_only_train.jsonl
  c_only_valid.jsonl      python_only_valid.jsonl
  c_only_test.jsonl       python_only_test.jsonl

Usage:
  python split_by_language.py
"""

import json
import os
from collections import Counter

INPUT_DIR = "./Files"
OUTPUT_DIR = "./Files"

SPLITS = ["multi_lang_train", "multi_lang_valid", "multi_lang_test"]
LANGUAGES = ["c", "python"]


def split_file(input_path, output_paths):
    """Read one jsonl file and write per-language output files."""
    writers = {lang: open(output_paths[lang], "w") for lang in LANGUAGES}
    counts = {lang: Counter() for lang in LANGUAGES}

    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            lang = record.get("language", "").lower()
            if lang in writers:
                writers[lang].write(json.dumps(record) + "\n")
                counts[lang][record["target"]] += 1

    for lang, w in writers.items():
        w.close()
        total = sum(counts[lang].values())
        vuln  = counts[lang][1]
        safe  = counts[lang][0]
        print(f"  [{lang}] {total} samples — vuln={vuln}, safe={safe} → {output_paths[lang]}")

    return counts


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for split in SPLITS:
        input_path = os.path.join(INPUT_DIR, f"{split}.jsonl")
        suffix = split.replace("multi_lang_", "")  # train / valid / test

        output_paths = {
            lang: os.path.join(OUTPUT_DIR, f"{lang}_only_{suffix}.jsonl")
            for lang in LANGUAGES
        }

        print(f"\n{split}.jsonl →")
        split_file(input_path, output_paths)

    print("\nDone. Language splits written to", OUTPUT_DIR)


if __name__ == "__main__":
    main()
