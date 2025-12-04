# dataset.py - Dataset handling for DiverseVul
import json
import re
import torch
from torch.utils.data import Dataset
import logging

logger = logging.getLogger(__name__)

class InputFeatures:
    def __init__(self, input_tokens, input_ids, idx, label):
        self.input_tokens = input_tokens
        self.input_ids = input_ids
        self.idx = str(idx)
        self.label = label

def convert_examples_to_features(js, tokenizer, args):
    """Convert DiverseVul JSON to model features with improved normalization"""
    # Better code normalization - preserve structure while reducing excessive whitespace
    code = js['func']
    # Normalize spaces and tabs but keep newlines for structure
    code = re.sub(r'[ \t]+', ' ', code)
    # Limit consecutive newlines to 2
    code = re.sub(r'\n\n+', '\n\n', code)
    code = code.strip()

    # Tokenize code
    code_tokens = tokenizer.tokenize(code)
    original_length = len(code_tokens)

    # Track truncation
    max_tokens = args.block_size - 2  # Reserve space for CLS and SEP
    truncated = original_length > max_tokens
    if truncated:
        sample_id = js.get('idx', js.get('hash', 'unknown'))
        logger.warning(
            f"Sample {sample_id} truncated: {original_length} -> {max_tokens} tokens "
            f"({original_length - max_tokens} tokens lost, {(original_length - max_tokens) / original_length * 100:.1f}%)"
        )

    code_tokens = code_tokens[:max_tokens]

    # Add special tokens
    source_tokens = [tokenizer.cls_token] + code_tokens + [tokenizer.sep_token]
    source_ids = tokenizer.convert_tokens_to_ids(source_tokens)

    # Note: Padding is now handled dynamically in collate_fn for efficiency
    # This saves memory by not storing padding in the dataset

    return InputFeatures(
        source_tokens, source_ids,
        js.get('idx', js.get('hash', '0')),
        js['target']
    )

class TextDataset(Dataset):
    def __init__(self, tokenizer, args, file_path):
        self.examples = []
        self.stats = {
            'total_lines': 0,
            'skipped_json_errors': 0,
            'skipped_key_errors': 0,
            'skipped_empty_func': 0,
            'loaded': 0,
            'truncated': 0,
            'token_lengths': []
        }

        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                self.stats['total_lines'] += 1

                try:
                    js = json.loads(line.strip())

                    # Validate required fields
                    if 'func' not in js:
                        logger.warning(f"Line {line_num}: Missing 'func' field, skipping")
                        self.stats['skipped_key_errors'] += 1
                        continue

                    if 'target' not in js:
                        logger.warning(f"Line {line_num}: Missing 'target' field, skipping")
                        self.stats['skipped_key_errors'] += 1
                        continue

                    # Check for empty function
                    if not js['func'].strip():
                        logger.warning(f"Line {line_num}: Empty function body, skipping")
                        self.stats['skipped_empty_func'] += 1
                        continue

                    features = convert_examples_to_features(js, tokenizer, args)
                    self.examples.append(features)
                    self.stats['loaded'] += 1
                    self.stats['token_lengths'].append(len(features.input_tokens))

                except json.JSONDecodeError as e:
                    logger.warning(f"Line {line_num}: Invalid JSON - {e}, skipping")
                    self.stats['skipped_json_errors'] += 1
                    continue
                except KeyError as e:
                    logger.warning(f"Line {line_num}: Missing required field {e}, skipping")
                    self.stats['skipped_key_errors'] += 1
                    continue
                except Exception as e:
                    logger.error(f"Line {line_num}: Unexpected error - {e}, skipping")
                    continue

        # Log summary statistics
        logger.info(f"\n{'='*60}")
        logger.info(f"Dataset: {file_path}")
        logger.info(f"{'='*60}")
        logger.info(f"Total lines processed: {self.stats['total_lines']}")
        logger.info(f"Successfully loaded: {self.stats['loaded']}")
        logger.info(f"Skipped (JSON errors): {self.stats['skipped_json_errors']}")
        logger.info(f"Skipped (missing fields): {self.stats['skipped_key_errors']}")
        logger.info(f"Skipped (empty functions): {self.stats['skipped_empty_func']}")

        if self.stats['token_lengths']:
            avg_tokens = sum(self.stats['token_lengths']) / len(self.stats['token_lengths'])
            max_tokens = max(self.stats['token_lengths'])
            min_tokens = min(self.stats['token_lengths'])
            logger.info(f"\nToken statistics:")
            logger.info(f"  Average: {avg_tokens:.1f} tokens")
            logger.info(f"  Min: {min_tokens} tokens")
            logger.info(f"  Max: {max_tokens} tokens")
            logger.info(f"  Block size: {args.block_size} tokens")

            # Calculate class distribution
            labels = [ex.label for ex in self.examples]
            vulnerable = sum(labels)
            safe = len(labels) - vulnerable
            logger.info(f"\nClass distribution:")
            logger.info(f"  Vulnerable: {vulnerable} ({vulnerable/len(labels)*100:.1f}%)")
            logger.info(f"  Safe: {safe} ({safe/len(labels)*100:.1f}%)")

        logger.info(f"{'='*60}\n")

        # Show first few examples for training data
        if 'train' in file_path and len(self.examples) > 0:
            logger.info("Sample examples:")
            for i in range(min(3, len(self.examples))):
                example = self.examples[i]
                logger.info(f"  Example {i}: label={example.label}, tokens={len(example.input_tokens)}")

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):
        return torch.tensor(self.examples[i].input_ids), torch.tensor(self.examples[i].label)


def collate_fn_dynamic_padding(batch):
    """
    Custom collate function for dynamic padding.
    Pads sequences to the longest in the batch instead of global max.
    """
    input_ids_list = [item[0] for item in batch]
    labels_list = [item[1] for item in batch]

    # Find max length in this batch
    max_length = max(len(ids) for ids in input_ids_list)

    # Pad all sequences to max length in batch
    padded_input_ids = []
    for ids in input_ids_list:
        padding_length = max_length - len(ids)
        if padding_length > 0:
            # Assuming pad_token_id is 1 (standard for RoBERTa)
            padded_ids = torch.cat([ids, torch.ones(padding_length, dtype=torch.long)])
        else:
            padded_ids = ids
        padded_input_ids.append(padded_ids)

    return torch.stack(padded_input_ids), torch.stack(labels_list)



