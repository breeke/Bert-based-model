# dataset.py - Dataset handling for DiverseVul
import json
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
    """Convert DiverseVul JSON to model features"""
    # Clean and tokenize code
    code = ' '.join(js['func'].split())
    code_tokens = tokenizer.tokenize(code)[:args.block_size-2]
    
    # Add special tokens
    source_tokens = [tokenizer.cls_token] + code_tokens + [tokenizer.sep_token]
    source_ids = tokenizer.convert_tokens_to_ids(source_tokens)
    
    # Pad to block_size
    padding_length = args.block_size - len(source_ids)
    source_ids += [tokenizer.pad_token_id] * padding_length
    
    return InputFeatures(
        source_tokens, source_ids, 
        js.get('idx', js.get('hash', '0')), 
        js['target']
    )

class TextDataset(Dataset):
    def __init__(self, tokenizer, args, file_path):
        self.examples = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    js = json.loads(line.strip())
                    features = convert_examples_to_features(js, tokenizer, args)
                    self.examples.append(features)
                except (json.JSONDecodeError, KeyError) as e:
                    continue
        
        logger.info(f"Loaded {len(self.examples)} examples from {file_path}")
        
        # Show first few examples for training data
        if 'train' in file_path and len(self.examples) > 0:
            for i in range(min(3, len(self.examples))):
                example = self.examples[i]
                logger.info(f"Example {i}: label={example.label}, tokens={len(example.input_tokens)}")

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):       
        return torch.tensor(self.examples[i].input_ids), torch.tensor(self.examples[i].label)



