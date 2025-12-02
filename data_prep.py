import json
import os
import random
from sklearn.model_selection import train_test_split
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_balanced_from_separated_files(vuln_file="./Files/vulnerable_only.jsonl", 
                                       not_vuln_file="./Files/not_vulnerable_only.jsonl",
                                       output_dir="./Files"):
    """
    Create balanced dataset from separated vulnerable and non-vulnerable files
    Takes ALL vulnerable samples and randomly samples equal amount from non-vulnerable
    """
    
    # Load all vulnerable samples
    vulnerable_data = []
    logger.info("Loading vulnerable samples...")
    
    try:
        with open(vuln_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    record = json.loads(line.strip())
                    if 'func' in record and 'target' in record:
                        vulnerable_data.append(record)
                except json.JSONDecodeError:
                    logger.warning(f"Skipping malformed JSON on line {line_num} in {vuln_file}")
                    continue
    except FileNotFoundError:
        logger.error(f"Vulnerable file not found: {vuln_file}")
        return
    
    # Load all non-vulnerable samples
    not_vulnerable_data = []
    logger.info("Loading non-vulnerable samples...")
    
    try:
        with open(not_vuln_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    record = json.loads(line.strip())
                    if 'func' in record and 'target' in record:
                        not_vulnerable_data.append(record)
                except json.JSONDecodeError:
                    logger.warning(f"Skipping malformed JSON on line {line_num} in {not_vuln_file}")
                    continue
    except FileNotFoundError:
        logger.error(f"Non-vulnerable file not found: {not_vuln_file}")
        return
    
    logger.info("=== File Loading Results ===")
    logger.info(f"Loaded {len(vulnerable_data)} vulnerable samples")
    logger.info(f"Loaded {len(not_vulnerable_data)} non-vulnerable samples")
    
    # Check if we have enough non-vulnerable samples
    if len(not_vulnerable_data) < len(vulnerable_data):
        logger.warning(f"Not enough non-vulnerable samples ({len(not_vulnerable_data)}) to match vulnerable samples ({len(vulnerable_data)})")
        logger.info("Using all available non-vulnerable samples")
        sampled_not_vulnerable = not_vulnerable_data
    else:
        # Randomly sample non-vulnerable to match vulnerable count
        logger.info(f"Randomly sampling {len(vulnerable_data)} non-vulnerable samples from {len(not_vulnerable_data)} available")
        random.seed(42)  # For reproducibility
        sampled_not_vulnerable = random.sample(not_vulnerable_data, len(vulnerable_data))
    
    # Combine the balanced data
    balanced_data = vulnerable_data + sampled_not_vulnerable
    
    # Shuffle the combined data
    random.seed(42)
    random.shuffle(balanced_data)
    
    logger.info("=== Balanced Dataset Created ===")
    logger.info(f"Total samples: {len(balanced_data)}")
    logger.info(f"Vulnerable: {len(vulnerable_data)} ({len(vulnerable_data)/len(balanced_data)*100:.1f}%)")
    logger.info(f"Non-vulnerable: {len(sampled_not_vulnerable)} ({len(sampled_not_vulnerable)/len(balanced_data)*100:.1f}%)")
    
    # Split into train/valid/test (70/15/15)
    train_data, temp_data = train_test_split(
        balanced_data, test_size=0.3, random_state=42,
        stratify=[d['target'] for d in balanced_data]
    )
    valid_data, test_data = train_test_split(
        temp_data, test_size=0.5, random_state=42,
        stratify=[d['target'] for d in temp_data]
    )
    
    # Save the balanced splits
    splits = {
        'balanced_train.jsonl': train_data,
        'balanced_valid.jsonl': valid_data,
        'balanced_test.jsonl': test_data
    }
    
    logger.info("=== Saving Balanced Splits ===")
    for filename, split_data in splits.items():
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            for record in split_data:
                json.dump(record, f, ensure_ascii=False)
                f.write('\n')
        
        vuln_count = sum(1 for d in split_data if d['target'] == 1)
        not_vuln_count = len(split_data) - vuln_count
        logger.info(f"{filename}: {len(split_data)} samples ({vuln_count} vulnerable, {not_vuln_count} not vulnerable)")
    
    # Verify the balance
    logger.info("=== Balance Verification ===")
    for filename, split_data in splits.items():
        vuln_ratio = sum(1 for d in split_data if d['target'] == 1) / len(split_data)
        logger.info(f"{filename}: {vuln_ratio*100:.1f}% vulnerable")
    
    return splits

def show_sample_data(data, label, count=3):
    """Show sample data for verification"""
    logger.info(f"=== Sample {label} Data ===")
    for i, sample in enumerate(data[:count]):
        logger.info(f"Sample {i+1}:")
        logger.info(f"  Target: {sample['target']}")
        logger.info(f"  Function preview: {sample['func'][:100]}...")
        logger.info(f"  Project: {sample.get('project', 'unknown')}")

if __name__ == "__main__":
    # Check if separated files exist
    vuln_file = "./Files/vulnerable_only.jsonl"
    not_vuln_file = "./Files/not_vulnerable_only.jsonl"
    
    if not os.path.exists(vuln_file):
        logger.error(f"Vulnerable file not found: {vuln_file}")
        logger.info("Please run data_prep.py first to create separated files")
        exit(1)
        
    if not os.path.exists(not_vuln_file):
        logger.error(f"Non-vulnerable file not found: {not_vuln_file}")
        logger.info("Please run data_prep.py first to create separated files")
        exit(1)
    
    # Create balanced dataset from separated files
    logger.info("Creating balanced dataset from separated files...")
    splits = create_balanced_from_separated_files(vuln_file, not_vuln_file)
    
    if splits:
        logger.info("\n=== Success! ===")
        logger.info("Balanced datasets created:")
        logger.info("- balanced_train.jsonl")
        logger.info("- balanced_valid.jsonl") 
        logger.info("- balanced_test.jsonl")
        logger.info("\nNext step: Train your model with:")
        logger.info("python train.py --train_data_file ./Files/balanced_train.jsonl --eval_data_file ./Files/balanced_valid.jsonl --test_data_file ./Files/balanced_test.jsonl --output_dir ./balanced_model --do_train --do_eval --do_test --num_epochs 3 --train_batch_size 8")
    else:
        logger.error("Failed to create balanced dataset")

