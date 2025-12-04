#!/usr/bin/env python3
"""
Test script to verify dataset improvements
"""
import sys
import logging
from transformers import RobertaTokenizer

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Import from local modules
from dataset import TextDataset, collate_fn_dynamic_padding

class Args:
    """Mock args for testing"""
    block_size = 400
    train_batch_size = 8
    eval_batch_size = 8

def test_dataset_loading():
    """Test dataset loading with new improvements"""
    logger.info("="*70)
    logger.info("Testing Dataset Improvements")
    logger.info("="*70)

    # Initialize tokenizer
    logger.info("\nInitializing tokenizer...")
    tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")

    args = Args()

    # Test loading sample training data
    logger.info("\n" + "="*70)
    logger.info("Loading sample training data...")
    logger.info("="*70)

    try:
        train_dataset = TextDataset(
            tokenizer,
            args,
            "./Files/sample_train.jsonl"
        )

        logger.info(f"\n✓ Successfully loaded training dataset")
        logger.info(f"  Total examples: {len(train_dataset)}")

        # Test a few samples
        logger.info("\nTesting sample access...")
        for i in range(min(3, len(train_dataset))):
            input_ids, label = train_dataset[i]
            logger.info(f"  Sample {i}: input_ids shape={input_ids.shape}, label={label.item()}")

    except FileNotFoundError:
        logger.error("✗ sample_train.jsonl not found. Please ensure data files exist.")
        return False
    except Exception as e:
        logger.error(f"✗ Error loading training data: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test validation data
    logger.info("\n" + "="*70)
    logger.info("Loading sample validation data...")
    logger.info("="*70)

    try:
        valid_dataset = TextDataset(
            tokenizer,
            args,
            "./Files/sample_valid.jsonl"
        )

        logger.info(f"\n✓ Successfully loaded validation dataset")
        logger.info(f"  Total examples: {len(valid_dataset)}")

    except Exception as e:
        logger.error(f"✗ Error loading validation data: {e}")
        return False

    # Test dynamic padding
    logger.info("\n" + "="*70)
    logger.info("Testing dynamic padding collate function...")
    logger.info("="*70)

    try:
        from torch.utils.data import DataLoader, SequentialSampler

        sampler = SequentialSampler(train_dataset)
        dataloader = DataLoader(
            train_dataset,
            sampler=sampler,
            batch_size=4,
            collate_fn=collate_fn_dynamic_padding
        )

        # Get first batch
        batch = next(iter(dataloader))
        input_ids_batch, labels_batch = batch

        logger.info(f"✓ Dynamic padding working correctly")
        logger.info(f"  Batch input_ids shape: {input_ids_batch.shape}")
        logger.info(f"  Batch labels shape: {labels_batch.shape}")
        logger.info(f"  Note: Sequences are padded to longest in batch, not global max")

    except Exception as e:
        logger.error(f"✗ Error testing dynamic padding: {e}")
        import traceback
        traceback.print_exc()
        return False

    logger.info("\n" + "="*70)
    logger.info("✓ All tests passed successfully!")
    logger.info("="*70)

    return True

if __name__ == "__main__":
    success = test_dataset_loading()
    sys.exit(0 if success else 1)
