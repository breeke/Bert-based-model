# ============================================================================
# train.py - Simple training script
# ============================================================================
import argparse
import os
import torch
from torch.utils.data import DataLoader, RandomSampler, SequentialSampler
from transformers import (
    RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer,
    get_linear_schedule_with_warmup
)
try:
    from transformers import AdamW
except ImportError:
    from torch.optim import AdamW
from tqdm import tqdm
import numpy as np
import logging
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
from dataset import TextDataset, collate_fn_dynamic_padding
from model import Model

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def train(args, train_dataset, model, tokenizer):
    """Training loop"""
    # Setup data loader with dynamic padding
    train_sampler = RandomSampler(train_dataset)
    train_dataloader = DataLoader(train_dataset, sampler=train_sampler,
                                  batch_size=args.train_batch_size,
                                  collate_fn=collate_fn_dynamic_padding)
    
    # Setup optimizer
    no_decay = ['bias', 'LayerNorm.weight']
    optimizer_grouped_parameters = [
        {'params': [p for n, p in model.named_parameters() if not any(nd in n for nd in no_decay)],
         'weight_decay': args.weight_decay},
        {'params': [p for n, p in model.named_parameters() if any(nd in n for nd in no_decay)], 
         'weight_decay': 0.0}
    ]
    optimizer = AdamW(optimizer_grouped_parameters, lr=args.learning_rate, eps=1e-8)
    
    total_steps = len(train_dataloader) * args.num_epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, 
                                                num_warmup_steps=int(0.1 * total_steps),
                                                num_training_steps=total_steps)
    
    model.to(args.device)
    model.train()
    
    logger.info("***** Running training *****")
    logger.info(f"  Num examples = {len(train_dataset)}")
    logger.info(f"  Num Epochs = {args.num_epochs}")
    logger.info(f"  Batch size = {args.train_batch_size}")
    logger.info(f"  Total optimization steps = {total_steps}")
    
    global_step = 0
    best_score = 0

    for epoch in range(args.num_epochs):
        epoch_loss = 0
        progress_bar = tqdm(train_dataloader, desc=f"Epoch {epoch+1}")

        for step, batch in enumerate(progress_bar):
            inputs = batch[0].to(args.device)
            labels = batch[1].to(args.device)
            
            loss, logits = model(inputs, labels)
            loss.backward()
            
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()
            
            epoch_loss += loss.item()
            global_step += 1
            
            progress_bar.set_postfix({'loss': f'{loss.item():.4f}'})
        
        avg_loss = epoch_loss / len(train_dataloader)
        logger.info(f"Epoch {epoch+1} average loss: {avg_loss:.4f}")
        
        # Evaluate after each epoch
        if args.eval_data_file:
            eval_f1 = evaluate(args, model, tokenizer)
            if eval_f1 > best_score:
                best_score = eval_f1
                os.makedirs(args.output_dir, exist_ok=True)
                model_path = os.path.join(args.output_dir, 'best_model.bin')
                torch.save(model.state_dict(), model_path)
                logger.info(f"New best model saved with F1: {best_score:.4f}")

def evaluate(args, model, tokenizer):
    """Evaluation function"""
    eval_dataset = TextDataset(tokenizer, args, args.eval_data_file)
    eval_sampler = SequentialSampler(eval_dataset)
    eval_dataloader = DataLoader(eval_dataset, sampler=eval_sampler,
                                 batch_size=args.eval_batch_size,
                                 collate_fn=collate_fn_dynamic_padding)
    
    model.eval()
    predictions = []
    labels = []
    
    with torch.no_grad():
        for batch in tqdm(eval_dataloader, desc="Evaluating"):
            inputs = batch[0].to(args.device)
            batch_labels = batch[1].to(args.device)
            
            loss, logits = model(inputs, batch_labels)
            
            preds = (logits.cpu().numpy() > 0.5).astype(int)
            predictions.extend(preds.flatten())
            labels.extend(batch_labels.cpu().numpy())
    
    preds_arr  = np.array(predictions)
    labels_arr = np.array(labels)

    accuracy  = accuracy_score(labels_arr, preds_arr)
    precision = precision_score(labels_arr, preds_arr, zero_division=0)
    recall    = recall_score(labels_arr, preds_arr, zero_division=0)
    f1        = f1_score(labels_arr, preds_arr, zero_division=0)
    try:
        auc = roc_auc_score(labels_arr, preds_arr)
    except ValueError:
        auc = float('nan')  # only 1 class present in batch

    tn, fp, fn, tp = confusion_matrix(labels_arr, preds_arr, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # False Positive Rate
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0  # False Negative Rate (missed vulns)

    logger.info("\n" + "="*50)
    logger.info("Evaluation Metrics")
    logger.info("="*50)
    logger.info(f"  Accuracy          : {accuracy:.4f}")
    logger.info(f"  Precision         : {precision:.4f}")
    logger.info(f"  Recall            : {recall:.4f}")
    logger.info(f"  F1 Score          : {f1:.4f}")
    logger.info(f"  AUC-ROC           : {auc:.4f}")
    logger.info(f"  False Positive Rate: {fpr:.4f}  ({fp} FP / {fp+tn} neg)")
    logger.info(f"  False Negative Rate: {fnr:.4f}  ({fn} FN / {fn+tp} vuln)  ← missed vulns")
    logger.info(f"  Confusion Matrix  : TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    logger.info("="*50 + "\n")

    model.train()
    return f1  # use F1 as the best-model criterion (better than accuracy for imbalanced data)

def test(args, model, tokenizer):
    """Test function - saves predictions"""
    test_dataset = TextDataset(tokenizer, args, args.test_data_file)
    test_sampler = SequentialSampler(test_dataset)
    test_dataloader = DataLoader(test_dataset, sampler=test_sampler,
                                batch_size=args.eval_batch_size,
                                collate_fn=collate_fn_dynamic_padding)
    
    model.eval()
    predictions = []
    
    with torch.no_grad():
        for batch in tqdm(test_dataloader, desc="Testing"):
            inputs = batch[0].to(args.device)
            logits = model(inputs)
            
            preds = (logits.cpu().numpy() > 0.5).astype(int)
            predictions.extend(preds.flatten())
    
    # Save predictions
    os.makedirs(args.output_dir, exist_ok=True)
    pred_file = os.path.join(args.output_dir, 'predictions.txt')
    with open(pred_file, 'w') as f:
        for i, (example, pred) in enumerate(zip(test_dataset.examples, predictions)):
            f.write(f"{example.idx}\t{pred}\n")
    
    logger.info(f"Saved predictions to {pred_file}")

def main():
    parser = argparse.ArgumentParser()
    
    # Required parameters
    parser.add_argument("--train_data_file", required=True, help="Training data file")
    parser.add_argument("--output_dir", required=True, help="Output directory")
    
    # Optional parameters
    parser.add_argument("--eval_data_file", default=None, help="Evaluation data file")
    parser.add_argument("--test_data_file", default=None, help="Test data file")
    parser.add_argument("--model_name_or_path", default="microsoft/unixcoder-base", help="Pretrained model")
    parser.add_argument("--tokenizer_name", default="microsoft/unixcoder-base", help="Tokenizer")
    
    # Training parameters
    parser.add_argument("--block_size", default=400, type=int, help="Maximum sequence length")
    parser.add_argument("--train_batch_size", default=8, type=int, help="Training batch size")
    parser.add_argument("--eval_batch_size", default=8, type=int, help="Evaluation batch size")
    parser.add_argument("--learning_rate", default=2e-5, type=float, help="Learning rate")
    parser.add_argument("--weight_decay", default=0.01, type=float, help="Weight decay")
    parser.add_argument("--num_epochs", default=3, type=int, help="Number of training epochs")
    parser.add_argument("--dropout_probability", default=0.1, type=float, help="Dropout probability")
    
    # Action flags
    parser.add_argument("--do_train", action='store_true', help="Run training")
    parser.add_argument("--do_eval", action='store_true', help="Run evaluation")
    parser.add_argument("--do_test", action='store_true', help="Run testing")
    
    args = parser.parse_args()
    
    # Setup device
    args.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {args.device}")
    
    # Load model and tokenizer
    config = RobertaConfig.from_pretrained(args.model_name_or_path)
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained(args.tokenizer_name)
    
    base_model = RobertaForSequenceClassification.from_pretrained(args.model_name_or_path, config=config)
    model = Model(base_model, config, tokenizer, args)
    
    logger.info("Model loaded successfully")
    
    # Training
    if args.do_train:
        train_dataset = TextDataset(tokenizer, args, args.train_data_file)
        train(args, train_dataset, model, tokenizer)
    
    # Load best model for evaluation/testing
    if args.do_eval or args.do_test:
        model_path = os.path.join(args.output_dir, 'best_model.bin')
        if os.path.exists(model_path):
            model.load_state_dict(torch.load(model_path, map_location=args.device))
            logger.info("Loaded best model for evaluation")
        model.to(args.device)
    
    # Evaluation
    if args.do_eval and args.eval_data_file:
        evaluate(args, model, tokenizer)
    
    # Testing
    if args.do_test and args.test_data_file:
        test(args, model, tokenizer)

if __name__ == "__main__":
    main()


