import argparse
import torch
import json
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer
from model import Model
from dataset import convert_examples_to_features

def predict_vulnerability(code_file, model_dir,threshold=0.3):
    """Predict vulnerability for a single code file"""
    
    # Load model
    config = RobertaConfig.from_pretrained("microsoft/codebert-base")
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
    
    base_model = RobertaForSequenceClassification.from_pretrained("microsoft/codebert-base", config=config)
    
    # Create args object
    class Args:
        dropout_probability = 0.1
        block_size = 400
    
    model = Model(base_model, config, tokenizer, Args())
    
    # Load trained weights
    model_path = f"{model_dir}/best_model.bin"
    model.load_state_dict(torch.load(model_path, map_location='cpu'))
    model.eval()
    
    # Read code file
    with open(code_file, 'r') as f:
        code = f.read()
    
    # Create test data
    test_data = {
        "func": code,
        "target": 0,  # dummy
        "idx": "test_sample",
        "project": "unknown"
    }
    
    # Tokenize
    features = convert_examples_to_features(test_data, tokenizer, Args())
    input_ids = torch.tensor([features.input_ids])
    
    # Predict
    with torch.no_grad():
        prob = model(input_ids)
        prediction = (prob.item() > threshold)
    
    print(f"File: {code_file}")
    print(f"Vulnerability Probability: {prob.item():.4f}")
    print(f"Prediction: {'VULNERABLE' if prediction else 'NOT VULNERABLE'}")
    print(f"Using threshold: {threshold}")
    
    return prediction, prob.item()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--code_file", required=True, help="Path to code file")
    parser.add_argument("--model_dir", required=True, help="Path to trained model directory")
    args = parser.parse_args()
    
    predict_vulnerability(args.code_file, args.model_dir)