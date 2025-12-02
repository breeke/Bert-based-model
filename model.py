import torch
import torch.nn as nn
import logging

logger = logging.getLogger(__name__)

class Model(nn.Module):   
    def __init__(self, encoder, config, tokenizer, args):
        super(Model, self).__init__()
        self.encoder = encoder
        self.config = config
        self.tokenizer = tokenizer
        self.args = args
        
        # Get hidden size from config
        if hasattr(config, 'hidden_size'):
            hidden_size = config.hidden_size
        else:
            hidden_size = 768  # Default for RoBERTa/CodeBERT
        
        # Dropout and classification layers
        self.dropout = nn.Dropout(getattr(args, 'dropout_probability', 0.1))
        self.classifier = nn.Linear(hidden_size, 1)
        
        # Initialize weights
        nn.init.normal_(self.classifier.weight, std=0.02)
        nn.init.zeros_(self.classifier.bias)

    def forward(self, input_ids=None, labels=None): 
        if input_ids is None:
            raise ValueError("input_ids cannot be None")
        
        # Create attention mask
        pad_token_id = self.tokenizer.pad_token_id if self.tokenizer.pad_token_id else 1
        attention_mask = input_ids.ne(pad_token_id)
        
        # FIXED: Access the base RoBERTa model correctly
        outputs = self.encoder.roberta(input_ids, attention_mask=attention_mask)
        
        # Get the sequence output (hidden states)
        sequence_output = outputs.last_hidden_state
        
        # Use [CLS] token (first token) for classification
        cls_output = sequence_output[:, 0, :]
        cls_output = self.dropout(cls_output)
        
        # Get logits and probabilities
        logits = self.classifier(cls_output)
        prob = torch.sigmoid(logits)
        
        if labels is not None:
            # Training mode - compute loss
            labels = labels.float().view(-1, 1)
            loss = -(labels * torch.log(prob + 1e-10) + 
                    (1 - labels) * torch.log(1 - prob + 1e-10))
            loss = loss.mean()
            return loss, prob
        else:
            # Inference mode
            return prob