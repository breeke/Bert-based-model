# Create this as create_minimal_data.py
import json
import os
import random

def create_minimal_dataset():
    os.makedirs("./Files", exist_ok=True)
    
    # Simple, clear vulnerable patterns
    vulnerable_samples = []
    safe_samples = []
    
    # Vulnerable patterns (target = 1)
    vuln_funcs = [
        "void overflow(char *input) { char buf[10]; strcpy(buf, input); }",
        "void format_bug(char *msg) { printf(msg); }",
        "char* use_after_free() { char *p = malloc(100); free(p); return p; }",
        "int null_deref(char *ptr) { return *ptr; }",
        "void unsafe_copy(char *src) { char dst[50]; sprintf(dst, src); }"
    ]
    
    # Safe patterns (target = 0)
    safe_funcs = [
        "void safe_copy(char *input) { char buf[100]; if(input) strncpy(buf, input, 99); buf[99]=0; }",
        "void safe_print(char *msg) { if(msg) printf(\"%s\", msg); }",
        "char* safe_malloc() { char *p = malloc(100); if(p) memset(p, 0, 100); return p; }",
        "int safe_deref(char *ptr) { return ptr ? *ptr : -1; }",
        "void safe_format(char *msg) { if(msg) printf(\"%s\", msg); }"
    ]
    
    # Generate multiple copies
    idx = 0
    for func in vuln_funcs:
        for i in range(600):  # 600 copies each
            vulnerable_samples.append({
                "func": func,
                "target": 1,
                "idx": f"vuln_{idx}_{i}"
            })
        idx += 1
    
    idx = 0
    for func in safe_funcs:
        for i in range(600):  # 600 copies each
            safe_samples.append({
                "func": func,
                "target": 0,
                "idx": f"safe_{idx}_{i}"
            })
        idx += 1
    
    # Combine and shuffle
    all_samples = vulnerable_samples + safe_samples
    random.seed(42)
    random.shuffle(all_samples)
    
    # Split
    train_size = int(0.7 * len(all_samples))
    valid_size = int(0.15 * len(all_samples))
    
    train_data = all_samples[:train_size]
    valid_data = all_samples[train_size:train_size + valid_size]
    test_data = all_samples[train_size + valid_size:]
    
    # Save files
    datasets = {
        './Files/minimal_train.jsonl': train_data,
        './Files/minimal_valid.jsonl': valid_data,
        './Files/minimal_test.jsonl': test_data
    }
    
    for filepath, data in datasets.items():
        with open(filepath, 'w') as f:
            for sample in data:
                json.dump(sample, f)
                f.write('\n')
        
        vuln_count = sum(1 for d in data if d['target'] == 1)
        print(f"{filepath}: {len(data)} samples ({vuln_count} vulnerable)")

if __name__ == "__main__":
    create_minimal_dataset()
    print("Minimal dataset created successfully!")