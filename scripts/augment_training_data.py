#!/usr/bin/env python3
"""
FASE 8: Synthetic training data generation
Goal: Augment limited real findings with synthetic examples

This generates realistic synthetic examples to improve training with only 1 real finding
"""

import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, '/home/leonardofsp/bug-bounty')

from core.ui import Colors, ui_log

class SyntheticDataGenerator:
    """Generate synthetic training examples"""
    
    # Common templates and their accuracies
    TEMPLATES = {
        "CVE-2024-2473": ("cve", "medium", 0.92),
        "wordpress-plugin": ("wordpress", "high", 0.88),
        "spring-actuator": ("springboot", "high", 0.89),
        "laravel-debug": ("laravel", "high", 0.87),
        "rce-command-injection": ("rce", "critical", 0.91),
        "sql-injection": ("sqli", "critical", 0.90),
        "xss-reflection": ("xss", "high", 0.85),
        "lfi-path-traversal": ("lfi", "high", 0.86),
        "django-debug": ("django", "high", 0.84),
        "header-detection": ("header-detect", "info", 0.65),
        "tech-detection": ("tech-detect", "info", 0.62),
        "favicon-hash": ("favicon", "info", 0.58),
        "waf-detection": ("waf-detect", "info", 0.55),
        "plugin-enumeration": ("plugin", "medium", 0.72),
        "cors-misconfiguration": ("cors", "high", 0.68),
        "jwt-weak-algo": ("jwt", "high", 0.70),
        "generic-placeholder": ("generic", "low", 0.45),
        "random-param": ("random", "low", 0.40),
        "placeholder-value": ("placeholder", "low", 0.15),
    }
    
    TARGETS = [
        "amazon_cn", "indaiatuba_sp_gov_br", "gsam_com", "honestdollar_com",
        "marionnaud_de", "moneyback_com_hk", "nordvpn_com", "runnr_in"
    ]
    
    CONTENT_TYPES = ["json", "html", "xml", "text", "unknown"]
    HOST_TYPES = ["wordpress", "docker", "aws", "azure", "github", "api", "admin", "dev", "standard"]
    SEVERITIES = ["critical", "high", "medium", "low", "info"]
    
    def __init__(self, num_synthetic=200):
        self.num_synthetic = num_synthetic
        self.output_file = "/home/leonardofsp/bug-bounty/data/fp_labels_augmented.csv"
        self.training_data = []
    
    def generate(self):
        """Generate synthetic training examples"""
        ui_log("AUGMENTER", f"Generating {self.num_synthetic} synthetic examples...", Colors.INFO)
        
        # Load real data
        real_data = self._load_real_data()
        self.training_data = real_data.copy()
        
        # Generate synthetic examples
        tp_count = 0
        fp_count = 0
        
        for i in range(self.num_synthetic):
            example = self._generate_example()
            self.training_data.append(example)
            
            if example["is_false_positive"] == 0:
                tp_count += 1
            else:
                fp_count += 1
        
        # Save augmented dataset
        self._save_augmented_data()
        
        print("\n" + "="*60)
        print("SYNTHETIC DATA AUGMENTATION")
        print("="*60)
        print(f"Total Training Samples: {len(self.training_data)}")
        print(f"Real Examples: {len(real_data)}")
        print(f"Synthetic Examples: {self.num_synthetic}")
        print(f"True Positives (synthetic): {tp_count} ({100*tp_count/self.num_synthetic:.1f}%)")
        print(f"False Positives (synthetic): {fp_count} ({100*fp_count/self.num_synthetic:.1f}%)")
        
        total_tp = len([x for x in self.training_data if x["is_false_positive"] == 0])
        total_fp = len([x for x in self.training_data if x["is_false_positive"] == 1])
        print(f"\nOverall Distribution:")
        print(f"True Positives: {total_tp} ({100*total_tp/len(self.training_data):.1f}%)")
        print(f"False Positives: {total_fp} ({100*total_fp/len(self.training_data):.1f}%)")
        print("="*60 + "\n")
    
    def _load_real_data(self):
        """Load real labeled examples"""
        real_file = "/home/leonardofsp/bug-bounty/data/fp_labels.csv"
        if not Path(real_file).exists():
            return []
        
        data = []
        with open(real_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                row["is_false_positive"] = int(row["is_false_positive"])
                data.append(row)
        
        return data
    
    def _generate_example(self):
        """Generate single synthetic training example"""
        template_id, template_type, accuracy = random.choice(list(self.TEMPLATES.values()))
        severity = random.choice(self.SEVERITIES)
        
        # Determine if TP or FP based on accuracy
        is_tp = random.random() < accuracy
        
        # Adjust some characteristics based on TP/FP
        if is_tp:
            # True positives: longer response, higher severity, proper content types
            response_len = random.randint(500, 5000)
            request_len = random.randint(200, 1000)
            extracted_len = random.randint(50, 500)
            content_type = random.choice(["json", "html", "xml", "text"])
            matched_status = random.choice(["200", "201", "400", "401", "403", "500"])
        else:
            # False positives: short response, low severity, generic content
            response_len = random.randint(0, 200)
            request_len = random.randint(0, 100)
            extracted_len = random.randint(0, 50)
            content_type = random.choice(["unknown", "text", "html"])
            matched_status = random.choice(["404", "403", "200"])
        
        target = random.choice(self.TARGETS)
        host_type = random.choice(self.HOST_TYPES)
        
        return {
            "template_id": f"{template_id}-{random.randint(1000, 9999)}",
            "severity": severity,
            "target": target,
            "response_len": str(response_len),
            "request_len": str(request_len),
            "extracted_len": str(extracted_len),
            "host": f"https://{target}.example.com/path/{random.randint(1, 100)}",
            "matched_at": f"https://{target}.example.com/matched",
            "tags": template_type,
            "content_type": content_type,
            "host_type": host_type,
            "matched_status": matched_status,
            "source": "synthetic",
            "is_false_positive": 0 if is_tp else 1
        }
    
    def _save_augmented_data(self):
        """Save augmented training dataset"""
        Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.output_file, 'w', newline='') as f:
            fieldnames = list(self.training_data[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.training_data)
        
        ui_log("AUGMENTER", f"Saved {len(self.training_data)} training samples to {self.output_file}", Colors.SUCCESS)

if __name__ == "__main__":
    generator = SyntheticDataGenerator(num_synthetic=200)
    generator.generate()
