#!/usr/bin/env python3
"""
FASE 8: Train LightGBM model for false positive detection
Goal: Build ML classifier to identify false positives with 90%+ precision
"""

import csv
import sys
import pickle
import numpy as np
from pathlib import Path

sys.path.insert(0, '/home/leonardofsp/bug-bounty')

from core.ui import Colors, ui_log

try:
    from lightgbm import LGBMClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
except ImportError as e:
    print(f"❌ Required package missing: {e}")
    print("Install with: pip install lightgbm scikit-learn")
    sys.exit(1)

class FPFilterModelTrainer:
    """Train ML model to detect false positives"""
    
    def __init__(self):
        self.training_file = "/home/leonardofsp/bug-bounty/data/fp_labels_augmented.csv"
        self.model_file = "/home/leonardofsp/bug-bounty/models/fp_filter_v1.pkl"
        self.report_file = "/home/leonardofsp/bug-bounty/reports/model_validation.txt"
        
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.model = None
        self.label_encoders = {}
    
    def train(self):
        """Train the model end-to-end"""
        ui_log("TRAINER", "Loading training data...", Colors.INFO)
        
        # Load and prepare data
        X, y = self._load_and_prepare_data()
        if X is None:
            return False
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        ui_log("TRAINER", f"Training set: {len(self.X_train)} samples", Colors.INFO)
        ui_log("TRAINER", f"Test set: {len(self.X_test)} samples", Colors.INFO)
        
        # Train model
        ui_log("TRAINER", "Training LightGBM model...", Colors.INFO)
        self.model = self._train_lightgbm()
        
        # Validate
        ui_log("TRAINER", "Validating model...", Colors.INFO)
        self._validate_model()
        
        # Save model
        self._save_model()
        
        return True
    
    def _load_and_prepare_data(self):
        """Load training data and convert to feature matrix"""
        if not Path(self.training_file).exists():
            ui_log("TRAINER", f"Training file not found: {self.training_file}", Colors.ERROR)
            return None, None
        
        data = []
        with open(self.training_file) as f:
            reader = csv.DictReader(f)
            data = list(reader)
        
        ui_log("TRAINER", f"Loaded {len(data)} training samples", Colors.SUCCESS)
        
        # Extract features and labels
        X = []
        y = []
        
        # Define which features to use
        feature_cols = [
            "response_len",
            "request_len", 
            "extracted_len",
            "severity",
            "content_type",
            "host_type",
            "matched_status",
            "tags"
        ]
        
        # First pass: collect all unique values for categorical features
        categorical_features = ["severity", "content_type", "host_type", "matched_status", "tags"]
        for cat_feat in categorical_features:
            unique_vals = list(set([d.get(cat_feat, "unknown") for d in data]))
            encoder = LabelEncoder()
            encoder.fit(unique_vals)
            self.label_encoders[cat_feat] = encoder
        
        # Second pass: build feature matrix
        for row in data:
            try:
                feature_row = []
                
                # Numeric features
                feature_row.append(float(row["response_len"]))
                feature_row.append(float(row["request_len"]))
                feature_row.append(float(row["extracted_len"]))
                
                # Categorical features (encode)
                for cat_feat in categorical_features:
                    val = row.get(cat_feat, "unknown")
                    encoded = self.label_encoders[cat_feat].transform([val])[0]
                    feature_row.append(encoded)
                
                X.append(feature_row)
                y.append(int(row["is_false_positive"]))
            
            except Exception as e:
                print(f"Warning: Skipping row due to error: {e}")
                continue
        
        return np.array(X), np.array(y)
    
    def _train_lightgbm(self):
        """Train LightGBM classifier"""
        from lightgbm import LGBMClassifier
        
        # Parameters
        model = LGBMClassifier(
            num_leaves=31,
            learning_rate=0.05,
            n_estimators=100,
            feature_fraction=0.8,
            bagging_fraction=0.8,
            bagging_freq=5,
            verbose=-1,
            random_state=42
        )
        
        # Train
        model.fit(self.X_train, self.y_train)
        
        return model
    
    def _validate_model(self):
        """Validate model on test set and print metrics"""
        # Predictions
        y_pred_proba = self.model.predict(self.X_test)
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        # Metrics
        report = classification_report(self.y_test, y_pred, 
                                      target_names=["True Positive", "False Positive"],
                                      output_dict=True)
        
        auc_score = roc_auc_score(self.y_test, y_pred_proba)
        conf_matrix = confusion_matrix(self.y_test, y_pred)
        
        # Print results
        print("\n" + "="*60)
        print("MODEL VALIDATION RESULTS")
        print("="*60)
        print("\nClassification Report:")
        print(classification_report(self.y_test, y_pred,
                                   target_names=["True Positive", "False Positive"]))
        
        print("\nConfusion Matrix:")
        print(f"  TN (correct TP): {conf_matrix[0, 0]}")
        print(f"  FP (missed FP):  {conf_matrix[0, 1]}")
        print(f"  FN (false alarm): {conf_matrix[1, 0]}")
        print(f"  TP (correct FP): {conf_matrix[1, 1]}")
        
        print(f"\nROC-AUC Score: {auc_score:.4f}")
        
        # Feature importance
        importances = self.model.feature_importances_
        feature_names = [
            "response_len", "request_len", "extracted_len",
            "severity", "content_type", "host_type", "matched_status", "tags"
        ]
        
        print("\nFeature Importance:")
        for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1])[:5]:
            print(f"  {name}: {imp:.4f}")
        
        print("="*60 + "\n")
        
        # Save report
        self._save_report(report, auc_score, conf_matrix)
    
    def _save_report(self, report, auc_score, conf_matrix):
        """Save validation report to file"""
        Path(self.report_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("FASE 8: FP FILTER MODEL VALIDATION REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write("Classification Report:\n")
            f.write(str(report) + "\n\n")
            
            f.write(f"ROC-AUC Score: {auc_score:.4f}\n\n")
            
            f.write("Confusion Matrix:\n")
            f.write(f"  True Negatives: {conf_matrix[0, 0]}\n")
            f.write(f"  False Positives: {conf_matrix[0, 1]}\n")
            f.write(f"  False Negatives: {conf_matrix[1, 0]}\n")
            f.write(f"  True Positives: {conf_matrix[1, 1]}\n")
        
        ui_log("TRAINER", f"Saved validation report to {self.report_file}", Colors.SUCCESS)
    
    def _save_model(self):
        """Save trained model to pickle file"""
        Path(self.model_file).parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            "model": self.model,
            "label_encoders": self.label_encoders
        }
        
        with open(self.model_file, 'wb') as f:
            pickle.dump(model_data, f)
        
        ui_log("TRAINER", f"Saved model to {self.model_file}", Colors.SUCCESS)

if __name__ == "__main__":
    trainer = FPFilterModelTrainer()
    success = trainer.train()
    sys.exit(0 if success else 1)
