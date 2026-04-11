#!/usr/bin/env python3
"""
FASE 8: ML-based False Positive Filter
Goal: Integration module that loads trained model and scores findings

MLFilter is called as the 8th filter layer in FalsePositiveKiller pipeline
"""

import pickle
import os
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.ERROR)  # no-op: overridden by core.logger.setup_logging()
logger = logging.getLogger(__name__)

try:
    import numpy as np
    import pandas as pd
    _ML_DEPS_AVAILABLE = True
except ImportError as _ml_import_err:
    _ML_DEPS_AVAILABLE = False
    logger.warning(f"ML dependencies unavailable ({_ml_import_err}). ML scoring disabled. Run: pip install numpy pandas")

class MLFilter:
    """ML-based false positive detector using trained LightGBM model"""
    
    MODEL_PATH = "/home/leonardofsp/bug-bounty/models/fp_filter_v1.pkl"
    DEFAULT_CONFIDENCE_THRESHOLD = 0.5  # Probability threshold for FP
    
    _model = None
    _label_encoders = None
    
    @classmethod
    def load_model(cls):
        """Load trained model and encoders from pickle file"""
        if cls._model is not None:
            return True  # Already loaded
        
        if not os.path.exists(cls.MODEL_PATH):
            logger.warning(f"ML model not found: {cls.MODEL_PATH}")
            return False
        
        try:
            with open(cls.MODEL_PATH, 'rb') as f:
                model_data = pickle.load(f)
            
            cls._model = model_data.get("model")
            cls._label_encoders = model_data.get("label_encoders", {})
            
            logger.info(f"Loaded ML model from {cls.MODEL_PATH}")
            return True
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            return False
    
    @classmethod
    def score_finding(cls, finding, confidence_threshold=None):
        """
        Score a finding using ML model
        
        Args:
            finding: dict with finding data
            confidence_threshold: probability threshold for FP classification (0-1)
        
        Returns:
            (is_false_positive: bool, confidence: float)
            - is_false_positive: True if model predicts FP with high confidence
            - confidence: probability [0-1] that finding is a false positive
        """
        if confidence_threshold is None:
            confidence_threshold = cls.DEFAULT_CONFIDENCE_THRESHOLD
        
        # Try to load model if not already loaded
        if cls._model is None:
            if not cls.load_model():
                # Model not available, don't filter
                return False, 0.0
        
        if not _ML_DEPS_AVAILABLE:
            return False, 0.0

        try:
            # Extract features from finding
            features = cls._extract_features(finding)
            if features is None:
                return False, 0.0
            
            # Predict probability of being FP
            feature_names = getattr(cls._model, "feature_name_", None)
            X_raw = np.array([features])
            X = pd.DataFrame(X_raw, columns=feature_names) if feature_names else X_raw
            
            # Get probability of FP class (class 1)
            proba = cls._model.predict_proba(X)[0]
            fp_probability = proba[1]  # Probability of being FP
            
            # Decide: is FP if probability > threshold
            is_fp = fp_probability > confidence_threshold
            
            return is_fp, fp_probability
        
        except Exception as e:
            logger.error(f"ML scoring failed: {e}")
            return False, 0.0
    
    @classmethod
    def _extract_features(cls, finding):
        """Extract ML features from finding dict
        
        Returns: list of 8 features [response_len, request_len, extracted_len,
                 severity_encoded, content_type_encoded, host_type_encoded,
                 matched_status_encoded, tags_encoded]
        """
        try:
            # Numeric features
            response_len = len(finding.get("response", ""))
            request_len = len(finding.get("request", ""))
            extracted_len = len(str(finding.get("extracted-results", [])))
            
            # Categorical features
            severity = finding.get("info", {}).get("severity", "info").lower()
            host = finding.get("host", "").lower()
            content_type = cls._detect_content_type(finding.get("response", ""))
            host_type = cls._detect_host_type(host)
            
            # Extract status code from response
            matched_status = cls._extract_status_code(finding.get("response", ""))
            
            # Extract tags
            tags = finding.get("info", {}).get("tags", [])
            tags_str = ",".join(tags) if tags else "unknown"
            
            # Encode categorical features
            features = [
                response_len,
                request_len,
                extracted_len,
                cls._encode_categorical("severity", severity),
                cls._encode_categorical("content_type", content_type),
                cls._encode_categorical("host_type", host_type),
                cls._encode_categorical("matched_status", matched_status),
                cls._encode_categorical("tags", tags_str[:50])  # Limit length
            ]
            
            return features
        
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None
    
    @classmethod
    def _encode_categorical(cls, feature_name, value):
        """Encode categorical feature using fitted encoder"""
        if cls._label_encoders is None:
            return 0
        
        encoder = cls._label_encoders.get(feature_name)
        if encoder is None:
            return 0
        
        try:
            # If value not in encoder classes, use default (0)
            if value not in encoder.classes_:
                return 0
            
            return encoder.transform([value])[0]
        except Exception:
            return 0
    
    @classmethod
    def _detect_content_type(cls, response):
        """Detect content type from HTTP response"""
        if not response:
            return "unknown"
        
        response_lower = response.lower()
        
        if "content-type: application/json" in response_lower:
            return "json"
        elif "content-type: text/html" in response_lower:
            return "html"
        elif "content-type: text/plain" in response_lower:
            return "text"
        elif "content-type: application/xml" in response_lower:
            return "xml"
        elif "content-type: image/" in response_lower:
            return "image"
        else:
            return "unknown"
    
    @classmethod
    def _detect_host_type(cls, host):
        """Detect host type from URL"""
        if not host:
            return "standard"
        
        host_lower = host.lower()
        
        if "wordpress" in host_lower or "wp-" in host_lower:
            return "wordpress"
        elif "docker" in host_lower or "container" in host_lower:
            return "docker"
        elif "aws" in host_lower or "ec2" in host_lower or ".amazonaws.com" in host_lower:
            return "aws"
        elif "azure" in host_lower or ".azurewebsites.net" in host_lower:
            return "azure"
        elif "github" in host_lower:
            return "github"
        elif "api" in host_lower:
            return "api"
        elif "admin" in host_lower:
            return "admin"
        elif ".dev" in host_lower or ".local" in host_lower:
            return "dev"
        else:
            return "standard"
    
    @classmethod
    def _extract_status_code(cls, response):
        """Extract HTTP status code from response"""
        if not response or "HTTP/" not in response:
            return "200"
        
        try:
            status_line = response.split("\r\n")[0]
            parts = status_line.split()
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass
        
        return "200"

# Initialize model on module import
MLFilter.load_model()
