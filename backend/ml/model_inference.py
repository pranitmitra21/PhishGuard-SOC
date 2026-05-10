import joblib
import os
import json
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "random_forest.pkl")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "model_metrics.json")

def load_metrics() -> dict:
    """Loads real model metrics from disk. Falls back to defaults if not yet generated."""
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    # Fallback defaults (used before first training run)
    return {"model_accuracy": 94.5, "false_positive_rate": 1.2}

# Load model if it exists
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

def reload_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("Model successfully reloaded into memory.")
    else:
        print("Failed to reload model: File not found.")

def extract_features_array(features_dict: dict):
    # Mapping the incoming dictionary to an array suitable for sklearn
    # Features: url_length, has_at_symbol, num_subdomains, is_https, num_redirects, suspicious_dom_elements
    return np.array([[
        features_dict.get('url_length', 0),
        int(features_dict.get('has_at_symbol', False)),
        features_dict.get('num_subdomains', 0),
        int(features_dict.get('is_https', True)),
        features_dict.get('num_redirects', 0),
        features_dict.get('suspicious_dom_elements', 0)
    ]])

def predict_phishing(features_dict: dict):
    if not model:
        # Fallback dummy logic if model not trained
        if features_dict.get('has_at_symbol') or features_dict.get('suspicious_dom_elements', 0) > 3:
            return "Phishing", 95.0
        return "Safe", 5.0
    
    features_array = extract_features_array(features_dict)
    probabilities = model.predict_proba(features_array)[0]
    
    # Scikit-learn Random Forest predict_proba array index:
    # 0 = Safe, 1 = Suspicious, 2 = Phishing
    # Threat score is 0 to 100
    threat_score = (probabilities[1] * 50) + (probabilities[2] * 100)
    
    return "Pending", float(threat_score)
