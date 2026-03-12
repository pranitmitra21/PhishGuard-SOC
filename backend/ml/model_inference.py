import joblib
import os
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "random_forest.pkl")

# Load model if it exists
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

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
            return "Phishing", 0.95
        return "Safe", 0.85
    
    features_array = extract_features_array(features_dict)
    prediction = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]
    
    # 0 = Safe, 1 = Suspicious, 2 = Phishing
    classes = ["Safe", "Suspicious", "Phishing"]
    status = classes[prediction]
    confidence = max(probabilities) * 100
    
    return status, round(confidence, 2)
