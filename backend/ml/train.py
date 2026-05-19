import joblib
import os
import json
import pandas as pd
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import numpy as np
import time
from xgboost import XGBClassifier
from ml.model_inference import PhishGuardEnsemble

# Provide paths
PROCESSED_DATA_PATH = os.path.join(os.path.dirname(__file__), "processed_features.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "random_forest.pkl")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "model_metrics.json")

def train_model(progress_callback=None):
    print(f"Loading processed dataset from {PROCESSED_DATA_PATH}...")
    
    if not os.path.exists(PROCESSED_DATA_PATH):
        print("Error: Processed features not found. Run dataset_builder.py first.")
        return
        
    df = pd.read_csv(PROCESSED_DATA_PATH)
    
    # Split features (X) and target label (y)
    X = df.drop('label', axis=1)
    y = df['label']
    
    print(f"Dataset loaded successfully. Shape: {df.shape}")
    print("Class distribution:")
    print(y.value_counts())
    
    # Train test split for validation
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale features for Deep Learning
    print("Normalizing features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train XGBoost
    print("Training XGBoost Classifier on massive network features...")
    xgb = XGBClassifier(
        n_estimators=150, 
        max_depth=12, 
        learning_rate=0.1, 
        random_state=42, 
        n_jobs=-1,
        tree_method='hist' # Highly optimized for large datasets
    )
    xgb.fit(X_train_scaled, y_train)
    
    print("Training Deep Learning Neural Network (MLPClassifier)...")
    mlp = MLPClassifier(
        hidden_layer_sizes=(128, 64), 
        learning_rate_init=0.005,
        random_state=42, 
        batch_size=2048,
        early_stopping=False
    )
    
    classes = np.unique(y)
    epochs = 15
    
    # Pre-compute XGBoost predictions on validation subset to save time during SSE loop
    val_X = X_test_scaled[:5000]
    val_y = y_test[:5000]
    xgb_probs_val = xgb.predict_proba(val_X)
    
    for i in range(1, epochs + 1):
        mlp.partial_fit(X_train_scaled, y_train, classes=classes)
        
        # Calculate real-time ensemble metrics on validation subset
        mlp_probs_val = mlp.predict_proba(val_X)
        ensemble_probs = (mlp_probs_val + xgb_probs_val) / 2.0
        ensemble_preds = np.argmax(ensemble_probs, axis=1)
        acc = accuracy_score(val_y, ensemble_preds)
        
        # Add visual padding so the frontend dashboard renders the animation smoothly
        time.sleep(0.3)
        
        if progress_callback:
            progress_callback({
                "epoch": i,
                "accuracy": acc,
                "loss": mlp.loss_
            })

    # Combine into Ensemble
    ensemble_model = PhishGuardEnsemble(mlp, xgb)

    print("Evaluating final Ensemble model accuracy on test split...")
    y_pred = ensemble_model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)

    # Compute False Positive Rate:
    cm = confusion_matrix(y_test, y_pred)
    fpr = 0.0
    if 0 in classes:  # 0 = Safe
        safe_idx = list(classes).index(0)
        actual_safe = cm[safe_idx].sum()
        correctly_safe = cm[safe_idx][safe_idx]
        false_positives = actual_safe - correctly_safe
        fpr = round((false_positives / actual_safe) * 100, 2) if actual_safe > 0 else 0.0

    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print(f"False Positive Rate: {fpr:.2f}%")

    # Save metrics to JSON
    metrics = {
        "model_accuracy": round(accuracy * 100, 2),
        "false_positive_rate": fpr
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f)
    print(f"Metrics saved to {METRICS_PATH}")

    # Build and save the final pipeline
    final_pipeline = Pipeline([
        ('scaler', scaler),
        ('ensemble', ensemble_model)
    ])
    joblib.dump(final_pipeline, MODEL_PATH)
    print(f"Ensemble Pipeline successfully saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
