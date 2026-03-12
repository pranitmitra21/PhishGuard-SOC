import joblib
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

# Provide paths
PROCESSED_DATA_PATH = os.path.join(os.path.dirname(__file__), "processed_features.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "random_forest.pkl")

def train_model():
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
    
    print("Training Random Forest Classifier on massive dataset...")
    # Limiting depth and estimators to keep model size reasonable despite huge data
    model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    print("Evaluating model accuracy on test split...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Suspicious', 'Phishing'], zero_division=0))

    # Save model
    joblib.dump(model, MODEL_PATH)
    print(f"Model successfully saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
