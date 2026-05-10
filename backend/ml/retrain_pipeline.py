import sys
import os
import pandas as pd

# Add backend directory to sys.path so we can import database and models
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(backend_dir)

from database import SessionLocal
import models
from ml.train import train_model

def run_pipeline():
    print("--- Starting Automated ML Retraining Pipeline ---")
    db = SessionLocal()
    
    # Get user reported threats
    reports = db.query(models.DetectionLog).filter(models.DetectionLog.status == "User_Reported_Phishing").all()
    
    if not reports:
        print("No new user reports found. Skipping retraining.")
        db.close()
        return False

    print(f"Found {len(reports)} new user-reported threats. Ingesting into dataset...")
    
    new_data = []
    for r in reports:
        new_data.append({
            'url_length': r.url_length,
            'has_at_symbol': 1 if r.has_at_symbol else 0,
            'num_subdomains': r.num_subdomains,
            'is_https': 1 if r.is_https else 0,
            'num_redirects': 0,
            'suspicious_dom_elements': r.suspicious_dom_elements,
            'label': 2  # 2 = Phishing
        })
        # Update status so it doesn't get ingested again on the next run
        # but remains visible in the dashboard as a Phishing detection
        r.status = "Phishing" 
        
    db.commit()
    db.close()

    df_new = pd.DataFrame(new_data)
    
    processed_path = os.path.join(os.path.dirname(__file__), "processed_features.csv")
    if os.path.exists(processed_path):
        print("Appending new data to existing processed_features.csv...")
        df_new.to_csv(processed_path, mode='a', header=False, index=False)
    else:
        print("Error: Base dataset not found. Cannot retrain.")
        return False

    print("Triggering Model Retraining on updated massive dataset...")
    train_model()
    
    print("--- Pipeline Complete. Live Model Updated! ---")
    return True

if __name__ == "__main__":
    run_pipeline()
